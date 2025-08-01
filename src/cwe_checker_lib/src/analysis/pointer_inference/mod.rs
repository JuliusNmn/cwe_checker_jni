//! A fixpoint algorithm analyzing all memory accesses in a program.
//!
//! The goal of the pointer inference analysis is to keep track of all memory objects and pointers
//! that the program knows about at specific program points during execution.
//! It is a combination of a points-to-analysis and a value-set-analysis.
//! The results of the pointer inference analysis are made available to other analyses,
//! which can use them to look up points-to and value set information.
//!
//! If the **Memory** check is enabled,
//! then the analysis also reports some possible memory management errors,
//! like Null pointer dereferences, to the user.
//!
//! ## The Memory Check
//!
//! If the **Memory** check is enabled, the pointer inference reports instances
//! of [CWE-476](https://cwe.mitre.org/data/definitions/476.html) (NULL Pointer Dereference)
//! that were detected during the analysis.
//!
//! The analysis operates on a best-effort basis.
//! In cases where we cannot know
//! whether an error is due to an error in the memory management of the program under analysis
//! or due to inexactness of the pointer inference analysis itself,
//! we try to treat it as the more likely (but not necessarily true) case of the two.
//!
//! See the `Config` struct for configurable analysis parameters.

use super::fixpoint::Computation;
use super::forward_interprocedural_fixpoint::GeneralizedContext;
use super::interprocedural_fixpoint_generic::NodeValue;
use crate::abstract_domain::{AbstractIdentifier, DataDomain, IntervalDomain, SizedDomain};
use crate::analysis::forward_interprocedural_fixpoint::Context as _;
use crate::analysis::graph::{Edge, Graph, Node};
use crate::checkers::prelude::*;
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::log::*;
use petgraph::csr::Edges;
use petgraph::graph::NodeIndex;
use petgraph::visit::{EdgeRef, IntoNodeReferences};
use std::collections::{BTreeMap, HashMap};

mod context;
pub mod detector;
pub mod object;
mod object_list;
mod state;
mod statistics;
mod vsa_result_impl;

use context::Context;
pub use state::State;

/// The version number of the analysis.
const VERSION: &str = "0.2";
/// The recursion limit for nested pointers.
const POINTER_RECURSION_DEPTH_LIMIT: u64 = 2;

/// The name and version number of the "Memory" CWE check.
pub static CWE_MODULE: CweModule = CweModule {
    name: "Memory",
    version: VERSION,
    run: extract_pi_analysis_results,
};

/// The abstract domain to use for absolute values.
pub type ValueDomain = IntervalDomain;

/// The abstract domain type for representing register values.
pub type Data = DataDomain<ValueDomain>;

/// Configurable parameters for the analysis.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Config {
    /// Names of extern functions that are `malloc`-like,
    /// i.e. the unique return value is a pointer to a newly allocated chunk of memory or a NULL pointer.
    pub allocation_symbols: Vec<String>,
}

/// A wrapper struct for the pointer inference computation object.
/// Also contains different analysis results computed through the fixpoint computation including generated log messages.
pub struct PointerInference<'a> {
    /// The pointer inference fixpoint computation object.
    computation: Computation<GeneralizedContext<'a, Context<'a>>>,
    /// A sender channel that can be used to collect logs in the corresponding log thread.
    log_collector: crossbeam_channel::Sender<LogThreadMsg>,
    /// The log messages and CWE warnings that have been generated during the pointer inference analysis.
    pub collected_logs: WithLogs<Vec<CweWarning>>,
    /// Maps the TIDs of assignment, load or store [`Def`] instructions to the computed value data.
    /// The map will be filled after the fixpoint computation finished.
    values_at_defs: HashMap<Tid, Data>,
    /// Maps the TIDs of load or store [`Def`] instructions to the computed address data.
    /// The map will be filled after the fixpoint computation finished.
    addresses_at_defs: HashMap<Tid, Data>,
    /// Maps certain TIDs like the TIDs of [`Jmp`] instructions to the pointer inference state at that TID.
    /// The map will be filled after the fixpoint computation finished.
    pub states_at_tids: HashMap<Tid, State>,
    /// Maps the TIDs of call instructions to a map mapping callee IDs to the corresponding value in the caller.
    /// The map will be filled after the fixpoint computation finished.
    id_renaming_maps_at_calls: HashMap<Tid, BTreeMap<AbstractIdentifier, Data>>,
}

impl<'a> PointerInference<'a> {
    /// Generate a new pointer inference computation for a project.
    pub fn new(
        analysis_results: &'a AnalysisResults<'a>,
        config: Config,
        log_sender: crossbeam_channel::Sender<LogThreadMsg>,
        print_stats: bool,
    ) -> PointerInference<'a> {
        let context = Context::new(analysis_results, config, log_sender.clone());
        let project = analysis_results.project;
        let function_signatures = analysis_results.function_signatures.unwrap();
        let sub_to_entry_node_map = crate::analysis::graph::get_entry_nodes_of_subs(context.graph);

        let mut fixpoint_computation =
            super::forward_interprocedural_fixpoint::create_computation_with_bottom_up_worklist_order(context, None);
        if print_stats {
            let _ = log_sender.send(LogThreadMsg::Log(
                LogMessage::new_info(format!(
                    "Adding {} entry points",
                    sub_to_entry_node_map.len()
                ))
                .source("Pointer Inference"),
            ));
        }
        for (sub_tid, start_node_index) in sub_to_entry_node_map.into_iter() {
            let fn_signature = function_signatures.get(&sub_tid).unwrap();
            let mut fn_entry_state = State::from_fn_sig(
                fn_signature,
                &project.stack_pointer_register,
                sub_tid.clone(),
            );
            if project.cpu_architecture.contains("MIPS") {
                let _ = fn_entry_state
                    .set_mips_link_register(&sub_tid, project.stack_pointer_register.size);
            }
            fixpoint_computation.set_node_value(
                start_node_index,
                super::interprocedural_fixpoint_generic::NodeValue::Value(fn_entry_state),
            );
        }
        
        PointerInference {
            computation: fixpoint_computation,
            log_collector: log_sender,
            collected_logs: WithLogs::wrap(Vec::new()),
            values_at_defs: HashMap::new(),
            addresses_at_defs: HashMap::new(),
            states_at_tids: HashMap::new(),
            id_renaming_maps_at_calls: HashMap::new(),
        }
    }
    
    /// Writes a Data object to a specific parameter of a function by index.
    ///
    /// This function looks up the entry node for the given function, retrieves the associated 
    /// state, and then writes the provided Data object to the parameter at the specified index.
    ///
    /// # Arguments
    ///
    /// * `function_tid` - The Tid of the function containing the parameter
    /// * `param_index` - The index of the parameter to write to
    /// * `data` - The Data object to write to the parameter
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the operation was successful
    /// * `Err(Error)` if the parameter could not be found or the write operation failed
    pub fn write_to_function_parameter(
        &mut self,
        function_tid: &Tid,
        param_index: usize,
        data: Data,
    ) -> Result<(), Error> {
        // Get the context to access function signatures and the global memory image
        let context = self.computation.get_context().get_context();
        let fn_signature = context.fn_signatures.get(function_tid)
            .ok_or_else(|| anyhow!("Function signature not found for {}", function_tid))?;
        
        // Find the entry node for the function
        let sub_to_entry_node_map = crate::analysis::graph::get_entry_nodes_of_subs(context.graph);
        let entry_node = sub_to_entry_node_map.get(function_tid)
            .ok_or_else(|| anyhow!("Function entry node not found for {}", function_tid))?;
        
        // Get the state at the entry node
        let node_value = self.computation.get_node_value(*entry_node)
            .ok_or_else(|| anyhow!("No state found at entry node for {}", function_tid))?;
        
        // Get the state and modify it
        match node_value {
            NodeValue::Value(state) => {
                let mut new_state = state.clone();
                new_state.write_to_parameter(
                    param_index,
                    data,
                    fn_signature,
                    &context.project.runtime_memory_image,
                )?;
                
                // Update the node with the modified state
                self.computation.set_node_value(*entry_node, NodeValue::Value(new_state));
                Ok(())
            },
            _ => Err(anyhow!("No state found at entry node for {}", function_tid)),
        }
    }

    /// Writes a Data object to a specific return value of a function call by index.
    ///
    /// This function looks up the state after the call returns and writes the provided Data object
    /// to the return register at the specified index according to the calling convention.
    ///
    /// # Arguments
    ///
    /// * `call_tid` - The Tid of the call instruction
    /// * `return_index` - The index of the return value to write to (0 for first return value, etc.)
    /// * `data` - The Data object to write to the return value
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the operation was successful
    /// * `Err(Error)` if the return value could not be found or the write operation failed
    pub fn write_to_return_value(
        &mut self,
        state: &mut State,
        call_tid: &Tid,
        return_index: usize,
        data: Data,
    ) -> Result<(), Error> {
       
        // Get the context to access calling conventions
        let context = self.computation.get_context().get_context();
        
        // Get the calling convention - we need to determine which one to use
        // For now, we'll use the default calling convention
        let cconv = context.project.get_specific_calling_convention(&None)
            .ok_or_else(|| anyhow!("No calling convention found for call {}", call_tid))?;
        
        // Get all return registers
        let return_registers = cconv.get_all_return_register();
        
        // Check if the return index is valid
        if return_index >= return_registers.len() {
            return Err(anyhow!("Return index {} out of bounds for call {}", return_index, call_tid));
        }
        
        // Get the return register at the specified index
        let return_register = return_registers[return_index];
        
        // Write the data to the return register
        state.set_register(return_register, data);
        
        Ok(())
    }

    /// Compute the fixpoint of the pointer inference analysis.
    /// Has a `max_steps` bound for the fixpoint algorithm to prevent infinite loops.
    ///
    /// If `print_stats` is `true` then some extra log messages with statistics about the computation are generated.
    pub fn compute(&mut self, print_stats: bool) {
        self.computation.compute_with_max_steps(100); // TODO: make max_steps configurable!
        if print_stats {
            self.count_blocks_with_state();
        }
        if !self.computation.has_stabilized() {
            let worklist_size = self.computation.get_worklist().len();
            self.log_info(format!(
                "Fixpoint did not stabilize. Remaining worklist size: {worklist_size}"
            ));
        }
        if print_stats {
            statistics::compute_and_log_mem_access_stats(self);
        }
    }

    /// Print results serialized as YAML to stdout
    pub fn print_yaml(&self) {
        let graph = self.computation.get_graph();
        for (node_index, value) in self.computation.node_values().iter() {
            let node = graph.node_weight(*node_index).unwrap();
            if let Ok(string) = serde_yaml::to_string(&(node, value)) {
                println!("{string}");
            } else {
                println!(
                    "Serializing failed at {node_index:?} with {:?}",
                    serde_yaml::to_string(value)
                );
            }
        }
    }

    /// Generate a compacted json representation of the results.
    /// Note that this output cannot be used for serialization/deserialization,
    /// but is only intended for user output and debugging.
    pub fn generate_compact_json(&self) -> serde_json::Value {
        let graph = self.computation.get_graph();
        let mut json_nodes = serde_json::Map::new();
        for (node_index, node_value) in self.computation.node_values().iter() {
            let node = graph.node_weight(*node_index).unwrap();
            if let NodeValue::Value(value) = node_value {
                json_nodes.insert(format!("{node}"), value.to_json_compact());
            }
        }
        serde_json::Value::Object(json_nodes)
    }

    /// Print a compacted json representation of the results to stdout.
    /// Note that this output cannot be used for serialization/deserialization,
    /// but is only intended for user output and debugging.
    pub fn print_compact_json(&self) {
        println!("{:#}", self.generate_compact_json());
    }

    /// Get the underlying graph of the computation.
    pub fn get_graph(&self) -> &Graph {
        self.computation.get_graph()
    }

    /// Get the context object of the computation.
    pub fn get_context(&self) -> &Context {
        self.computation.get_context().get_context()
    }

    /// Get the value associated to a node in the computed fixpoint
    /// (or intermediate state of the algorithm if the fixpoint has not been reached yet).
    /// Returns `None` if no value is associated to the Node.
    pub fn get_node_value(&self, node_id: NodeIndex) -> Option<&NodeValue<State>> {
        self.computation.get_node_value(node_id)
    }

    /// Print the number of blocks that have a state associated to them.
    /// Intended for debug purposes.
    fn count_blocks_with_state(&self) {
        let graph = self.computation.get_graph();
        let mut stateful_blocks: i64 = 0;
        let mut all_blocks: i64 = 0;
        for (node_id, node) in graph.node_references() {
            if let Node::BlkStart(_block, _sub) = node {
                all_blocks += 1;
                if self.computation.get_node_value(node_id).is_some() {
                    stateful_blocks += 1;
                }
            }
        }
        self.log_info(format!(
            "Blocks with state: {stateful_blocks} / {all_blocks}"
        ));
    }

    /// Send an info log message to the log collector.
    fn log_info(&self, msg: impl Into<String>) {
        let log_msg = LogMessage::new_info(msg.into()).source("Pointer Inference");
        let _ = self.log_collector.send(LogThreadMsg::Log(log_msg));
    }

    /// Fill the various result maps of `self` that are needed for the [`VsaResult`](crate::analysis::vsa_results::VsaResult) trait implementation.
    pub fn fill_vsa_result_maps(&mut self) {
        let context = self.computation.get_context().get_context();
        let graph = self.computation.get_graph();
        for node in graph.node_indices() {
            match graph[node] {
                Node::BlkStart(blk, _sub) => {
                    let node_state = match self.computation.get_node_value(node) {
                        Some(NodeValue::Value(value)) => value,
                        _ => continue,
                    };
                    let mut state = node_state.clone();
                    for def in &blk.term.defs {
                        match &def.term {
                            Def::Assign { var: _, value } => {
                                self.values_at_defs
                                    .insert(def.tid.clone(), state.eval(value));
                            }
                            Def::Load { var, address } => {
                                let loaded_value = state
                                    .load_value(
                                        address,
                                        var.size,
                                        &context.project.runtime_memory_image,
                                    )
                                    .unwrap_or_else(|_| Data::new_top(var.size));
                                self.values_at_defs.insert(def.tid.clone(), loaded_value);
                                self.addresses_at_defs
                                    .insert(def.tid.clone(), state.eval(address));
                            }
                            Def::Store { address, value } => {
                                self.values_at_defs
                                    .insert(def.tid.clone(), state.eval(value));
                                self.addresses_at_defs
                                    .insert(def.tid.clone(), state.eval(address));
                            }
                        }
                        state = match context.update_def(&state, def) {
                            Some(new_state) => new_state,
                            None => break,
                        }
                    }
                }
                Node::BlkEnd(blk, _sub) => {
                    let node_state = match self.computation.get_node_value(node) {
                        Some(NodeValue::Value(value)) => value,
                        _ => continue,
                    };
                    
                    for jmp in &blk.term.jmps {
                        self.states_at_tids
                            .insert(jmp.tid.clone(), node_state.clone());
                    }
                }
                Node::CallSource { .. } => (),
                Node::CallReturn {
                    call: (caller_blk, _caller_sub),
                    return_: _,
                } => {
                    let call_tid = match caller_blk.term.jmps.first() {
                        Some(call) => &call.tid,
                        _ => continue,
                    };
                    let (state_before_call, state_before_return) =
                        match self.computation.get_node_value(node) {
                            Some(NodeValue::CallFlowCombinator {
                                call_stub: Some(state_before_call),
                                interprocedural_flow: Some(state_before_return),
                            }) => (state_before_call, state_before_return),
                            _ => continue,
                        };
                    let id_to_data_map = context.create_full_callee_id_to_caller_data_map(
                        state_before_call,
                        state_before_return,
                        call_tid,
                    );
                    self.id_renaming_maps_at_calls
                        .insert(call_tid.clone(), id_to_data_map);
                }
            }
        }
    }

    /// Get the state of the fixpoint computation at the block end node before the given jump instruction.
    /// This function only yields results after the fixpoint has been computed.
    pub fn get_state_at_jmp_tid(&self, jmp_tid: &Tid) -> Option<&State> {
        self.states_at_tids.get(jmp_tid)
    }

    /// Get the mapping from callee IDs to caller values for the given call.
    /// This function only yields results after the fixpoint has been computed.
    ///
    /// Note that the maps may contain mappings from callee IDs to temporary caller IDs that get instantly removed from the caller
    /// since they are not referenced in any caller object.
    pub fn get_id_renaming_map_at_call_tid(
        &self,
        call_tid: &Tid,
    ) -> Option<&BTreeMap<AbstractIdentifier, Data>> {
        self.id_renaming_maps_at_calls.get(call_tid)
    }

    /// Print information on dead ends in the control flow graph for debugging purposes.
    /// Ignore returns where there is no known caller stack id.
    #[allow(dead_code)]
    fn print_cfg_dead_ends(&self) {
        let graph = self.computation.get_graph();
        for (node_id, node) in graph.node_references() {
            if let Some(node_value) = self.computation.get_node_value(node_id) {
                if !graph
                    .neighbors(node_id)
                    .any(|neighbor| self.computation.get_node_value(neighbor).is_some())
                {
                    match node {
                        Node::BlkEnd(block, _sub) => {
                            let state = node_value.unwrap_value();
                            if block.term.jmps.is_empty() {
                                println!("Dead end without jumps after block {}", block.tid);
                            }
                            for jmp in block.term.jmps.iter() {
                                match &jmp.term {
                                    Jmp::BranchInd(target_expr) => {
                                        let address = state.eval(target_expr);
                                        println!(
                                            "{}: Indirect jump to {}",
                                            jmp.tid,
                                            address.to_json_compact()
                                        );
                                    }
                                    Jmp::CallInd { target, return_ } => {
                                        let address = state.eval(target);
                                        println!(
                                            "{}: Indirect call to {}. HasReturn: {}",
                                            jmp.tid,
                                            address.to_json_compact(),
                                            return_.is_some()
                                        );
                                    }
                                    Jmp::Return(_) => {}
                                    _ => println!(
                                        "{}: Unexpected Jmp dead end: {:?}",
                                        jmp.tid, jmp.term
                                    ),
                                }
                            }
                        }
                        Node::BlkStart(block, _sub) => {
                            println!("{}: ERROR: Block start without successor state!", block.tid)
                        }
                        Node::CallSource { source, .. } => {
                            println!("{}: ERROR: Call source without target!", source.0.tid)
                        }
                        Node::CallReturn { call, return_ } => {
                            let (call_state, return_state) = match node_value {
                                NodeValue::CallFlowCombinator {
                                    call_stub,
                                    interprocedural_flow,
                                } => (call_stub.is_some(), interprocedural_flow.is_some()),
                                _ => panic!(),
                            };
                            println!(
                                "CallReturn. Caller: ({}, {}), Return: ({}, {})",
                                call.0.tid, call_state, return_.0.tid, return_state
                            );
                        }
                    }
                }
            }
        }
    }
}

/// The entry point for the memory analysis check.
/// Does not actually compute anything
/// but just extracts the results of the already computed pointer inference analysis.
pub fn extract_pi_analysis_results(
    analysis_results: &AnalysisResults,
    _analysis_params: &serde_json::Value,
    _debug_settings: &debug::Settings,
) -> WithLogs<Vec<CweWarning>> {
    let pi_anaylsis = analysis_results.pointer_inference.unwrap();

    pi_anaylsis.collected_logs.clone()
}

/// Compute the pointer inference analysis and return its results.
///
/// If `print_debug` is set to `true` print debug information to *stdout*.
/// Note that the format of the debug information is currently unstable and subject to change.
pub fn run<'a>(
    analysis_results: &'a AnalysisResults<'a>,
    config: Config,
    print_debug: bool,
    print_stats: bool,
) -> PointerInference<'a> {
    let logging_thread = LogThread::spawn(LogThread::collect_and_deduplicate);

    let mut computation = PointerInference::new(
        analysis_results,
        config,
        logging_thread.get_msg_sender(),
        print_stats,
    );

    computation.compute(print_stats);
    computation.fill_vsa_result_maps();

    if print_debug {
        computation.print_compact_json();
    }

    // save the logs and CWE warnings
    let (logs, cwe_warnings) = logging_thread.collect();
    computation.collected_logs = WithLogs::new(cwe_warnings, logs);
    computation
}

// TODO: Fix tests.
/*
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::abstract_domain::AbstractLocation;
    use crate::analysis::vsa_results::VsaResult;
    use crate::intermediate_representation::{Arg, Expression, RuntimeMemoryImage, Tid};
    use crate::ByteSize;

    impl<'a> PointerInference<'a> {
        pub fn mock(project: &'a Project) -> PointerInference<'a> {
            let analysis_results = Box::new(AnalysisResults::mock_from_project(project));
            let analysis_results: &'a AnalysisResults = Box::leak(analysis_results);
            let config = Config {
                allocation_symbols: vec!["malloc".to_string()],
            };
            let (log_sender, _) = crossbeam_channel::unbounded();
            PointerInference::new(analysis_results, config, log_sender, false)
        }

        pub fn set_node_value(&mut self, node_value: State, node_index: NodeIndex) {
            self.computation
                .set_node_value(node_index, NodeValue::Value(node_value));
        }

        pub fn get_mut_values_at_defs(&mut self) -> &mut HashMap<Tid, Data> {
            &mut self.values_at_defs
        }

        pub fn get_mut_addresses_at_defs(&mut self) -> &mut HashMap<Tid, Data> {
            &mut self.addresses_at_defs
        }

        pub fn get_mut_states_at_tids(&mut self) -> &mut HashMap<Tid, State> {
            &mut self.states_at_tids
        }
    }

    /// Simple placeholder for an object that implements the [`VsaResult`]
    /// trait.
    ///
    /// The [`ValueDomain`] of the VSA is the pointer inference [`Data`] and
    /// expressions are evaluated based on a fixed pointer inference [`State`]
    /// that is stored in the `state` member.
    ///
    /// When asked to return [`values`] or [`addresses`] at Defs it always just
    /// returns the stored `value_at_def` or `address_at_def` members. In
    /// general, it completely ignores any [`Tid`] you give it as an argument.
    ///
    /// [`ValueDomain`]: VsaResult::ValueDomain
    /// [`values`]: VsaResult::eval_value_at_def
    /// [`addresses`]: VsaResult::eval_address_at_def
    #[derive(Debug)]
    pub struct MockVsaResult {
        state: State,
        address_at_def: Data,
        value_at_def: Data,
        runtime_memory_image: RuntimeMemoryImage,
    }

    impl MockVsaResult {
        pub fn new(
            state: State,
            address_at_def: Option<Data>,
            value_at_def: Option<Data>,
            runtime_memory_image: Option<RuntimeMemoryImage>,
        ) -> Self {
            Self {
                state,
                address_at_def: address_at_def.unwrap_or(Data::new_empty(ByteSize::new(8))),
                value_at_def: value_at_def.unwrap_or(Data::new_empty(ByteSize::new(8))),
                runtime_memory_image: runtime_memory_image
                    .unwrap_or(RuntimeMemoryImage::empty(true)),
            }
        }

        pub fn set_state(&mut self, new_state: State) {
            self.state = new_state
        }
    }

    impl VsaResult for MockVsaResult {
        type ValueDomain = Data;

        fn eval_address_at_def(&self, _def_tid: &Tid) -> Option<Data> {
            Some(self.address_at_def.clone())
        }

        fn eval_value_at_def(&self, _def_tid: &Tid) -> Option<Data> {
            Some(self.value_at_def.clone())
        }

        fn eval_at_jmp(&self, _jmp_tid: &Tid, expression: &Expression) -> Option<Data> {
            Some(self.state.eval(expression))
        }

        fn eval_parameter_arg_at_call(&self, _jmp_tid: &Tid, parameter: &Arg) -> Option<Data> {
            self.state
                .eval_parameter_arg(parameter, &self.runtime_memory_image)
                .ok()
        }

        fn eval_parameter_location_at_call(
            &self,
            _jmp_tid: &Tid,
            parameter: &AbstractLocation,
        ) -> Option<Data> {
            Some(
                self.state
                    .eval_abstract_location(parameter, &self.runtime_memory_image),
            )
        }

        fn eval_at_node(&self, _node: NodeIndex, expression: &Expression) -> Option<Data> {
            Some(self.state.eval(expression))
        }
    }
}
*/

//! Command line interface for the cwe_checker.
//!
//! General documentation about the cwe_checker is contained in the
//! [`cwe_checker_lib`] crate.

extern crate cwe_checker_lib; // Needed for the docstring-link to work

mod constants;
mod debug_functions;


use anyhow::Context;
use anyhow::Error;
use clap::{Parser, ValueEnum};
use colored::*;
use colored::control::SHOULD_COLORIZE;
use cwe_checker_lib::abstract_domain::TryToBitvec;
use cwe_checker_lib::intermediate_representation::Variable;
use cwe_checker_lib::utils::binary::MemorySegment;
use petgraph;
use petgraph::visit::IntoNodeReferences;

use cwe_checker_lib::analysis::graph;
use cwe_checker_lib::analysis::graph::Node;
use cwe_checker_lib::analysis::pointer_inference::PointerInference;
use cwe_checker_lib::analysis::pointer_inference::detector::resolve_jni_function_from_address;
use cwe_checker_lib::checkers::CweModule;
use cwe_checker_lib::pipeline::{disassemble_binary, AnalysisResults};
use cwe_checker_lib::utils::binary::BareMetalConfig;
use cwe_checker_lib::utils::debug;
use cwe_checker_lib::utils::log::LogThread;
use cwe_checker_lib::utils::log::WithLogs;
use cwe_checker_lib::utils::log::{print_all_messages, CweWarning, LogLevel, LogMessage};
use cwe_checker_lib::utils::read_config_file;
use cwe_checker_lib::abstract_domain::{DataDomain, IntervalDomain, PointerInfo};
use cwe_checker_lib::intermediate_representation::{Bitvector, Tid};
use cwe_checker_lib::abstract_domain::{AbstractIdentifier, AbstractLocation};
use cwe_checker_lib::intermediate_representation::Expression;

use std::collections::{BTreeSet, HashSet};
use std::convert::From;
use std::ops::Deref;
use std::path::PathBuf;

use crate::debug_functions::print_data_domain;


mod cfg_stats;

#[derive(ValueEnum, Clone, Debug, Copy)]
/// Selects which kind of debug output is displayed.
pub enum CliDebugMode {
    /// Output of the Ghidra plugin.
    PcodeRaw,
    /// The output of the Ghidra plugin deserialized into Rust types.
    PcodeParsed,
    /// The very first IR representation of the program.
    IrEarly,
    /// After blocks within a function have been normal ordered.
    IrFnBlksSorted,
    /// After non-returning external functions have been marked.
    IrNonRetExtFunctionsMarked,
    /// After calls to stubs for external functions have been replaced with
    /// calls to the external function.
    IrExtCallsReplaced,
    /// After existing, referenced blocks have blocks have been inlined into
    /// functions.
    IrInlined,
    /// After the subregister substitution pass.
    IrSubregistersSubstituted,
    /// After all control flow transfers have a valid target.
    IrCfPatched,
    /// After empty functions have been removed.
    IrEmptyFnRemoved,
    /// The unoptimized IR.
    IrRaw,
    /// After unreachable basic blocks have been removed from functions.
    IrIntraproceduralDeadBlocksElimed,
    /// After trivial expressions have been replaced with their results.
    IrTrivialExpressionsSubstituted,
    /// After input expressions have been propagated along variable assignments.
    IrInputExpressionsPropagated,
    /// After assignments to dead variables have been removed.
    IrDeadVariablesElimed,
    /// After control flow across conditionals with the same condition has been
    /// simplified.
    IrControlFlowPropagated,
    /// After stack pointer alignment via logical AND has been substituted with
    /// a subtraction operation.
    IrStackPointerAlignmentSubstituted,
    /// The final IR.
    IrOptimized,
    /// Whole-program call graph.
    Cg,
    /// Whole-program control flow graph.
    Cfg,
    /// Result of the Pointer Inference computation.
    Pi,
}

impl From<&CliDebugMode> for debug::Stage {
    fn from(mode: &CliDebugMode) -> Self {
        use CliDebugMode::*;
        match mode {
            PcodeRaw => debug::Stage::Pcode(debug::PcodeForm::Raw),
            PcodeParsed => debug::Stage::Pcode(debug::PcodeForm::Parsed),
            IrEarly => debug::Stage::Ir(debug::IrForm::Early),
            IrFnBlksSorted => debug::Stage::Ir(debug::IrForm::FnBlksSorted),
            IrNonRetExtFunctionsMarked => debug::Stage::Ir(debug::IrForm::NonRetExtFunctionsMarked),
            IrExtCallsReplaced => debug::Stage::Ir(debug::IrForm::ExtCallsReplaced),
            IrInlined => debug::Stage::Ir(debug::IrForm::Inlined),
            IrSubregistersSubstituted => debug::Stage::Ir(debug::IrForm::SubregistersSubstituted),
            IrCfPatched => debug::Stage::Ir(debug::IrForm::CfPatched),
            IrEmptyFnRemoved => debug::Stage::Ir(debug::IrForm::EmptyFnRemoved),
            IrRaw => debug::Stage::Ir(debug::IrForm::Raw),
            IrIntraproceduralDeadBlocksElimed => {
                debug::Stage::Ir(debug::IrForm::IntraproceduralDeadBlocksElimed)
            }
            IrTrivialExpressionsSubstituted => {
                debug::Stage::Ir(debug::IrForm::TrivialExpressionsSubstituted)
            }
            IrInputExpressionsPropagated => {
                debug::Stage::Ir(debug::IrForm::InputExpressionsPropagated)
            }
            IrDeadVariablesElimed => debug::Stage::Ir(debug::IrForm::DeadVariablesElimed),
            IrControlFlowPropagated => debug::Stage::Ir(debug::IrForm::ControlFlowPropagated),
            IrStackPointerAlignmentSubstituted => {
                debug::Stage::Ir(debug::IrForm::StackPointerAlignmentSubstituted)
            }
            IrOptimized => debug::Stage::Ir(debug::IrForm::Optimized),
            Cg => debug::Stage::CallGraph,
            Cfg => debug::Stage::ControlFlowGraph,
            Pi => debug::Stage::Pi,
        }
    }
}

#[derive(Debug, Parser)]
#[command(version, about)]
/// Find vulnerable patterns in binary executables
struct CmdlineArgs {
    /// The path to the binary.
    #[arg(required_unless_present("module_versions"), value_parser = check_file_existence)]
    binary: Option<String>,

    /// Path to a custom configuration file to use instead of the standard one.
    #[arg(long, short, value_parser = check_file_existence)]
    config: Option<String>,

    /// Write the results to a file instead of stdout.
    /// This only affects CWE warnings. Log messages are still printed to stdout.
    #[arg(long, short)]
    out: Option<String>,

    /// Specify a specific set of checks to be run as a comma separated list, e.g. 'CWE332,CWE476,CWE782'.
    ///
    /// Use the "--module-versions" command line option to get a list of all valid check names.
    #[arg(long, short)]
    partial: Option<String>,

    /// Generate JSON output.
    #[arg(long, short)]
    json: bool,

    /// Do not print log messages. This prevents polluting stdout for json output.
    #[arg(long, short)]
    quiet: bool,

    /// Print additional debug log messages.
    #[arg(long, short, conflicts_with("quiet"))]
    verbose: bool,

    /// Include various statistics in the log messages.
    /// This can be helpful for assessing the analysis quality for the input binary.
    #[arg(long, conflicts_with("quiet"))]
    statistics: bool,

    /// Path to a configuration file for analysis of bare metal binaries.
    ///
    /// If this option is set then the input binary is treated as a bare metal binary regardless of its format.
    #[arg(long, value_parser = check_file_existence)]
    bare_metal_config: Option<String>,

    /// Prints out the version numbers of all known modules.
    #[arg(long)]
    module_versions: bool,

    /// Output for debugging purposes.
    /// The current behavior of this flag is unstable and subject to change.
    #[arg(long, hide(true))]
    debug: Option<CliDebugMode>,

    /// Read the saved output of the Pcode Extractor plugin from a file instead
    /// of invoking Ghidra.
    #[arg(long, hide(true))]
    pcode_raw: Option<String>,

    /// Print some statistics and metrics of the IR-program's CFG and exit.
    #[arg(long, hide(true))]
    cfg_stats: bool,
}

impl From<&CmdlineArgs> for debug::Settings {
    fn from(args: &CmdlineArgs) -> Self {
        let stage = match &args.debug {
            None => debug::Stage::default(),
            Some(mode) => mode.into(),
        };
        let verbosity = if args.verbose {
            debug::Verbosity::Verbose
        } else if args.quiet {
            debug::Verbosity::Quiet
        } else {
            debug::Verbosity::default()
        };

        let mut builder = debug::SettingsBuilder::default()
            .set_stage(stage)
            .set_verbosity(verbosity)
            .set_termination_policy(debug::TerminationPolicy::EarlyExit);

        if let Some(pcode_raw) = &args.pcode_raw {
            builder = builder.set_saved_pcode_raw(PathBuf::from(pcode_raw.clone()));
        }

        builder.build()
    }
}

fn main() -> Result<(), Error> {
    let cmdline_args = CmdlineArgs::parse();

    // Check and print color support
    if SHOULD_COLORIZE.should_colorize() {
        println!("{}", "Terminal supports colors - using colored output".green());
    } else {
        println!("{}", "Terminal does not support colors - using plain output".yellow());
    }

    run_with_ghidra(&cmdline_args)
}

/// Return `Ok(file_path)` only if `file_path` points to an existing file.
fn check_file_existence(file_path: &str) -> Result<String, String> {
    if std::fs::metadata(file_path)
        .map_err(|err| format!("{err}"))?
        .is_file()
    {
        Ok(file_path.to_string())
    } else {
        Err(format!("{file_path} is not a file."))
    }
}

/// Run the cwe_checker with Ghidra as its backend.
fn run_with_ghidra(args: &CmdlineArgs) -> Result<(), Error> {
    let debug_settings = args.into();
    let mut modules = cwe_checker_lib::checkers::get_modules();
    if args.module_versions {
        // Only print the module versions and then quit.
        println!("[cwe_checker] module_versions:");
        for module in modules.iter() {
            println!("{module}");
        }
        return Ok(());
    }

    // Get the bare metal configuration file if it is provided
    let bare_metal_config_opt: Option<BareMetalConfig> =
        args.bare_metal_config.as_ref().map(|config_path| {
            let file = std::io::BufReader::new(std::fs::File::open(config_path).unwrap());
            serde_json::from_reader(file)
                .expect("Parsing of the bare metal configuration file failed")
        });
    let binary_file_path = PathBuf::from(args.binary.clone().unwrap());

    let (binary, mut project) =
        disassemble_binary(&binary_file_path, bare_metal_config_opt, &debug_settings)?;


    // This memory section represents memory contents of the JNIEnv* struct. It holds Function Addresses
    // The value of the first argument (JNIEnv*) is the start of this block
    let jnienv_addr = 0x13337;
    let jnienv_functions_start_addr = 0x20000;
    // Clone the memory image to make it mutable
    let mut memory_image = project.runtime_memory_image.clone();

    // Create a new memory segment at jnienv_addr containing 1024 integers counting up from 0x23337
    let segment_size = 8 * 1024; // 8 bytes per integer * 1024 integers
    
    // Create a vector to hold the 1024 integers
    let mut segment_function_addresses = Vec::with_capacity(segment_size);
    for i in 0..1024 {
        // Each integer is 8 bytes, little-endian
        let bytes = (i as u64 + jnienv_functions_start_addr).to_le_bytes();
        segment_function_addresses.extend_from_slice(&bytes);
    }
    
    // This segment stores the JNI Functions that the JNIEnv memory points to
    // JNIEnv struct points to addresses in here, even though there is no actual executable code.
    // todo maybe create stub functions to point to?
    let memory_segment_jnienv = MemorySegment {
        bytes: segment_function_addresses,
        base_address: jnienv_addr, 
        read_flag: true,
        write_flag: false,
        execute_flag: false,
    };
    
    memory_image.memory_segments.push(memory_segment_jnienv.clone());
    
    // Create a vector to hold the functions that the JNIEnv struct points to. 
    // 
    let mut segment_functions = Vec::with_capacity(segment_size);
    for i in 0..1024 {
        // Each integer is 8 bytes, little-endian
        let bytes = (jnienv_functions_start_addr + (i*8) as u64).to_le_bytes();
        segment_functions.extend_from_slice(&bytes);
    }
    
    // Create the memory segment
    let memory_segment_functions = MemorySegment {
        bytes: segment_functions,
        base_address: jnienv_functions_start_addr, 
        read_flag: true,
        write_flag: false,
        execute_flag: true,
    };
    
    memory_image.memory_segments.push(memory_segment_functions.clone());
    
    project.runtime_memory_image = memory_image;

    
    println!("{}", format!("Created memory segment at address 0x{:x} with size {}. This is the JNIEnv* struct", 
                          memory_segment_jnienv.base_address, memory_segment_jnienv.bytes.len()).green());
    println!("{}", format!("Created memory segment at address 0x{:x} with size {}. This is the JNI Functions", 
                          memory_segment_functions.base_address, memory_segment_functions.bytes.len()).green());
    if debug_settings.should_debug(debug::Stage::CallGraph) {
        // TODO: Move once call graph is used somewhere else.
        let cg = graph::call::CallGraph::new(&project.program);
        debug_settings.print_compact_json(&cg, debug::Stage::CallGraph);
    }

    if args.cfg_stats {
        let cfg_stats = cfg_stats::CfgProperties::new(&project.program);
        println!("{:#}", serde_json::to_value(cfg_stats)?);
        return Ok(());
    }

    // Filter the modules to be executed.
    if let Some(ref partial_module_list) = args.partial {
        filter_modules_for_partial_run(&mut modules, partial_module_list);
    } else if project.runtime_memory_image.is_lkm {
        modules.retain(|module| cwe_checker_lib::checkers::MODULES_LKM.contains(&module.name));
    } else {
        // TODO: CWE78 is disabled on a standard run for now,
        // because it uses up huge amounts of RAM and computation time on some binaries.
        modules.retain(|module| module.name != "CWE78");
    }

    // Get the configuration file.
    let config: serde_json::Value = if let Some(ref config_path) = args.config {
        let file = std::io::BufReader::new(std::fs::File::open(config_path).unwrap());
        serde_json::from_reader(file).context("Parsing of the configuration file failed")?
    } else if project.runtime_memory_image.is_lkm {
        read_config_file("lkm_config.json")?
    } else {
        read_config_file("config.json")?
    };

    // Generate the control flow graph of the program
    let control_flow_graph = graph::get_program_cfg_with_logs(&project.program);
    debug_settings.print_compact_json(control_flow_graph.deref(), debug::Stage::ControlFlowGraph);

    let analysis_results = AnalysisResults::new(&binary, &control_flow_graph, &project);

    let modules_depending_on_string_abstraction = BTreeSet::from_iter(["CWE78"]);
    let modules_depending_on_pointer_inference = BTreeSet::from_iter([
        "CWE119", "CWE134", "CWE190", "CWE252", "CWE337", "CWE416", "CWE476", "CWE789", "Memory",
    ]);

    let string_abstraction_needed = modules
        .iter()
        .any(|module| modules_depending_on_string_abstraction.contains(&module.name));

    let pi_analysis_needed = string_abstraction_needed
        || modules
            .iter()
            .any(|module| modules_depending_on_pointer_inference.contains(&module.name));

    // Compute function signatures if required
    let function_signatures = if pi_analysis_needed {
        let function_signatures = analysis_results.compute_function_signatures();

        Some(function_signatures)
    } else {
        None
    };
    let analysis_results =
        analysis_results.with_function_signatures(function_signatures.as_deref());


    
    let logging_thread = LogThread::spawn(LogThread::collect_and_deduplicate);

    let mut computation = PointerInference::new(
        &analysis_results,
        serde_json::from_value(config["Memory"].clone()).unwrap(),
        logging_thread.get_msg_sender(),
        args.statistics,
    );
    
    // Add taint markers to all function parameters
    println!("\n{}", "Adding taint markers to all function parameters:".bold());
    
    // First collect all the functions and their signatures
    let mut functions_to_taint = Vec::new();
    {
        let context = computation.get_context();
        for (tid, sub) in &analysis_results.project.program.term.subs {
            if let Some(fn_signature) = context.fn_signatures.get(tid) {
                // Only collect functions that start with "Java_"
                if sub.term.name.starts_with("Java_") {
                    functions_to_taint.push((tid.clone(), sub.term.name.clone(), fn_signature.parameters.len()));
                }
            } else {
                println!("{}: {}", sub.term.name.yellow(), "No function signature available".dimmed());
            }
        }
    }
    let jnienv_addri = 0x13337;
    let jnienv_addr =  Bitvector::from_i64(jnienv_addri);
    // Set taint marker
    let taint_string = "TAINT_MEMORY_ARRAY";
    let mem_ptr = IntervalDomain::new_pointer(
        PointerInfo::from_tag(taint_string.to_string()),
        jnienv_addr.clone(),
        jnienv_addr.clone()
    );
    let mut tainted_mem_value = DataDomain::<IntervalDomain>::from_target(
        AbstractIdentifier::new(
                Tid::new_block(format!("0x{:x}", jnienv_addri), 0),
            AbstractLocation::from_global_address(&jnienv_addr)
        ),
        Bitvector::from_i64(0).into()
    );
    tainted_mem_value.set_absolute_value(Some(mem_ptr));
    
    // Now apply the taint to each function parameter
    for (tid, fn_name, param_count) in functions_to_taint {
        println!("{}: {} parameters", fn_name.cyan().bold(), param_count);
        
        // Add taint to each paramete (except the first one)
        for param_idx in 1..param_count {  // Start from 1 instead of 0
            // Create taint string in the format TAINT_<function_name>_<arg_index>
            let taint_string = format!("TAINT_{}_{}",fn_name, param_idx);
            
            // Create Data object with appropriate value based on parameter index
            let bv = Bitvector::from_i64(0);  // All parameters get 0, not just first one
            let mut data = DataDomain::<IntervalDomain>::from(bv);
            
            // Set taint as pointer info
            data.set_absolute_value(Some(IntervalDomain::new_pointer(PointerInfo::from_tag(taint_string.clone()), jnienv_addr.clone(), jnienv_addr.clone())));
            
            // Add taint to the parameter
            if let Err(e) = computation.write_to_function_parameter(&tid, param_idx, data.clone()) {
                println!("  {}: {}", format!("Error setting taint for parameter {}", param_idx).red(), e);
            } else {
                println!("  {}: {}", format!("Parameter {}", param_idx).green(), taint_string);
            }
        }
    }

    let cconv = match project.get_specific_calling_convention(&Some(String::from("cdecl"))) {
        Some(cconv) => cconv,
        None => {
            panic!("Could not find calling convention");
        }
    };

    computation.compute(args.statistics);
    computation.fill_vsa_result_maps();
    let params = cconv.get_all_parameter_register();

    // Set to track functions that contain JNI calls
    let mut functions_with_jni_calls = std::collections::HashSet::new();
    
    // Get all Java_ functions
    let java_functions: Vec<_> = analysis_results.project.program.term.subs.iter()
        .filter(|(_, sub)| sub.term.name.starts_with("Java_"))
        .collect();
    
    println!("Found {} Java_ functions", java_functions.len());
    
    // Check each Java_ function for JNI calls
    for (tid, sub) in &java_functions {
        let mut has_jni_call = false;
        
        // Check all jumps in all blocks of this function
        for block in &sub.term.blocks {
            for jmp in &block.term.jmps {
                if let cwe_checker_lib::intermediate_representation::Jmp::CallInd { target, .. } = &jmp.term {
                    // Get the state at this jump
                    if let Some(state) = computation.get_state_at_jmp_tid(&jmp.tid) {
                        if let Expression::Var(var) = target {
                            let value = state.get_register(var);
                            let function_name = resolve_jni_function_from_address(&value);
                            if let Some((name, offset)) = function_name {
                                // This is a JNI call
                                has_jni_call = true;
                                println!("  {}: JNI call {} (offset: {})", sub.term.name.cyan(), name.green(), offset);
                                break;
                            }
                        }
                    }
                } else if let cwe_checker_lib::intermediate_representation::Jmp::Call { target, .. } = &jmp.term {
                    let sub = project.program.term.subs.iter().find(|(_, sub)| sub.tid.address() == target.address());
                    if let Some(sub) = sub {
                        let sub_name = &sub.1.term.name;
                        if sub_name.starts_with("llvm_") {
                            
                            println!("static call to {:}", sub_name);
                            if let Some(state) = computation.states_at_tids.get(&jmp.tid) {
                                for i in 0..3 {
                                    let value = state.get_register(params[i]);
                                    if let Some(absolute_value) = value.get_absolute_value() {
                                        match absolute_value.try_to_offset() {
                                            Ok(offset) => {
                                                if offset == jnienv_addri {
                                                    println!("[jni_detector] JNIEnv passed to function {}", sub_name);
                                                }
                                            }
                                            Err(_) => {
                                                
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if has_jni_call {
                break;
            }
        }
        
        if has_jni_call {
            functions_with_jni_calls.insert(tid.clone());
        }
    }
    
    // Print Java_ functions without JNI calls
    println!("\n{}", "Java_ functions WITHOUT JNI calls:".bold());
    let mut functions_without_jni = Vec::new();
    
    for (tid, sub) in &java_functions {
        if !functions_with_jni_calls.contains(tid) {
            functions_without_jni.push(&sub.term.name);
        }
    }
    
    if functions_without_jni.is_empty() {
        println!("  {}", "All Java_ functions contain JNI calls".green());
    } else {
        println!("  Found {} Java_ functions without JNI calls:", functions_without_jni.len());
        for function_name in functions_without_jni {
            println!("    {}", function_name.yellow());
        }
    }

   for (tid, sub) in &project.program.term.subs {
    if sub.term.name.starts_with("llvm_") {
        // get 1st parameter

        let params = cconv.get_all_parameter_register();
        if let Some(state) = computation.states_at_tids.get(tid) {
            let value = state.get_register(params[0]);
            print_data_domain(&value, "state at 1st register");
        }

    }
   }
    
   return Ok(());
    // save the logs and CWE warnings
    let (logs, cwe_warnings) = logging_thread.collect();
    computation.collected_logs = WithLogs::new(cwe_warnings, logs);
    let pi_results = computation;
    
    let analysis_results = analysis_results.with_pointer_inference(Some(&pi_results));
    // Compute string abstraction analysis if required
    let string_abstraction_results =
        if string_abstraction_needed {
            Some(analysis_results.compute_string_abstraction(
                &config["StringAbstraction"],
                Some(&pi_results)
            ))
        } else {
            None
        };
    let analysis_results =
        analysis_results.with_string_abstraction(string_abstraction_results.as_ref());

    // Print debug and then return.
    // Right now there is only one debug printing function.
    // When more debug printing modes exist, this behaviour will change!
    if debug_settings.should_debug(debug::Stage::Pi) {
        cwe_checker_lib::analysis::pointer_inference::run(
            &analysis_results,
            serde_json::from_value(config["Memory"].clone()).unwrap(),
            true,
            false,
        );
        return Ok(());
    }

    // Execute the modules and collect their logs and CWE-warnings.
    let mut all_cwe_warnings = Vec::new();
    for module in modules {
        let cwe_warnings = (module.run)(&analysis_results, &config[&module.name], &debug_settings);
        all_cwe_warnings.push(cwe_warnings);
    }

    // Print the results of the modules.
    let all_logs: Vec<&LogMessage> = if args.quiet {
        Vec::new() // Suppress all log messages since the `--quiet` flag is set.
    } else {
        let mut all_logs = Vec::new();

        // Aggregate the logs of all objects that come with logs.
        all_logs.extend(project.logs().iter());
        all_logs.extend(control_flow_graph.logs().iter());
        if let Some(function_signatures) = &function_signatures {
            all_logs.extend(function_signatures.logs().iter());
        }
        for cwe_warnings in all_cwe_warnings.iter() {
            all_logs.extend(cwe_warnings.logs().iter());
        }

        if args.statistics {
            // TODO: Fix the `--statistics` flag.
            //cwe_checker_lib::utils::log::add_debug_log_statistics(&mut all_logs);
            todo!()
        }
        if !args.verbose {
            all_logs.retain(|log_msg| log_msg.level != LogLevel::Debug);
        }

        all_logs
    };
    let all_cwes: Vec<&CweWarning> = all_cwe_warnings.iter().flat_map(|x| x.iter()).collect();

    print_all_messages(all_logs, all_cwes, args.out.as_deref(), args.json);

    if false {
        if let Some(binary_path) = &args.binary {
            let output_path = format!("{}.json", binary_path);
            let json_value = pi_results.generate_compact_json();
            if let Ok(json_str) = serde_json::to_string_pretty(&json_value) {
                if let Err(e) = std::fs::write(&output_path, json_str) {
                    println!("{}", format!("Warning: Failed to write pointer inference results to {}: {}", output_path, e).yellow());
                } else {
                    println!("{}", format!("Pointer inference results written to {}", output_path).green());
                }
            }
        }
    }
    
    if false {
        // Print function addresses and names
        println!("\n{}", "Functions in program:".bold());
        for (tid, sub) in &analysis_results.project.program.term.subs {
            let address = match u64::try_from(sub.tid.address()) {
                Ok(addr) => addr,
                Err(_) => 0,
            };
            let name = &sub.term.name;
            let fn_signature = pi_results.get_context().fn_signatures.get(tid);
            println!("{}: {}", 
                format!("0x{:x} {:?}", address, fn_signature).yellow(),
                name.to_string().cyan()
                );
        }
    }

    Ok(())
}

/// Only keep the modules specified by the `--partial` parameter in the `modules` list.
/// The parameter is a comma-separated list of module names, e.g. 'CWE332,CWE476,CWE782'.
fn filter_modules_for_partial_run(modules: &mut Vec<&CweModule>, partial_param: &str) {
    let module_names: HashSet<&str> = partial_param.split(',').collect();
    *modules = module_names
        .into_iter()
        .filter_map(|module_name| {
            if let Some(module) = modules.iter().find(|module| module.name == module_name) {
                Some(*module)
            } else if module_name.is_empty() {
                None
            } else {
                panic!("Error: {module_name} is not a valid module name.")
            }
        })
        .collect();
}

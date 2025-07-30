
use crate::abstract_domain::{DataDomain, IntervalDomain, PointerInfo, RegisterDomain, TryToBitvec};
use crate::analysis::pointer_inference::detector::constants::JniCallOffset;
use crate::analysis::pointer_inference::{self, State};
use crate::intermediate_representation::{Jmp, Project, RuntimeMemoryImage, Sub};
use crate::prelude::{Bitvector, Term};
mod constants;

/// Resolve a function name from an address value
/// Returns (function_name, offset) tuple
pub fn resolve_jni_function_from_address(
    value: &DataDomain<IntervalDomain>
) -> Option<(String, u64)> {
    if let Some(address) = value.get_absolute_value() {
        // Try to extract a u64 value from the interval domain
        if let Ok(bitvec) = address.try_to_bitvec() {
            if let Ok(addr_u64) = bitvec.try_to_u64() {
                let address_str = format!("{:#x}", addr_u64);
                
                // Check if address is in JNI environment range (0x20000 to 0x20fff)
                if addr_u64 >= 0x20000 && addr_u64 <= 0x20fff {
                    let offset = addr_u64 - 0x20000;
                    // Lookup function from constants::JNI_ENV_FUNCTIONS
                    if let Some(function) = constants::JNI_ENV_FUNCTIONS.get(offset as usize) {
                        return Some((function.to_string(), offset));
                    }
                }

            }
        }
    }
    
    None
}


/// Helper to extract a null-terminated string from memory, up to max_len bytes
fn extract_null_terminated_string_from_memory(
    memory_image: &RuntimeMemoryImage,
    address: &Bitvector,
    max_len: usize,
) -> Option<String> {
    // Find the segment and index
    for segment in &memory_image.memory_segments {
        let addr_u64 = address.try_to_u64().ok()?;
        if addr_u64 >= segment.base_address && addr_u64 < segment.base_address + segment.bytes.len() as u64 {
            let start_index = (addr_u64 - segment.base_address) as usize;
            let bytes = &segment.bytes[start_index..std::cmp::min(segment.bytes.len(), start_index + max_len)];
            if let Some(end_index) = bytes.iter().position(|&b| b == 0) {
                let slice = &bytes[..=end_index];
                if let Ok(c_str) = std::ffi::CStr::from_bytes_with_nul(slice) {
                    if let Ok(s) = c_str.to_str() {
                        return Some(s.to_string());
                    }
                }
            } else {
                // No null terminator found in max_len
                let slice = bytes;
                if let Ok(s) = std::str::from_utf8(slice) {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Extract a string constant from an absolute value by resolving its address
fn extract_string_constant_from_absolute_value(
    absolute_value: &IntervalDomain,
    memory_image: &RuntimeMemoryImage,
    max_len: usize,
) -> Option<String> {
    // Only proceed if the interval is precise (start == end)
    let addr_bv = absolute_value.try_to_bitvec().ok()?;
    
    extract_null_terminated_string_from_memory(memory_image, &addr_bv, max_len)
}
pub fn get_pointer_info(data_domain: &DataDomain<IntervalDomain>) -> Option<PointerInfo> {
    if let Some(absolute_value) = data_domain.get_absolute_value() {
        return Some(absolute_value.pointer_info.clone());
    }
    let relative_values = data_domain.get_relative_values();
    if !relative_values.is_empty() {
        for (id, val) in relative_values {
            return Some(val.pointer_info.clone());
        }
    }
    None
}
pub fn update_pointer_info(data_domain: &mut DataDomain<IntervalDomain>, update_callback: &dyn Fn(&PointerInfo) -> PointerInfo){
    if let Some(absolute_value) = data_domain.get_absolute_value() {
        let data = absolute_value.with_pointer_info(update_callback(&absolute_value.pointer_info));
        data_domain.set_absolute_value(Some(data));
    }
    let relative_values = data_domain.get_relative_values();
    if !relative_values.is_empty() {
        let mut new_relative_values = std::collections::BTreeMap::new();
        for (id, val) in relative_values {
            let updated_offset = val.with_pointer_info(update_callback(&val.pointer_info));
            new_relative_values.insert(id.clone(), updated_offset);
        }
        data_domain.set_relative_values(new_relative_values);
    }
    
}

pub fn process_jni_call(project: &Project, state: &State, name: &str, offset: u64, call: &Term<Jmp>) -> Option<State> {
    match project.program.find_sub_containing_jump(&call.tid) {
        Some(sub_tid) => {
            if let Some(sub) = project.program.term.subs.get(&sub_tid) {
                println!("[jni_detector] Processing JNI Call in Method: {:?}", sub.term.name);
                println!("[jni_detector] Call: {:?} Offset: {}", name, offset);  
            }
        }
        None => {
            println!("[jni_detector] Could not find sub containing jump");
        }
    }
        
        

    let max_len = 300;
    let memory_image = &project.runtime_memory_image;
    let cconv = match project.get_specific_calling_convention(&Some(String::from("cdecl"))) {
        Some(cconv) => cconv,
        None => {
            panic!("Could not find calling convention");
        }
    };
    let param_registers = cconv.get_all_parameter_register();
    let return_registers = cconv.get_all_return_register();

    
    if offset == JniCallOffset::FindClass as u64 {
        let class_name_register = &param_registers[2];
        let class_name = state.get_register(class_name_register);
        if let Some(absolute_value) = class_name.get_absolute_value() {
            match extract_string_constant_from_absolute_value(&absolute_value, memory_image, max_len) {
                Some(s) => {
                    println!("[jni_detector] Resolved class name string: {} updating pointer info", s);
                    let mut ret = state.get_register(return_registers[0]).clone();
                    update_pointer_info(&mut ret, &|pointer_info| pointer_info.with_class_id(s.clone()));
                    let mut new_state = state.clone();
                    new_state.set_register(return_registers[0], ret);
                    return Some(new_state);
                },
                None => {
                    if let Ok(addr_bv) = absolute_value.try_to_bitvec() {
                        println!("[jni_detector] Could not resolve class name string at address: 0x{:x}", addr_bv.try_to_u64().unwrap_or(0));
                    }
                }
            }
        }
    } else if offset == JniCallOffset::GetMethodId as u64 {
        let method_id_register = &param_registers[3];
        let method_id = state.get_register(method_id_register);

        let class_id_register = &param_registers[2];
        let class_id = state.get_register(class_id_register);
        let class_id_pointer_info = get_pointer_info(&class_id);
        if let Some(absolute_value) = method_id.get_absolute_value() {
            match extract_string_constant_from_absolute_value(&absolute_value, memory_image, max_len) {
                Some(s) => {
                    println!("[jni_detector] Resolved method name string: {} updating pointer info", s);
                    let mut ret = state.get_register(return_registers[0]).clone();
                    update_pointer_info(&mut ret, 
                        &|pointer_info| 
                        pointer_info.with_method_id(s.clone())
                    );
                    if let Some(class_id_pointer_info) = class_id_pointer_info {
                        update_pointer_info(&mut ret, 
                            &|pointer_info| 
                            pointer_info.with_class_ids(class_id_pointer_info.class_id.clone())
                        );
                    }
                    let mut new_state = state.clone();
                    new_state.set_register(return_registers[0], ret);
                    return Some(new_state);
                },
                None => {
                    if let Ok(addr_bv) = absolute_value.try_to_bitvec() {
                        println!("[jni_detector] Could not resolve class name string at address: 0x{:x}", addr_bv.try_to_u64().unwrap_or(0));
                    }
                }
            }
        }
    } else if offset >= JniCallOffset::CallObjectMethod as u64 && offset <= JniCallOffset::GetFieldId as u64 {
        let method_id_register = &param_registers[3];
        let method_id = state.get_register(method_id_register);

        let method_id_pointer_info = get_pointer_info(&method_id);
        if let Some(method_id_pointer_info) = method_id_pointer_info {
            println!("[jni_detector] Call Detected for Method ID: {:?} \n Tagged Call Arguments", method_id_pointer_info);
            // get call arguments
            for i in 3..param_registers.len() {
                let param_register = &param_registers[i];
                let param = state.get_register(param_register);
                if let Some(param_pointer_info) = get_pointer_info(&param) {
                    if param_pointer_info.tags.len() > 0 {
                        println!("[jni_detector] Parameter {} : {:?}", i, param_pointer_info);
                    }
                }
            }
            return Some(state.clone());
        }    
    }
    return None;
}
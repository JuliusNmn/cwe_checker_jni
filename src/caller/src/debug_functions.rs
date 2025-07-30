
use colored::*;
use cwe_checker_lib::abstract_domain::{DataDomain, RegisterDomain};
/// Helper function to print a DataDomain value with consistent coloring
pub fn print_data_domain<T: RegisterDomain + std::fmt::Debug>(value: &DataDomain<T>, label: &str) {
    let rel_vals = value.get_relative_values();
    let abs_vals = value.get_absolute_value();
    if !rel_vals.is_empty() || !abs_vals.is_none() {
        println!("    {} {}", label.white().bold(), "=".white());
    } else {
        println!("    {} {}", label.white(), "=".white());
    }
    // Print relative_values
    if !rel_vals.is_empty() {
        println!("      {}", "relative_values:");
        for (k, v) in rel_vals {
            println!("        {}", format!("{:?}", k).magenta());
            println!("        {}", format!("{:?}", v).green());
            
        }   
    } else {
        println!("      {}", "relative_values: {{}}".dimmed());
    }
    // Print absolute_value
    match abs_vals{
        Some(abs) => {
            println!("      {} {}", "absolute_value:", format!("{:?}", abs).cyan());
            

        },
        None => println!("      {}", "absolute_value: None".dimmed()),
    }
    // Print contains_top_values
    println!("      {} {}", "contains_top_values:", format!("{}", value.contains_top()).blue());
}

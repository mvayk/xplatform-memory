use std::{fs::File, io};
use xplatform_memory::memory::{
    definitions::{Module, ProtectionType},
    wrapper::*,
};

pub fn main() -> io::Result<()> {
    let process_name = "test";
    let process = Process::new(process_name)?;
    let module: Module = process.get_module(process_name)?;

    // let at_base = process.read_memory(module_base)?;

    let pid = process.pid;
    let maps_file = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    println!("{}", maps_file);

    Ok(())
}

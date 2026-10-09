use std::{fs::File, io};
use xplatform_memory::memory::{definitions::ProtectionType, wrapper::*};

pub fn main() -> io::Result<()> {
    let process_name = "ArmaReforgerSteam.exe";
    let process = Process::new(process_name)?;
    let module_base = process.get_module_base(process_name)?;

    // let at_base = process.read_memory(module_base)?;
    println!("ass");

    let pid = process.pid;
    let maps_file = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    println!("{}", maps_file);

    Ok(())
}

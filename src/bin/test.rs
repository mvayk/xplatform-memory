use std::io;
use xplatform_memory::memory::{definitions::ProtectionType, wrapper::*};

pub fn main() -> io::Result<()> {
    let process_name = "";
    let process = Process::new(process_name)?;
    process.get_module_base(process_name)?;

    Ok(())
}

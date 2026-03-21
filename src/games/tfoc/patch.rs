use std::io;

use crate::memory::*;
use crate::wrapper::*;

pub fn patch(process_name: &str) -> io::Result<()> {
    let process = Process::new(process_name)?;
    println!("PID: {}", process.pid);

    let module_base = process.get_module_base(process_name)?;
    println!("base: {:x}", module_base);

    Ok(())
}

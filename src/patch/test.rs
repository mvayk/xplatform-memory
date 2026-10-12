use crate::{
    formatter::Hex,
    process::*,
    types::{Address, Module, ProtectionType},
};
use std::io;

pub fn entry() -> io::Result<()> {
    crate::log!("testing");
    let process_name = "test";
    let process = Process::new(process_name)?;
    let pid = process.pid;

    // let maps_file = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    // println!("{}", maps_file);

    let module: Module = process.get_module(process_name)?;

    process.read_memory::<Address>(module.address.start)?;
    process.protect_memory(&[0x14000], 1usize, ProtectionType::PAGE_NOACCESS)?;

    let filtered_regions = process.inner.get_filtered_regions()?;
    let more_filtered: Vec<crate::linux::map::MapEntry> = Vec::new();
    for region in filtered_regions {
        if region.is_readable() {
            //log!(region);
        }
    }

    Ok(())
}

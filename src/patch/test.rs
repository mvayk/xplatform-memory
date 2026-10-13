use crate::{
    formatter::Hex,
    linux::map::MapEntry,
    process::*,
    types::{Address, Module},
};
use std::io;

pub fn entry() -> io::Result<()> {
    let process_name = "test";
    let process = Process::new(process_name)?;
    let pid = process.pid;

    // let maps_file = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    // println!("{}", maps_file);

    let module: Module = process.get_module(process_name)?;
    let filtered_regions = process.inner.get_filtered_regions()?;

    let mut stack: MapEntry;
    for region in filtered_regions {
        if region.is_readable() {
            crate::log!("{}", region);
            if region.module_name == "[stack]" {
                stack = region;
                crate::log!("found stack");
                // process.protect_memory(
                //     &[stack.start_address],
                //     (stack.end_address - stack.start_address) as usize,
                //     ProtectionType::PAGE_NOACCESS,
                // )?;
            }
        }
    }

    let baseregion = process
        .inner
        .get_region_from_address(module.address.start)?;

    crate::log!(region = format_args!("{baseregion}"));
    process.read_memory::<Address>(module.address.start)?;

    Ok(())
}

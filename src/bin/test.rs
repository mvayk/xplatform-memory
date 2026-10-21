#![allow(unused)]
use std::io;

use tracing::warn;

use xpmemtool::{
    core::{self, Xpmentool},
    formatter::Hex,
    linux::{map::MapEntry, readwrite::MemData},
    process::*,
    types::{Address, Module, ProtectionType},
};

fn main() -> io::Result<()> {
    core::Xpmentool::init();

    let process_name = "openttd.exe";
    let process = Process::new(process_name)?;

    // let maps_file = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    // println!("{}", maps_file);

    let module: Module = process.get_module(process_name)?;
    let filtered_regions = process.inner.get_filtered_regions()?;

    for region in filtered_regions {
        if region.is_readable() {
            xpmemtool::log!("{}", region);
            if region.module_name == "[stack]" {
                xpmemtool::log!("found stack");
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

    let a = baseregion.get_pages();
    process.protect_memory(
        &[baseregion.addresses.start],
        1usize,
        ProtectionType::PAGE_EXECUTE_READWRITE,
    )?;

    xpmemtool::log!(region = format_args!("{baseregion}"));

    xpmemtool::log!("not a successful one");

    // for x in a {
    //     xpmemtool::log!(page = %x);
    // }

    let ptr = process.allocate_memory()?;
    process.inner.get_region_from_address(ptr)?;

    let memdatas = process.read_memory(&[ptr])?;
    for memdata in memdatas {
        let converted = memdata.to_u64();
        xpmemtool::log!(converted);
        xpmemtool::log!(%memdata);
    }

    //process.read_memory::<Address>(module.address.start)?;
    //process.inner.get_page_from_address(module.address.start)?;

    Ok(())
}

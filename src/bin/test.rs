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
    let mut module: Module = process.get_module(process_name)?;

    let mut baseregion = process
        .inner
        .get_region_from_address(module.address.start)?;

    baseregion.update(&process);

    let modulepid = baseregion.pid;
    let modulename = module.name;
    xpmemtool::log!(base = format_args!("{baseregion} at {modulename} in {modulepid}"));

    let allocation = process.allocate_memory()?;
    //process.inner.get_page_from_address(allocation)?;

    process.protect_memory(
        &[allocation],
        1usize,
        ProtectionType::PAGE_EXECUTE_READWRITE,
    )?;

    let memdatas = process.inner.read_memory_long(&[allocation])?;

    for memdata in memdatas {
        let converted = memdata.to_u64();
        xpmemtool::log!(converted);
        xpmemtool::log!(%memdata);
    }

    Ok(())
}

fn stack_check(process: &Process) -> io::Result<()> {
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

    Ok(())
}

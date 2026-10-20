#![allow(unused)]
use std::io;

use tracing::warn;

use xpmemtool::{
    core::{self, Xpmentool},
    formatter::Hex,
    linux::map::MapEntry,
    process::*,
    types::{Address, Module, ProtectionType},
};

fn main() -> io::Result<()> {
    core::Xpmentool::init();

    // let bwrap = Process::new("bwrap")?;
    let sober = Process::new("openttd.exe")?;
    // xpmemtool::log!(bwrap_pid = bwrap.pid);
    // xpmemtool::log!(sober = sober.pid);

    //let find_all_pids = sober.inner.find_all_pids("sober")?;

    tracing::trace!("balls");

    // for pid in find_all_pids {
    //     xpmemtool::log!(pid);
    // }

    Ok(())
}

fn idkidk() -> io::Result<()> {
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

    // for x in a {
    //     xpmemtool::log!(page = %x);
    // }

    let ptr = process.allocate_memory()?;
    process.inner.get_region_from_address(ptr)?;

    let idk = process.read_memory::<u64>(ptr)?;
    xpmemtool::log!(idk);

    process.write_memory(idk, &[64])?;

    let idk = process.read_memory::<u64>(ptr)?;
    xpmemtool::log!(idk);

    //process.read_memory::<Address>(module.address.start)?;
    //process.inner.get_page_from_address(module.address.start)?;

    Ok(())
}

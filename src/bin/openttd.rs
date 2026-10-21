#![allow(dead_code)]
use std::io;
use xpmemtool::{core::Xpmentool, process::Process, types::Address};

pub fn main() -> io::Result<()> {
    Xpmentool::init();

    let process_name = "openttd.exe";
    let process = Process::new(process_name)?;
    let module_base = process.get_module_base(process_name)?;

    /*
        -- WINE --
        (a)"openttd.exe"+00F97380 +
        (b)(a + 0x0)
        (final)b + 0x90
    */

    let level1 = process.read_memory((module_base) + 0xF97380)?;
    let level2 = process.read_memory(level1)?;
    let money_addy = level2 + 0x90;

    process.read_memory(money_addy)?;
    process.write_memory(money_addy, 12000000u64)?;

    Ok(())
}

fn openttd_linux_long(process: &Process) -> io::Result<()> {
    let module_base = process.get_module_base("openttd.exe")?;
    let level1 = process
        .inner
        .read_memory_long(&[(module_base + 0xF97380)])?;
    let level2 = process
        .inner
        .read_memory_long(&[level1[0].to_u64()] /*+ 0x0 */)?;
    let money_addy = (level2[0].to_u64()) + 0x90;

    process.inner.read_memory_long(&[money_addy])?;
    process.inner.write_memory_long(
        &[money_addy],
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
    )?;

    Ok(())
}

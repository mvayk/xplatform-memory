use crate::{process::Process, types::Address};
use std::io;

pub fn entry() -> io::Result<()> {
    let process_name = "openttd.exe";
    let process = Process::new(process_name)?;
    let module_base = process.get_module_base(process_name)?;

    /*
        -- WINE --
        (a)"openttd.exe"+00F97380 +
        (b)(a + 0x0)
        (final)b + 0x90
    */
    let level1 = process.read_memory::<Address>(module_base + 0xF97380)?;
    let level2 = process.read_memory::<Address>(level1 + 0x0)?;
    let money_addy = level2 + 0x90;

    process.read_memory::<i64>(money_addy)?;
    process.write_memory(money_addy, &100000000i64)?;

    Ok(())
}

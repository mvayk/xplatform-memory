use std::io;

use xplatform_memory::memory::wrapper::*;

pub fn main() -> io::Result<()> {
    let process_name = "openttd.exe";
    println!("[+] Patching: {}", process_name);

    let process = Process::new(process_name)?;
    println!("PID: {}", process.process.pid);

    let module_base = process.get_module_base(process_name)?;
    println!("base: {:x}", module_base);

    /*
        -- WINE --
        (a)"openttd.exe"+00F97380 +
        (b)(a + 0x0)
        (final)b + 0x90
    */
    let level1 = process.read_memory::<usize>(module_base + 0xF97380)?;
    let level2 = process.read_memory::<usize>(level1 + 0x0)?;
    let money_addy = level2 + 0x90;
    let money = process.read_memory::<i64>(money_addy)?;

    println!("{:?}", money);
    process.write_memory(money_addy, &100000000i64)?;

    Ok(())
}

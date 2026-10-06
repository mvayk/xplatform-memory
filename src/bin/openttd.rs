use std::{
    fs::File,
    io::{self, BufWriter, Write},
};
use xplatform_memory::memory::{definitions::ProtectionType, wrapper::*};

fn dump_stuff(process: &Process) -> io::Result<()> {
    let readable_regions = process.get_readable_regions()?;
    let mut file = BufWriter::new(File::create("readable_regions.bin")?);
    for region in &readable_regions {
        writeln!(file, "{:#x}-{:#x}", region.0, region.1)?;
    }
    file.flush()?;

    let mem_pages = process.get_all_pages()?;
    let mut file = BufWriter::new(File::create("mem_pages.bin")?);
    for region in &mem_pages {
        writeln!(file, "{:#x}", region)?;
    }
    file.flush()?;

    Ok(())
}

pub fn main() -> io::Result<()> {
    let process_name = "openttd.exe";
    let process = Process::new(process_name)?;
    let module_base = process.get_module_base(process_name)?;

    /*
        -- WINE --
        (a)"openttd.exe"+00F97380 +
        (b)(a + 0x0)
        (final)b + 0x90
    */
    let level1 = process.read_memory::<usize>(module_base + 0xF97380)?;
    let level2 = process.read_memory::<usize>(level1 + 0x0)?;
    let money_addy = level2 + 0x90;
    //process.read_memory::<i64>(money_addy)?;

    process.write_memory(money_addy, &100000000i64)?;

    //dump_stuff(&process)?;
    // let addy = [0x1400000].to_vec();
    // process.protect_memory(addy, 1usize, ProtectionType::PAGE_EXECUTE_READWRITE)?;

    /* dont do this. */
    // process.protect_memory(
    //     process.get_all_pages()?,
    //     1usize,
    //     ProtectionType::PAGE_EXECUTE_READWRITE,
    // )?;

    process.exit()
}

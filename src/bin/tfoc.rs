use std::io;
use xpmemtool::{core::Xpmentool, log, process::*};

pub fn main() -> io::Result<()> {
    Xpmentool::init(true);

    let process_name = "tfoc.exe";
    let process = Process::new(process_name)?;

    /* SetMaxTickRate */
    let max_fps_address = 0x19FB01C;

    let old_fps = process.read_memory::<u64>(max_fps_address)?;
    log!(old_fps = old_fps, "old fps:");
    process.write_memory(max_fps_address, &10.0f32)?;
    println!(
        "FPS cap set to {:?}",
        process.read_memory::<u64>(max_fps_address)?
    );

    Ok(())
}

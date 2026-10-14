use std::io;
use xpmemtool::process::*;

pub fn main() -> io::Result<()> {
    let process_name = "tfoc.exe";
    let process = Process::new(process_name)?;

    /* SetMaxTickRate */
    let max_fps_address = 0x19FB01C;

    process.write_memory(max_fps_address, &10.0f32)?;
    println!(
        "FPS cap set to {:?}",
        process.read_memory::<f32>(max_fps_address)?
    );

    Ok(())
}

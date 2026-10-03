use std::io;
use xplatform_memory::memory::wrapper::*;

pub fn main() -> io::Result<()> {
    let process_name = "tfoc.exe";
    println!("[+] Patching: {}", process_name);

    let process = Process::new(process_name)?;
    println!("PID: {}", process.pid);

    let module_base = process.get_module_base(process_name)?;
    println!("base: {:x}", module_base);

    /* SetMaxTickRate */
    let max_fps_address = 0x19FB01Cusize;
    println!("{max_fps_address}");
    println!("{:?}", process.read_memory::<u32>(max_fps_address)?);

    process.write_memory(max_fps_address, &10.0f32)?;
    println!(
        "FPS cap set to {:?}",
        process.read_memory::<f32>(max_fps_address)?
    );

    Ok(())
}

use std::io;

mod memory;
use crate::memory::*;
use crate::wrapper::*;

fn main() -> io::Result<()> {
    let tfoc: (&str, bool) = ("TFOC.exe", false);
    let twfc: (&str, bool) = ("TWFC_steamless.exe", true);

    if tfoc.1 == true {
        let process = Process::new("TFOC.exe")?;
        println!("PID: {}", process.pid);

        let module_base = process.get_module_base("TFOC.exe")?;
        println!("base: {:x}", module_base);
    } else if twfc.1 == true {
        let process = Process::new("TWFC_steamless.exe")?;
        println!("PID: {}", process.pid);

        let module_base = process.get_module_base("TWFC_steamless.exe")?;
        println!("base: {:x}", module_base);

        /* tfoc fps unlocker thx for magical address */
        let max_fps_address = 0x12A03F30usize;

        process.write_memory(max_fps_address, &260.0f32)?;
        println!(
            "FPS cap set to {:?}",
            process.read_memory::<f32>(max_fps_address)?
        );
    } else {
        panic!("I DONT KNOW");
    }

    Ok(())
}

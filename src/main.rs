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

        /* semi fov fix
        func signature:
        int __userpurge sub_117BADC0@<xmm0>(int this@<ecx>)

        allocate memory and write fov value to allocation because xmm0 doesnt support being written to directly
        and then override original instructions that asscess fov with new instructions
        */
        let cave_addr = process.allocate_memory(4)?;
        process.write_memory(cave_addr, &120.0f32)?;

        let cave_bytes = (cave_addr as u32).to_le_bytes();
        let patch: [u8; 9] = [
            0xF3,
            0x0F,
            0x10,
            0x05, // MOVSS xmm0, [imm32]
            cave_bytes[0],
            cave_bytes[1],
            cave_bytes[2],
            cave_bytes[3],
            0xC3, // RET
        ];

        process.write_memory(0x117BADC0, &patch)?;
    } else {
        panic!("I DONT KNOW");
    }

    Ok(())
}

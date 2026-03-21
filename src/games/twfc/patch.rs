use std::io;

use crate::memory::*;
use crate::wrapper::*;

pub fn patch(process_name: &str) -> io::Result<()> {
    let process = Process::new(process_name)?;
    println!("PID: {}", process.pid);

    let module_base = process.get_module_base(process_name)?;
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
    /* let cave_addr = process.allocate_memory(4)?;
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

    process.write_memory(0x117BADC0, &patch)?; */

    /* twfc widescreen patch signature */
    let pattern: &str = "
        8B ?? ?? 89 ?? ?? ?? ?? ?? D9 ?? ?? D9 ?? ?? ?? ?? ?? C3
    ";

    let signature = process.scan_module(process_name, pattern)?;
    let fov_address = signature + 0xC;
    let cave_addr = process.allocate_memory(4)?;

    process.write_memory(cave_addr, &120.0f32)?;
    let mut patch: [u8; 6] = [0xD9, 0x05, 0, 0, 0, 0];
    patch[2..].copy_from_slice(&(cave_addr as u32).to_le_bytes());

    process.write_memory(fov_address, &patch)?;

    Ok(())
}

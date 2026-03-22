use std::io;

use crate::memory::wrapper::*;

const DEFAULT_ASPECT: f32 = 1.777777791;
const BASE_FOV: f32 = 90.0;

fn calculate_fov(aspect_ratio: f32, additional_fov: f32) -> io::Result<f32> {
    let ratio = aspect_ratio / DEFAULT_ASPECT;
    let half_fov = (BASE_FOV / 2.0).to_radians();
    let corrected = 2.0 * (half_fov.tan() * ratio).atan();
    Ok(corrected.to_degrees() + additional_fov)
}

pub fn patch(process_name: &str) -> io::Result<()> {
    let process = Process::new(process_name)?;
    println!("PID: {}", process.pid);

    let module_base = process.get_module_base(process_name)?;
    println!("base: {:x}", module_base);

    /* tfoc fps unlocker thx for magical address */
    let max_fps_address = 0x12A03F30usize;
    println!("{:?}", process.read_memory::<u32>(max_fps_address)?);

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

    only issue is that for some reason when you zoom in you zoom out?

    allocating memory on linux is apparently very hard so instead we are going to override 4 bytes somewhere in the executable instead of allocating 4 bytes
    apparently apparently when wine setups .text section it is only readable and executable and for some reason not writable. so we gotta ptrace attach and then write
    */
    /*let allocation_addr = process.allocate_memory(4)?; */
    let cave_addr = 0x12A3CCD0;
    let fov = calculate_fov(
        process.get_aspect_ratio("Transformers: War for Cybertron")?,
        20.0f32,
    )?;
    process.write_memory(cave_addr, &fov)?;

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

    Ok(())
}

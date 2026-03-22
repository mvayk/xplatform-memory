use std::io;

fn main() -> io::Result<()> {
    xplatform_memory::games::tfoc::patch("TFOC.exe");
    Ok(())
}

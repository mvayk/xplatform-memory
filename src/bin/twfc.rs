use std::io;

fn main() -> io::Result<()> {
    xplatform_memory::games::tfoc::patch("TWFC_steamless.exe");
    Ok(())
}

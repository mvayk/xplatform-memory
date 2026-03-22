use std::io;

fn main() -> io::Result<()> {
    xplatform_memory::games::twfc::patch("TWFC_steamless.exe");
    Ok(())
}

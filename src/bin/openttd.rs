use std::io;

fn main() -> io::Result<()> {
    xplatform_memory::games::openttd::patch("openttd.exe");
    Ok(())
}

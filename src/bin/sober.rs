use std::io::Error;
#[cfg(target_os = "linux")]
use std::{fs, io, path::Path};

use xpmemtool::{
    core::{self},
    process::*,
};
fn main() -> io::Result<()> {
    core::Xpmentool::init();

    let sober = Process::new("Main")?;
    is_really_sober(sober)?;

    Ok(())
}

fn is_really_sober(sober: Process) -> io::Result<()> {
    let exe_path_string = format!("/proc/{}/exe", sober.pid);
    let exe_path = Path::new(&exe_path_string);
    if let Ok(exe) = fs::read_link(exe_path)
        && exe != Path::new("/app/bin/sober")
    {
        tracing::error!(
            exe_path_string,
            "sober-bin detected Main but exe not symlinked to correct path"
        );
        return Err(Error::new(
            io::ErrorKind::InvalidData,
            "Failed to detect Sober",
        ));
    }

    Ok(())
}

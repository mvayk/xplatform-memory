#[cfg(target_os = "linux")]
use std::{
    fs,
    io::{self, Error},
    path::Path,
};

use xpmemtool::{
    core::{self},
    process::*,
    types::Module,
};
fn main() -> io::Result<()> {
    core::Xpmentool::init();

    let sober = Process::new("Main")?;
    is_really_sober(&sober)?;

    let mut modules: Vec<Module> = Vec::new();
    for region in sober.inner.get_filtered_regions()? {
        let Ok(module) = sober.get_module(region.module_name.as_str()) else {
            continue;
        };

        if !modules.iter().any(|m| m.name == module.name) {
            modules.push(module);
        }
    }

    for module in modules {
        let name = module.name;
        println!("{name}");
        xpmemtool::log!(m = format_args!("{name}"));
    }

    Ok(())
}

fn is_really_sober(sober: &Process) -> io::Result<()> {
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

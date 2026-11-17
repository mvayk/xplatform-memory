use std::io;
use xpmemtool::{core::Xpmentool, log, process::*};

fn main() -> io::Result<()> {
    Xpmentool::init(true);

    let process_name = "cstrike_win64.exe";
    log!("test");

    Ok(())
}

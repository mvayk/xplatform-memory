#![allow(unused)]
#[cfg(not(target_os = "linux"))]
compile_error!("this binary only supports Linux");

use std::io;

use tracing::warn;

use xpmemtool::{
    core::{self, Xpmentool},
    formatter::Hex,
    linux::map::MapEntry,
    process::*,
    types::{Address, Module, ProtectionType},
};

fn main() -> io::Result<()> {
    Xpmentool::init(true);

    let process_name = "gmod.exe";
    let mut process = Process::new(process_name)?;

    process.inner.load("css_entry".to_string());

    Ok(())
}

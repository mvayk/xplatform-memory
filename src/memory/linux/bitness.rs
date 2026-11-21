use std::{
    fs,
    io::{self, Read},
};

use nix::unistd::Pid;

pub enum Bitness {
    x64,
    x32,
}

pub fn get_bitness(pida: i32) -> io::Result<Bitness> {
    let pid = Pid::from_raw(pida);
    let mut header = [0u8; 5];
    let mut file = fs::File::open(format!("/proc/{}/exe", pid.as_raw()))?;
    file.read_exact(&mut header)?;

    if &header[0..4] != b"\x7fELF" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "target executable is not a valid ELF file",
        ));
    }

    match header[4] {
        1 => {
            tracing::warn!(
                bitness = "x32",
                pid = pida,
                "xpmemtool was not designed to handle x32bit processes"
            );
            Ok(Bitness::x32)
        }
        2 => {
            tracing::info!(bitness = "x64", pid = pida);
            Ok(Bitness::x64)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unrecognized ELF class byte: {other}"),
        )),
    }
}

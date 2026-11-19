use std::{io, ops::Add};
use xpmemtool::{core::Xpmentool, formatter::Hex, log, process::*, types::Address};

use crate::Definitions::Sensitivity;

#[repr(u64)]
enum Definitions {
    /* client.dll */
    ConVar = 0x6775E8,
    /**/ Sensitivity = 0x54,
    C_PlayerInstance = 0x5C00D8,
    /**/ C_PositionX = 0x09C,
    /**/ C_PositionZ = 0x0A4,
    /**/ C_PositionY = 0x0A0,

    /* server.dll */
    Important = 0x7B54D0,
    S_PlayerInstance = 0x7B54D8,
    /**/ S_PositionX = 0x358,
    /**/ S_PositionZ = 0x35C,
    /**/ S_PositionY = 0x360,
}

impl Add<u64> for Definitions {
    type Output = u64;
    fn add(self, base: u64) -> u64 {
        self as u64 + base
    }
}

impl Add<Definitions> for u64 {
    type Output = u64;
    fn add(self, def: Definitions) -> u64 {
        self + def as u64
    }
}

fn main() -> io::Result<()> {
    Xpmentool::init(true);

    let process_name = "cstrike_win64.exe";
    let process = Process::new(process_name)?;
    log!("test");

    let client_base = process.get_module_base("client.dll")?;
    let server_base = process.get_module_base("server.dll")?;
    let engine_base = process.get_module_base("engine.dll")?;

    let convar = process.read_memory::<Address>(client_base + Definitions::ConVar)?;
    let sensitivity = process.read_memory::<f32>(convar + Definitions::Sensitivity)?;

    let player_instance: Address = server_base + Definitions::S_PlayerInstance;
    let z_pos = process.read_memory::<f32>(player_instance + Definitions::S_PositionZ)?;

    log!(z_pos, "Position Z:");
    log!(sensitivity, "sensitivity:");

    Ok(())
}

use std::io;
use std::ops::Add;
use xpmemtool::core::Xpmentool;
use xpmemtool::formatter::Hex;
use xpmemtool::log;
use xpmemtool::process::Process;

use crate::Definitions::{PersistentLevel, PhoneState};

/* base=0x7ff60f950000
 * gworld_rva = 0x7FF0AD2FD000
 * FFFF FFFA 9D9A D000
 */
#[repr(u64)]
#[derive(Clone, Copy)]
enum Definitions {
    // Pointers
    GameEngine = 0xB6D0C88,
    L_Dev = 0xB6CDF70,

    // Offsets
    PersistentLevel = 0x30,
    Cash = 0x208,
    Xp = 0x210,

    // TODO: find PhoneActor offset from PersistentLevel
    PhoneActor = 0x0,
    PhoneState = 0x3C0,
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

    let process_name = "CarFlipping-Win64-Shipping.exe";
    let process = Process::new(process_name)?;
    let module_base = process.get_module_base(process_name)?;

    let gworld = process.read_memory(module_base + Definitions::L_Dev)?;
    log!(ldev = %Hex(gworld), "L_Dev:");

    let persistentl = process.read_memory(gworld + Definitions::PersistentLevel)?;
    log!(Persistent_Level = %Hex(persistentl), "L_Dev:");

    /* wrong */
    let phone_actor = process.read_memory(persistentl + Definitions::PhoneActor)?;
    log!(PhoneActor = %Hex(phone_actor), "PhoneActor:");

    let phone_state = process.read_memory(phone_actor + Definitions::PhoneState)?;
    log!(PhoneState = %Hex(phone_state), "PhoneState:");

    let cash = phone_state + Definitions::Cash;
    let cash_value = process.read_memory::<u64>(phone_state + Definitions::Cash)?;
    log!(
        cash_value = format_args!("{}", cash_value as i32),
        "cash value:"
    );
    let _ = process.write_memory(cash, i32::MAX / 2)?;
    let cash_value = process.read_memory::<u64>(phone_state + Definitions::Cash)?;
    log!(
        cash_value = format_args!("{}", cash_value as i32),
        "new cash value:"
    );

    let xp = phone_state + Definitions::Xp;
    let xp_value = process.read_memory::<u64>(phone_state + Definitions::Xp)?;
    log!(xp_value = format_args!("{}", xp_value as i32), "xp value:");

    let _ = process.write_memory(xp, i32::MAX)?;

    Ok(())
}

use std::io;

mod memory;
use crate::memory::*;
use crate::wrapper::*;

mod games;

fn main() -> io::Result<()> {
    let tfoc: (&str, bool) = ("TFOC.exe", false);
    let twfc: (&str, bool) = ("TWFC_steamless.exe", true);

    if tfoc.1 == true {
        games::tfoc::patch(tfoc.0);
    } else if twfc.1 == true {
        games::twfc::patch(twfc.0);
    } else {
        panic!("I DONT KNOW");
    }

    Ok(())
}

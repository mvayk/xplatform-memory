use rand;
use rand::Rng;
use std::time::Duration;
use std::{io, ops::Add};
use std::{thread, time};
use xpmemtool::linux::page::Page;
use xpmemtool::linux::wine_map::attribute_wine_modules;
use xpmemtool::{core::Xpmentool, formatter::Hex, log, process::*, types::Address};

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
    let mut process = Process::new(process_name)?;
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

    /* fun! */
    let target = process.get_module("client.dll")?;
    log!(target_start_addy = %Hex(target.addresses.start));
    log!(target_end_addy = %Hex(target.addresses.end));

    let size = target.addresses.end - target.addresses.start;
    let start = target.addresses.start;
    log!(target_size = %Hex(size));
    log!(target_start = %Hex(start));

    let mut writable_addresses: Vec<Address> = Vec::new();
    let regions = target.inner.get_regions()?;
    let mut all_pages: Vec<Page> = Vec::new();
    for r in &regions {
        let lpages = r.get_pages()?;
        for lp in lpages {
            all_pages.push(lp);
        }
    }

    log!(page_count = all_pages.len());
    log!(region_count = regions.len());

    for region in regions {
        log!(region_flag = region.protection_flag.to_string());
        let pages = region.get_pages()?;
        for p in &pages {
            if p.is_writable() {
                writable_addresses.extend(p.addresses);
            }
        }
    }

    // writable_addresses
    //     .iter()
    //     .for_each(|a| log!(address = %Hex(*a)));

    log!(addresses_amount = writable_addresses.len());

    process.inner.load("css_entry".to_string())?;

    let run = false;
    if !run {
        return Ok(());
    }

    for _ in 1..=u64::MAX {
        std::thread::sleep(Duration::from_millis(500));

        let ran_index = rand::random_range(0..writable_addresses.len());
        let previous = process.read_memory::<u8>(writable_addresses[ran_index])?;
        // if previous == 0x0 {
        //     continue;
        // }

        process.write_memory::<u8>(writable_addresses[ran_index], previous >> 1)?;

        //rand::random_range(0..u64::MAX),
    }

    // for a in writable_addresses {
    //     println!("{}", a);
    // }

    // for mut i in 1..50 {
    //     let random_addy: Address =
    //         rand::random_range(server_dll.address.start..server_dll.address.end);
    //     let protection = match process.query_address_protection(random_addy) {
    //         Ok(p) => p,
    //         Err(_) => continue,
    //     };
    //
    //     log!(p = protection.to_string());
    //     if !protection.is_writable() {
    //         continue;
    //     }
    //
    //     log!(randaddy = %Hex(random_addy));
    //
    //     let _ = match process.write_memory::<u64>(random_addy, rand::random()) {
    //         _ => continue,
    //     };
    // }

    Ok(())
}

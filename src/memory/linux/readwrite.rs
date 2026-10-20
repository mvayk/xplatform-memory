use crate::linux::platform::ProcessPlatform;
use crate::types::Address;
use std::os::unix::fs::FileExt;
use std::{fs, io};

pub struct MemData {
    pub word: [u8; 8],
}

fn process_addresses(process: &ProcessPlatform, addresses: &[Address]) -> io::Result<Vec<Address>> {
    let mut readable = Vec::with_capacity(addresses.len());

    for &address in addresses {
        let page = process.get_page_from_address(address)?;
        if page.is_readable() {
            readable.push(address);
        } else {
            tracing::warn!(
                page = %page,
                address,
                "unable to read or write due to permissions, skipping address"
            );
        }
    }

    Ok(readable)
}

impl ProcessPlatform {
    pub fn read_memory(&self, addresses: &[Address]) -> io::Result<Vec<MemData>> {
        let addresses: Vec<Address> = process_addresses(self, addresses)?;
        let mem_file = fs::File::open(format!("/proc/{}/mem", self.pid))?;

        let mut data: Vec<MemData> = Vec::with_capacity(addresses.len());

        for address in addresses {
            let mut word = [0u8; 8];
            if mem_file.read_exact_at(&mut word, address).is_err() {
                tracing::warn!("read_memory skipping due to something lol");
                continue;
            }
            data.push(MemData { word });
        }

        Ok(data)
    }
}

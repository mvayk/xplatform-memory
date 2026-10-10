use crate::memory::definitions::ProtectionType;
use std::io;

pub struct Page {
    pub size: u64,
    pub protection_flag: ProtectionType,
    pub start_address: u64,
    pub end_address: u64,
}

impl Page {
    pub fn new(start_address: u64, protection_flag: ProtectionType) -> io::Result<Self> {
        let size = Page::get_page_size()?;
        let end_address = start_address + Page::get_page_size()?;

        Ok(Page {
            size,
            protection_flag,
            start_address,
            end_address,
        })
    }

    pub fn get_page_size() -> io::Result<u64> {
        Ok(unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64)
    }

    pub fn get_page_range(&self) -> io::Result<String> {
        Ok(format!("{:x}-{:x}", self.start_address, self.end_address))
    }

    pub fn get_addresses(&self) -> io::Result<Vec<u64>> {
        let mut addresses: Vec<u64> = Vec::new();
        for addy in self.start_address..self.end_address {
            addresses.push(addy);
        }

        Ok(addresses)
    }
}

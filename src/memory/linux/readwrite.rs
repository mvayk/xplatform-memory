use libc::seccomp_data;

use crate::linux::platform::ProcessPlatform;
use crate::types::Address;
use std::io::Error;
use std::os::unix::fs::FileExt;
use std::{fmt, fs, io, mem};

pub struct MemData {
    pub address: Address,
    pub word: [u8; 8],
}

impl fmt::Display for MemData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "word {:?} at address {:#x}", (self.word), (self.address))
    }
}

impl MemData {
    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.word)
    }
}

fn to_byte_slice<T: Copy>(data: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(data as *const T as *const u8, mem::size_of::<T>()) }
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

/* backends
    process_vm
    memfile
    ptrace
*/

impl ProcessPlatform {
    pub fn read_memory(&self, addy: Address) -> io::Result<u64> {
        let addresses: Vec<Address> = process_addresses(self, &[addy])?;
        let mem_file = fs::File::open(format!("/proc/{}/mem", self.pid))?;

        let address = addresses[0];

        let mut word = [0u8; 8];
        match mem_file.read_exact_at(&mut word, address) {
            Ok(_) => {
                tracing::info!(
                    read = format_args!("{word:#x?}"),
                    addr = format_args!("{address:?}"),
                    "read_memory successful:"
                );
            }
            Err(e) => {
                tracing::error!(addr = format_args!("{address:?}"), error = %e, "read_memory encountered an error on addr:");
                return Err(Error::new(
                    io::ErrorKind::Interrupted,
                    "read_memory failed to read",
                ));
            }
        }

        Ok(u64::from_le_bytes(word))
    }

    pub fn write_memory<T: Copy>(&self, addy: Address, data: &T) -> io::Result<()> {
        let addresses: Vec<Address> = process_addresses(self, &[addy])?;
        let mem_file = fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.pid))?;

        let address = addresses[0];
        let data = to_byte_slice(data);

        match mem_file.write_all_at(&data, address) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(addr = format_args!("{address:?}"), error = %e, "write_memory encountered an error on addr:");
                return Err(Error::new(
                    io::ErrorKind::Interrupted,
                    "write_memory failed to write",
                ));
            }
        }

        Ok(())
    }

    pub fn write_memory_long(&self, addresses: &[Address], data: &[u8]) -> io::Result<()> {
        let addresses: Vec<Address> = process_addresses(self, addresses)?;
        let mem_file = fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.pid))?;

        for address in addresses {
            mem_file.write_all_at(&data, address).inspect_err(|e| tracing::warn!(addr = format_args!("{address:?}"), error = %e, "write_memory_long encountered an error on addr:"))?;
        }

        Ok(())
    }

    pub fn read_memory_long(&self, addresses: &[Address]) -> io::Result<Vec<MemData>> {
        let addresses: Vec<Address> = process_addresses(self, addresses)?;
        let mem_file = fs::File::open(format!("/proc/{}/mem", self.pid))?;

        let mut data: Vec<MemData> = Vec::with_capacity(addresses.len());

        for (_, &address) in addresses.iter().enumerate() {
            let mut word = [0u8; 8];
            let result = mem_file.read_exact_at(&mut word, address);
            match result {
                Ok(_) => {
                    tracing::info!(
                        address,
                        read = format_args!("{word:#x?}"),
                        "read_memory_long successful for address:",
                    );
                    data.push(MemData { address, word });
                }
                Err(e) => {
                    tracing::warn!(addr = format_args!("{address:?}"), error = %e, "read_memory_long encountered an error on addr:");
                }
            }
        }
        Ok(data)
    }
}

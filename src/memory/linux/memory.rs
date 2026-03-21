use std::io;

#[cfg(target_os = "linux")]
pub mod platform {
    use libc::{iovec, process_vm_readv, process_vm_writev};
    use std::fs;
    use std::io;
    use std::mem;

    pub fn find_pid(name: &str) -> io::Result<i32> {
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();
            if let Ok(pid) = filename.parse::<i32>() {
                let comm_path = format!("/proc/{}/comm", pid);
                if let Ok(proc_name) = fs::read_to_string(comm_path) {
                    if proc_name.trim() == name {
                        return Ok(pid);
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find process",
        ))
    }

    pub struct PlatformProcess {
        pub pid: i32,
    }

    impl PlatformProcess {
        pub fn new(pid: i32) -> io::Result<Self> {
            Ok(PlatformProcess { pid })
        }

        pub fn get_module_base(&self, module: &str) -> io::Result<usize> {
            let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
            for line in maps.lines() {
                if line.contains(module) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    let addresses: Vec<&str> = parts[0].split('-').collect();
                    let base = usize::from_str_radix(addresses[0], 16).unwrap();
                    return Ok(base);
                }
            }
            Err(io::Error::new(io::ErrorKind::NotFound, "module not found"))
        }

        pub fn get_module_size(&self, module: &str) -> io::Result<usize> {
            let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
            let base = self.get_module_base(module)?;
            let mut end = base;

            let mut found_base = false;
            for line in maps.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 5 {
                    continue;
                }
                let addrs: Vec<&str> = parts[0].split('-').collect();
                if addrs.len() < 2 {
                    continue;
                }
                let start = usize::from_str_radix(addrs[0], 16).unwrap_or(0);
                let hi = usize::from_str_radix(addrs[1], 16).unwrap_or(0);
                let perms = parts[1];
                let is_named = parts.len() >= 6;

                if start == base {
                    found_base = true;
                    end = hi;
                    continue;
                }

                if found_base {
                    if start == end && perms.starts_with("r-xp") && !is_named {
                        end = hi;
                    } else {
                        break;
                    }
                }
            }

            Ok(end - base)
        }

        pub fn read_memory<T: Copy>(&self, address: usize) -> io::Result<T> {
            let mut buffer: T = unsafe { mem::zeroed() };
            let local_iov = iovec {
                iov_base: &mut buffer as *mut _ as *mut _,
                iov_len: mem::size_of::<T>(),
            };
            let remote_iov = iovec {
                iov_base: address as *mut _,
                iov_len: mem::size_of::<T>(),
            };
            let result = unsafe { process_vm_readv(self.pid, &local_iov, 1, &remote_iov, 1, 0) };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(buffer)
        }

        pub fn read_memory_range(
            &self,
            address_start: usize,
            scan_size: usize,
        ) -> io::Result<Vec<u8>> {
            use std::os::unix::fs::FileExt;
            let path = format!("/proc/{}/mem", self.pid);
            let file = std::fs::File::open(path)?;
            let mut buf = vec![0u8; scan_size];
            file.read_at(&mut buf, address_start as u64)?;
            Ok(buf)
        }

        pub fn write_memory<T: Copy>(&self, address: usize, value: &T) -> io::Result<()> {
            let local_iov = iovec {
                iov_base: value as *const _ as *mut _,
                iov_len: mem::size_of::<T>(),
            };
            let remote_iov = iovec {
                iov_base: address as *mut _,
                iov_len: mem::size_of::<T>(),
            };
            let result = unsafe { process_vm_writev(self.pid, &local_iov, 1, &remote_iov, 1, 0) };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /* TODO: add allocate memory, signature scanning, protect memory */
    }
}

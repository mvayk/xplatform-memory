#[cfg(target_os = "linux")]

pub mod platform {
    use crate::memory::utils::{ProtectionType, ctx};
    use libc::{
        PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE, iovec, process_vm_readv, process_vm_writev,
        user_regs_struct,
    };

    use nix::sys::ptrace;
    use nix::sys::signal::Signal::SIGTRAP;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::Pid;
    use std::fs;
    use std::io;
    use std::mem;
    use std::process::Command;

    /* old comm method truncates actual name of process at 15 characters for some reason
    resulting in unable to find process if the process name is longer than 15 */
    pub fn find_pid(name: &str) -> io::Result<i32> {
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let filename = entry.file_name();
            let filename = filename.to_string_lossy();
            if let Ok(pid) = filename.parse::<i32>() {
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                if let Ok(cmdline) = fs::read_to_string(cmdline_path) {
                    if let Some(exe_path) = cmdline.split('\0').next() {
                        let exe_name = exe_path
                            .rsplit(|c| c == '/' || c == '\\')
                            .next()
                            .unwrap_or(exe_path);

                        if exe_name.eq_ignore_ascii_case(name) {
                            return Ok(pid);
                        }
                    }
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Failed to find process",
        ))
    }

    pub struct ProcessPlatform {
        pub pid: i32,
    }

    impl ProcessPlatform {
        pub fn new(pid: i32) -> io::Result<Self> {
            Ok(ProcessPlatform { pid })
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
            let data = unsafe {
                std::slice::from_raw_parts(value as *const T as *const u8, mem::size_of::<T>())
            };

            let local_iov = iovec {
                iov_base: data.as_ptr() as *mut _,
                iov_len: data.len(),
            };
            let remote_iov = iovec {
                iov_base: address as *mut _,
                iov_len: data.len(),
            };

            let result = unsafe { process_vm_writev(self.pid, &local_iov, 1, &remote_iov, 1, 0) };

            if result == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(14) {
                    return self.write_memory_ptrace(address, data);
                }
                return Err(err);
            }

            Ok(())
        }

        fn write_memory_ptrace(&self, address: usize, data: &[u8]) -> io::Result<()> {
            let pid = Pid::from_raw(self.pid);
            let mut offset = 0;

            ptrace::attach(pid).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
            waitpid(pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            while offset < data.len() {
                let addr = (address + offset) as *mut libc::c_void;
                let remaining = std::cmp::min(8, data.len() - offset);

                let mut word: i64 = if remaining < 8 {
                    ptrace::read(pid, addr).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
                } else {
                    0
                };

                let word_bytes = word.to_ne_bytes();
                let mut new_word = word_bytes;
                new_word[..remaining].copy_from_slice(&data[offset..offset + remaining]);
                word = i64::from_ne_bytes(new_word);

                ptrace::write(pid, addr, word)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                offset += remaining;
            }

            ptrace::detach(pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            Ok(())
        }

        /* missing many checks n stuff so its very low quality */
        pub fn protect_memory(
            &self,
            address: u64,
            length: u64,
            protection: ProtectionType,
        ) -> io::Result<()> {
            let prot: i32 = match protection {
                ProtectionType::PAGE_EXECUTE => PROT_EXEC,
                ProtectionType::PAGE_EXECUTE_READ => PROT_READ | PROT_EXEC,
                ProtectionType::PAGE_EXECUTE_READWRITE => PROT_READ | PROT_EXEC | PROT_WRITE,
                ProtectionType::PAGE_NOACCESS => PROT_NONE,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Failed to match protection",
                    ));
                }
            };

            let pid = Pid::from_raw(self.pid);

            ptrace::attach(pid).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
            waitpid(pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let original_registers: user_regs_struct =
                ctx("getregs (start)", ptrace::getregs(pid))?;
            let rip = original_registers.rip;

            let original_word = ctx("original_word: ", ptrace::read(pid, rip as *mut _))?;
            let mut patched = (original_word as usize).to_le_bytes();
            patched[0] = 0x0f;
            patched[1] = 0x05; /* syscall */
            patched[2] = 0xcc; /* int3    */

            let patched_word = i64::from_le_bytes(patched);

            /* write patch */
            ptrace::write(pid, rip as *mut _, patched_word)?;

            /* setup the registers to call mprotect internally */
            let mut registers = original_registers;
            registers.rax = libc::SYS_mprotect as u64;
            registers.rdi = address;
            registers.rsi = length;
            registers.rdx = prot as u64;
            registers.rip = rip;

            ptrace::setregs(pid, registers)?;

            /* continue */
            ptrace::cont(pid, None)?;

            match waitpid(pid, None)? {
                WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGTRAP) => {}
                _ => return Err(io::Error::last_os_error()), // idk
            }

            let after = ptrace::getregs(pid)?;
            let ret = after.rax as i64;

            /* restore */
            ptrace::write(pid, rip as *mut _, original_word)?;
            ptrace::setregs(pid, original_registers)?;

            /* debug  temp */
            println!(
                "[!] memory protection results: after: {:?}, ret: {}",
                after, ret
            );

            ptrace::detach(pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            Ok(())
        }

        /**/
        pub fn get_readable_regions(&self) -> io::Result<Vec<(usize, usize)>> {
            let maps = fs::read_to_string(format!("/proc/{}/maps", self.pid))?;
            let mut regions = Vec::new();

            for line in maps.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 || !parts[1].starts_with('r') {
                    continue;
                }
                // [vvar]/[vsyscall]
                if parts.len() >= 6 && (parts[5] == "[vvar]" || parts[5] == "[vsyscall]") {
                    continue;
                }
                if let Some((s, e)) = parts[0].split_once('-') {
                    if let (Ok(s), Ok(e)) =
                        (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16))
                    {
                        regions.push((s, e));
                    }
                }
            }
            Ok(regions)
        }

        pub fn get_all_addresses(&self) -> io::Result<Vec<usize>> {
            let mut addrs = Vec::new();
            for (s, e) in self.get_readable_regions()? {
                addrs.extend(s..e);
            }
            Ok(addrs)
        }

        pub fn dump_memory(&self) -> io::Result<(Vec<usize>, Vec<u8>)> {
            use std::os::unix::fs::FileExt;

            let file = fs::File::open(format!("/proc/{}/mem", self.pid))?;
            let mut addrs = Vec::new();
            let mut bytes = Vec::new();

            for (start, end) in self.get_readable_regions()? {
                let mut buf = vec![0u8; end - start];
                let n = match file.read_at(&mut buf, start as u64) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                buf.truncate(n);
                addrs.extend(start..start + n);
                bytes.extend_from_slice(&buf);
            }
            Ok((addrs, bytes))
        }
        /**/

        /* x11 only */
        pub fn get_aspect_ratio(&self, window_title: &str) -> io::Result<f32> {
            let output = Command::new("xdotool")
                .args([
                    "search",
                    "--name",
                    window_title,
                    "getwindowgeometry",
                    "--shell",
                    "%1",
                ])
                .output();

            if let Ok(out) = output {
                let text = String::from_utf8_lossy(&out.stdout);
                let mut w: Option<f32> = None;
                let mut h: Option<f32> = None;

                for line in text.lines() {
                    if let Some(val) = line.strip_prefix("WIDTH=") {
                        w = val.trim().parse().ok();
                    } else if let Some(val) = line.strip_prefix("HEIGHT=") {
                        h = val.trim().parse().ok();
                    }
                }

                if let (Some(w), Some(h)) = (w, h) {
                    if h > 0.0 {
                        return Ok(w / h);
                    }
                }
            }

            /* fallback */
            Ok(16.0 / 9.0)
        }
    }
}

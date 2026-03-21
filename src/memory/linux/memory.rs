#[cfg(target_os = "linux")]

pub mod platform {
    use libc::{
        MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, iovec, mmap, munmap,
        process_vm_readv, process_vm_writev, user_regs_struct,
    };
    use nix::sys::ptrace;
    use nix::sys::wait::waitpid;
    use nix::unistd::Pid;
    use std::fs;
    use std::io;
    use std::mem;
    use std::process::Command;

    /* need this for allocate_memory when saving & modifying registers */
    fn get_process_bitness(pid: i32) -> io::Result<usize> {
        let exe_path = format!("/proc/{}/exe", pid);
        let mut file = fs::File::open(&exe_path)?;

        let mut elf_header = [0u8; 5];
        std::io::Read::read_exact(&mut file, &mut elf_header)?;

        if &elf_header[0..4] != b"\x7fELF" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Not an elf"));
        }

        match elf_header[4] {
            1 => Ok(32),
            2 => Ok(64),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown elf")),
        }
    }

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

        /* TODO: signature scanning, protect memory, */
        pub fn allocate_memory(&self, size: usize) -> io::Result<usize> {
            let bitpenis = get_process_bitness(self.pid)?;

            let target_pid = Pid::from_raw(self.pid);

            ptrace::attach(target_pid)
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;

            waitpid(target_pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            /* much better way to have down this :\ */
            let allocated_addr = if bitpenis == 32 {
                self.allocate_32bit(target_pid, size)?
            } else {
                self.allocate_64bit(target_pid, size)?
            };

            ptrace::detach(target_pid, None)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            Ok(allocated_addr)
        }

        fn allocate_64bit(&self, target_pid: Pid, size: usize) -> io::Result<usize> {
            let regs =
                ptrace::getregs(target_pid).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let original_regs = regs;

            let mut new_regs = regs;
            new_regs.rax = 9;
            new_regs.rdi = 0;
            new_regs.rsi = size as u64;
            new_regs.rdx = (PROT_READ | PROT_WRITE) as u64;
            new_regs.r10 = (MAP_PRIVATE | MAP_ANONYMOUS) as u64;
            new_regs.r8 = (-1i64) as u64;
            new_regs.r9 = 0;

            ptrace::setregs(target_pid, new_regs)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let original_instruction = ptrace::read(target_pid, regs.rip as ptrace::AddressType)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            unsafe {
                ptrace::write(target_pid, regs.rip as ptrace::AddressType, 0x050f)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }

            ptrace::step(target_pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            waitpid(target_pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let result_regs =
                ptrace::getregs(target_pid).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let allocated_addr = result_regs.rax as usize;

            unsafe {
                ptrace::write(
                    target_pid,
                    regs.rip as ptrace::AddressType,
                    original_instruction,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }

            ptrace::setregs(target_pid, original_regs)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if allocated_addr as i64 == -1 || allocated_addr as i64 > -4096 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "mmap failed in target process",
                ));
            }

            Ok(allocated_addr)
        }

        fn allocate_32bit(&self, target_pid: Pid, size: usize) -> io::Result<usize> {
            let regs =
                ptrace::getregs(target_pid).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let original_regs = regs;

            let mut new_regs = regs;
            new_regs.rax = 192;
            new_regs.rbx = 0;
            new_regs.rcx = size as u64;
            new_regs.rdx = (PROT_READ | PROT_WRITE) as u64;
            new_regs.rsi = (MAP_PRIVATE | MAP_ANONYMOUS) as u64;
            new_regs.rdi = (-1i64) as u64;
            new_regs.rbp = 0;

            ptrace::setregs(target_pid, new_regs)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let original_instruction = ptrace::read(target_pid, regs.rip as ptrace::AddressType)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            unsafe {
                ptrace::write(target_pid, regs.rip as ptrace::AddressType, 0x80cd)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }

            ptrace::step(target_pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            waitpid(target_pid, None).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let result_regs =
                ptrace::getregs(target_pid).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let allocated_addr = result_regs.rax as usize;

            unsafe {
                ptrace::write(
                    target_pid,
                    regs.rip as ptrace::AddressType,
                    original_instruction,
                )
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            }

            ptrace::setregs(target_pid, original_regs)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if allocated_addr as i32 == -1 || (allocated_addr as i32) > -4096 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "mmap failed in target process",
                ));
            }

            Ok(allocated_addr)
        }
    }
}

use crate::memory::linux::platform::ProcessPlatform;
use crate::memory::linux::trace::PtraceGuard;
use libc::{c_long, c_void, iovec, process_vm_readv, process_vm_writev};
use nix::{sys::ptrace, unistd::Pid};
use std::os::unix::fs::FileExt;
use std::{fs, io, mem, slice};

impl ProcessPlatform {
    pub fn read_memory<T: Copy>(&self, address: usize) -> io::Result<T> {
        let size = mem::size_of::<T>();
        let mut buffer = mem::MaybeUninit::<T>::uninit();

        let local_iov = iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: size,
        };
        let remote_iov = iovec {
            iov_base: address as *mut _,
            iov_len: size,
        };

        let n = unsafe { process_vm_readv(self.pid, &local_iov, 1, &remote_iov, 1, 0) };

        if n < 0 {
            tracing::debug!(n = n, "read_memory");
            let err = io::Error::last_os_error();
            tracing::error!(pid = self.pid, addr = format_args!("{address:#x}"), size, error = %err, "read_memory failed");
            tracing::warn!("attempting to read memory through read_memory_procmem");
            let mut result = self.read_memory_procmem(address);
            match result {
                Ok(_) => {
                    tracing::debug!("read_memory_procmem returned success to read_memory");
                    buffer = result?;
                    return Ok(unsafe { buffer.assume_init() });
                }
                Err(e) => {
                    tracing::debug!(error = %e, "read_memory_procmem returned failure");
                    //return Err(e);
                }
            }

            tracing::warn!("attempting to read memory through read_memory_ptrace");
            result = self.read_memory_ptrace(address);
            match result {
                Ok(_) => {
                    tracing::debug!("read_memory_ptrace returned success to read_memory");
                    buffer = result?;
                    return Ok(unsafe { buffer.assume_init() });
                }
                Err(e) => {
                    tracing::error!(error = %e, "read_memory_ptrace returned failure");
                    return Err(e);
                }
            }
        }

        if n as usize != size {
            tracing::error!(
                pid = self.pid,
                addr = format_args!("{address:#x}"),
                got = n,
                expected = size,
                "short read"
            );
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("short read at {address:#x}: got {n} of {size} bytes"),
            ));
        }

        tracing::info!(
            pid = self.pid,
            addr = format_args!("{address:#x}"),
            size,
            "read_memory successful"
        );

        Ok(unsafe { buffer.assume_init() })
    }

    pub fn read_memory_procmem<T: Copy>(&self, address: usize) -> io::Result<T> {
        let f = fs::OpenOptions::new()
            .read(true)
            .open(format!("/proc/{}/mem", self.pid))
            .map_err(|e| {
                tracing::error!(error = %e, "read_memory_procmem failed to open /mem");
                e
            })?;

        let mut buf = vec![0u8; mem::size_of::<T>()];
        let result = f.read_exact_at(&mut buf, address as u64);

        match &result {
            Ok(()) => tracing::info!(
                pid = self.pid,
                addr = format_args!("{address:#x}"),
                len = buf.len(),
                "read_memory_procmem successful"
            ),
            Err(e) => tracing::warn!(
                pid = self.pid,
                addr = format_args!("{address:#x}"),
                error = %e,
                "read_memory_procmem failed"
            ),
        }

        result?;
        Ok(unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) })
    }

    pub fn read_memory_ptrace<T: Copy>(&self, address: usize) -> io::Result<T> {
        let pid = Pid::from_raw(self.pid);
        let _guard = PtraceGuard::attach(pid)?;

        let len = mem::size_of::<T>();
        let end = address.checked_add(len).ok_or_else(|| {
            tracing::error!(
                address = address,
                "read_memory_ptrace failed due to an address overflow"
            );
            io::Error::new(io::ErrorKind::InvalidInput, "address overflow")
        })?;

        let mut buf = vec![0u8; len];

        let mut offset = 0;
        while len - offset >= 8 {
            let word = ptrace::read(pid, (address + offset) as *mut c_void);
            match word {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(
                        address = address,
                        offset = offset,
                        error = %e,
                        "read_memory_ptrace failed to read word"
                    );

                    return Err(io::Error::from(e));
                }
            }
            buf[offset..offset + 8].copy_from_slice(&word?.to_ne_bytes());
            offset += 8;
        }

        let rem = len - offset;
        if rem > 0 {
            let tail_addr = address + offset;

            let forward = ptrace::read(pid, tail_addr as *mut c_void)
                .map(|w| w.to_ne_bytes())
                .map_err(io::Error::from);

            match forward {
                Ok(bytes) => buf[offset..].copy_from_slice(&bytes[..rem]),
                Err(e) if len >= 8 => {
                    tracing::warn!(
                        error = %e,
                        "write_memory_ptrace tail read at tail_addr failed, trying end-8"
                    );
                    let word =
                        ptrace::read(pid, (end - 8) as *mut c_void).map_err(io::Error::from)?;
                    let bytes = word.to_ne_bytes();
                    buf[offset..].copy_from_slice(&bytes[8 - rem..]);
                }
                Err(e) => return Err(e),
            }
        }

        let content = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const T) };

        tracing::info!(
            pid = self.pid,
            addr = format_args!("{address:#x}"),
            len,
            "read_memory_ptrace successful"
        );

        Ok(content)
    }

    /* refactor */
    pub fn write_memory<T: Copy>(&self, address: usize, value: &T) -> io::Result<()> {
        let data =
            unsafe { slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>()) };
        self.write_bytes(address, data)
    }

    pub fn write_bytes(&self, address: usize, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let local_iov = iovec {
            iov_base: data.as_ptr() as *mut c_void,
            iov_len: data.len(),
        };
        let remote_iov = iovec {
            iov_base: address as *mut c_void,
            iov_len: data.len(),
        };

        let n = unsafe { process_vm_writev(self.pid, &local_iov, 1, &remote_iov, 1, 0) };

        if n >= 0 && n as usize == data.len() {
            tracing::info!(
                pid = self.pid,
                addr = format_args!("{address:#x}"),
                len = data.len(),
                "write_bytes ok (process_vm_writev)"
            );
            return Ok(());
        }

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EFAULT) {
                tracing::error!(pid = self.pid, addr = format_args!("{address:#x}"), error = %err, "write_bytes failed (non-EFAULT)");
                return Err(err);
            }
            tracing::warn!(
                pid = self.pid,
                addr = format_args!("{address:#x}"),
                "process_vm_writev got EFAULT, falling back"
            );
        }

        self.write_memory_procmem(address, data).or_else(|e| {
            tracing::warn!(pid = self.pid, addr = format_args!("{address:#x}"), error = %e, "procmem write failed, falling back to ptrace");
            self.write_memory_ptrace(address, data)
        })
    }

    fn write_memory_procmem(&self, address: usize, data: &[u8]) -> io::Result<()> {
        let f = fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.pid))?;
        let result = f.write_all_at(data, address as u64);
        match &result {
            Ok(()) => tracing::info!(
                pid = self.pid,
                addr = format_args!("{address:#x}"),
                len = data.len(),
                "write_memory_procmem successful"
            ),
            Err(e) => {
                tracing::warn!(pid = self.pid, addr = format_args!("{address:#x}"), error = %e, "write_memory_procmem failed")
            }
        }
        result
    }

    fn write_memory_ptrace(&self, address: usize, data: &[u8]) -> io::Result<()> {
        let pid = Pid::from_raw(self.pid);
        let _guard = PtraceGuard::attach(pid)?;
        // tracing::info!(
        //     pid = self.pid,
        //     addr = format_args!("{address:#x}"),
        //     len = data.len(),
        //     "write_memory_ptrace attached"
        // );

        let end = address
            .checked_add(data.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address overflow"))?;

        let mut offset = 0;
        while data.len() - offset >= 8 {
            let word = c_long::from_ne_bytes(data[offset..offset + 8].try_into().unwrap());
            ptrace::write(pid, (address + offset) as *mut c_void, word).map_err(io::Error::from)?;
            offset += 8;
        }

        let rem = data.len() - offset;
        if rem > 0 {
            let tail = &data[offset..];
            let tail_addr = address + offset;

            let write_window = |start: usize| -> io::Result<()> {
                let ptr = start as *mut c_void;
                let word = ptrace::read(pid, ptr).map_err(io::Error::from)?;
                let mut bytes = word.to_ne_bytes();
                let skip = tail_addr - start;
                bytes[skip..skip + rem].copy_from_slice(tail);
                ptrace::write(pid, ptr, c_long::from_ne_bytes(bytes)).map_err(io::Error::from)
            };

            write_window(tail_addr).or_else(|e| {
                tracing::warn!(pid = self.pid, error = %e, "tail write_window at tail_addr failed, trying end-8");
                write_window(end - 8)
            })?;
        }

        // tracing::info!(
        //     pid = self.pid,
        //     addr = format_args!("{address:#x}"),
        //     len = data.len(),
        //     "write_bytes"
        // );
        Ok(())
    }
}

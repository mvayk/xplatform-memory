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
            return Err(io::Error::last_os_error());
        }
        if n as usize != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("short read at {address:#x}: got {n} of {size} bytes"),
            ));
        }

        Ok(unsafe { buffer.assume_init() })
    }

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
            return Ok(());
        }

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EFAULT) {
                return Err(err);
            }
        }

        self.write_memory_procmem(address, data)
            .or_else(|_| self.write_memory_ptrace(address, data))
    }

    fn write_memory_procmem(&self, address: usize, data: &[u8]) -> io::Result<()> {
        let f = fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.pid))?;
        f.write_all_at(data, address as u64)
    }

    fn write_memory_ptrace(&self, address: usize, data: &[u8]) -> io::Result<()> {
        let pid = Pid::from_raw(self.pid);
        let _guard = PtraceGuard::attach(pid)?;

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

            write_window(tail_addr).or_else(|_| write_window(end - 8))?;
        }

        Ok(())
    }
}

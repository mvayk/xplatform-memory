/* claude babe vibe */
/* TODO: make this not disgusting */
use crate::formatter::Hex;
use crate::linux::platform::ProcessPlatform;
use crate::linux::trace::PtraceGuard;
use crate::types::{Address, Pod};
use libc::{c_long, c_void, iovec, process_vm_readv, process_vm_writev};
use nix::{sys::ptrace, unistd::Pid};
use std::os::unix::fs::FileExt;
use std::{fs, io, mem, slice};

fn check_range(addr: Address, len: usize) -> io::Result<Address> {
    addr.checked_add(len as Address)
        .filter(|e| usize::try_from(*e).is_ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "address overflow"))
}

#[inline]
fn ptr(addr: Address) -> *mut c_void {
    addr as usize as *mut c_void
}

#[inline]
fn is_fatal(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ESRCH)
}

fn with_tail_window(
    tail_addr: Address,
    end: Address,
    mut f: impl FnMut(Address) -> io::Result<()>,
) -> io::Result<()> {
    match f(tail_addr) {
        Ok(()) => Ok(()),
        Err(e) => match end.checked_sub(8) {
            Some(start) if start != tail_addr => {
                tracing::debug!(error = %e, "tail window failed, retrying at end-8");
                f(start)
            }
            _ => Err(e),
        },
    }
}

fn peek(pid: Pid, addr: Address) -> io::Result<[u8; 8]> {
    ptrace::read(pid, ptr(addr))
        .map(|w| w.to_ne_bytes())
        .map_err(io::Error::from)
}

fn poke(pid: Pid, addr: Address, bytes: [u8; 8]) -> io::Result<()> {
    ptrace::write(pid, ptr(addr), c_long::from_ne_bytes(bytes)).map_err(io::Error::from)
}

type ReadBackend = fn(&ProcessPlatform, Address, &mut [u8]) -> io::Result<()>;
type WriteBackend = fn(&ProcessPlatform, Address, &[u8]) -> io::Result<()>;

const READ_BACKENDS: &[(&str, ReadBackend)] = &[
    ("process_vm_readv", ProcessPlatform::read_vm),
    ("/proc/pid/mem", ProcessPlatform::read_procmem),
    ("ptrace", ProcessPlatform::read_ptrace),
];

const WRITE_BACKENDS: &[(&str, WriteBackend)] = &[
    ("process_vm_writev", ProcessPlatform::write_vm),
    ("/proc/pid/mem", ProcessPlatform::write_procmem),
    ("ptrace", ProcessPlatform::write_ptrace),
];

impl ProcessPlatform {
    pub fn read_memory<T: Pod>(&self, address: Address) -> io::Result<T> {
        let mut value: T = unsafe { mem::zeroed() };
        let buf = unsafe {
            slice::from_raw_parts_mut((&mut value as *mut T).cast::<u8>(), mem::size_of::<T>())
        };
        self.read_bytes(address, buf)?;

        tracing::info!(buf, "read_memory read");

        Ok(value)
    }

    pub fn write_memory<T: Pod>(&self, address: Address, value: &T) -> io::Result<()> {
        let data =
            unsafe { slice::from_raw_parts((value as *const T).cast::<u8>(), mem::size_of::<T>()) };
        self.write_bytes(address, data)
    }

    pub fn read_vec(&self, address: Address, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_bytes(address, &mut buf)?;
        Ok(buf)
    }

    pub fn read_bytes(&self, address: Address, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        check_range(address, buf.len())?;

        let mut last_err = None;
        for (name, backend) in READ_BACKENDS {
            match backend(self, address, buf) {
                Ok(()) => {
                    tracing::info!(pid = self.pid, addr = %Hex(address), len = buf.len(), backend = name, "read ok");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(pid = self.pid, addr = %Hex(address), len = buf.len(), backend = name, error = %e, "read backend failed");
                    let fatal = is_fatal(&e);
                    last_err = Some(e);
                    if fatal {
                        break;
                    }
                }
            }
        }
        let err = last_err.expect("at least one backend");
        tracing::error!(pid = self.pid, addr = %Hex(address), len = buf.len(), error = %err, "read_bytes failed");
        Err(err)
    }

    pub fn write_bytes(&self, address: Address, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        check_range(address, data.len())?;

        let mut last_err = None;
        for (name, backend) in WRITE_BACKENDS {
            match backend(self, address, data) {
                Ok(()) => {
                    tracing::info!(pid = self.pid, addr = %Hex(address), len = data.len(), backend = name, "write ok");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(pid = self.pid, addr = %Hex(address), len = data.len(), backend = name, error = %e, "write backend failed");
                    let fatal = is_fatal(&e);
                    last_err = Some(e);
                    if fatal {
                        break;
                    }
                }
            }
        }
        let err = last_err.expect("at least one backend");
        tracing::error!(pid = self.pid, addr = %Hex(address), len = data.len(), error = %err, "write_bytes failed");
        Err(err)
    }
}

impl ProcessPlatform {
    fn read_vm(&self, addr: Address, buf: &mut [u8]) -> io::Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let rest = &mut buf[done..];
            let local = iovec {
                iov_base: rest.as_mut_ptr().cast(),
                iov_len: rest.len(),
            };
            let remote = iovec {
                iov_base: ptr(addr + done as Address),
                iov_len: rest.len(),
            };
            let n = unsafe { process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
            match n {
                n if n < 0 => {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "short read at {}: got {done} of {} bytes",
                            Hex(addr),
                            buf.len()
                        ),
                    ));
                }
                n => done += n as usize,
            }
        }
        Ok(())
    }

    fn read_procmem(&self, addr: Address, buf: &mut [u8]) -> io::Result<()> {
        fs::File::open(format!("/proc/{}/mem", self.pid))?.read_exact_at(buf, addr)
    }

    fn read_ptrace(&self, addr: Address, buf: &mut [u8]) -> io::Result<()> {
        let pid = Pid::from_raw(self.pid);
        let end = check_range(addr, buf.len())?;
        let _guard = PtraceGuard::attach(pid)?;

        let mut off = 0usize;
        while buf.len() - off >= 8 {
            let word = peek(pid, addr + off as Address)?;
            buf[off..off + 8].copy_from_slice(&word);
            off += 8;
        }

        let rem = buf.len() - off;
        if rem > 0 {
            let tail_addr = addr + off as Address;
            with_tail_window(tail_addr, end, |start| {
                let word = peek(pid, start)?;
                let skip = (tail_addr - start) as usize;
                buf[off..].copy_from_slice(&word[skip..skip + rem]);
                Ok(())
            })?;
        }
        Ok(())
    }

    fn write_vm(&self, addr: Address, data: &[u8]) -> io::Result<()> {
        let mut done = 0usize;
        while done < data.len() {
            let rest = &data[done..];
            let local = iovec {
                iov_base: rest.as_ptr() as *mut c_void,
                iov_len: rest.len(),
            };
            let remote = iovec {
                iov_base: ptr(addr + done as Address),
                iov_len: rest.len(),
            };
            let n = unsafe { process_vm_writev(self.pid, &local, 1, &remote, 1, 0) };
            match n {
                n if n < 0 => {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!(
                            "short write at {}: wrote {done} of {} bytes",
                            Hex(addr),
                            data.len()
                        ),
                    ));
                }
                n => done += n as usize,
            }
        }
        Ok(())
    }

    fn write_procmem(&self, addr: Address, data: &[u8]) -> io::Result<()> {
        fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/{}/mem", self.pid))?
            .write_all_at(data, addr)
    }

    fn write_ptrace(&self, addr: Address, data: &[u8]) -> io::Result<()> {
        let pid = Pid::from_raw(self.pid);
        let end = check_range(addr, data.len())?;
        let _guard = PtraceGuard::attach(pid)?;

        let mut off = 0usize;
        while data.len() - off >= 8 {
            let word: [u8; 8] = data[off..off + 8].try_into().expect("8-byte chunk");
            poke(pid, addr + off as Address, word)?;
            off += 8;
        }

        let rem = data.len() - off;
        if rem > 0 {
            let tail = &data[off..];
            let tail_addr = addr + off as Address;
            with_tail_window(tail_addr, end, |start| {
                let mut word = peek(pid, start)?;
                let skip = (tail_addr - start) as usize;
                word[skip..skip + rem].copy_from_slice(tail);
                poke(pid, start, word)
            })?;
        }
        Ok(())
    }
}

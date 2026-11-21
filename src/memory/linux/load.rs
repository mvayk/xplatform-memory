use nix::{
    sys::{signal::Signal, wait::WaitStatus},
    unistd::Pid,
};
use object::{Object, ObjectSegment, ObjectSymbol};

use crate::{
    formatter::Hex,
    linux::{
        map::{maps_loaded, process_ready},
        platform::ProcessPlatform,
        trace::{ASMInjector, InputRegisters, UnexpectedWaitStatus},
    },
};
use std::{
    fs,
    io::{self, Error},
    path::Path,
    time::Duration,
};

/* i am in pain */
fn runtime_addr(p: &ProcessPlatform, lib: &str, sym: &str) -> Option<u64> {
    let regions = p.get_all_regions().ok()?;

    let is_lib = |m: &str| {
        Path::new(m)
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix(lib))
            .map_or(false, |rest| rest.starts_with('.') || rest.starts_with('-'))
    };

    let path = regions
        .iter()
        .find(|r| is_lib(&r.module_name))?
        .module_name
        .clone();

    let base = regions
        .iter()
        .filter(|r| r.module_name == path)
        .map(|r| r.addresses.start)
        .min()?;

    let data = fs::read(&path).ok()?;
    let file = object::File::parse(&*data).ok()?;

    let first_vaddr = file.segments().map(|s| s.address()).min().unwrap_or(0);

    let off = file
        .dynamic_symbols()
        .chain(file.symbols())
        .find(|s| s.name() == Ok(sym) && !s.is_undefined() && s.address() != 0)?
        .address();

    let addr = base + off - first_vaddr;
    debug_assert_ne!(
        addr, 0,
        "resolved {sym} in {lib} to null — symbol lookup is wrong"
    );
    Some(addr)
}

impl ProcessPlatform {
    pub fn load(&mut self, entry_name: String) -> io::Result<()> {
        process_ready(&self, Duration::from_secs(25))?;

        let Some(dl_open_addr) = runtime_addr(&self, "libc.so", "dlopen") else {
            tracing::error!("failed to find dl_open in target process");
            return Err(Error::new(
                io::ErrorKind::NotFound,
                "load failed to find dl_open in target process",
            ));
        };

        let path = "/home/mvayk/projects/xplatform-memory/target/release/libxpmemtool.so"
            .to_owned()
            + "\x00";

        tracing::debug!("attempting to allocate memory for so path");
        let alloc_path = self.allocate_memory()?;
        let _ = self.write_memory_long(&[alloc_path], path.as_bytes())?;

        tracing::info!(dl_open = %Hex(dl_open_addr));

        // let a = self.get_region_from_address(0x7b4c9cb295ed)?;
        // println!("{}", a.module_name);

        self.read_memory_long(&[alloc_path], path.len())?;

        tracing::debug!("creating injector instance directly");
        {
            let mut injector = ASMInjector::new(Pid::from_raw(self.pid), true)?;

            let new_regs = InputRegisters {
                rdi: alloc_path,
                rsi: libc::RTLD_LAZY as u64,
                r9: dl_open_addr,
                rip: injector.saved_regs.rip,
                ..Default::default()
            };

            tracing::debug!("attempting to call calling dl_open");
            match injector.call(new_regs, true) {
                Ok(ret) if ret < 0 => {
                    tracing::error!(ret, "load failed");
                    return Err(Error::new(io::ErrorKind::NotFound, "something went wrong"));
                }
                Ok(ptr) => {
                    tracing::info!(
                        memory_address = format_args!("{ptr:#x}"),
                        "load received success"
                    );
                    ptr
                }
                Err(e) => {
                    tracing::error!(error = %e, "syscall failed");
                    return Err(Error::new(
                        io::ErrorKind::NotFound,
                        "something went horrifically wrong",
                    ));
                }
            };
        }

        /* just so maps has time to refresh */
        /* i think accessing /mem while ptrace attached causes it to crash? */
        maps_loaded(&self, "libxpmemtool", Duration::from_secs(10))?;

        tracing::debug!("attempting to find libxpmemtool path in process memory");
        let Some(entry_addr) = runtime_addr(&self, "libxpmemtool", &entry_name) else {
            tracing::error!("failed to find xpmemtool in target process");
            return Err(Error::new(
                io::ErrorKind::NotFound,
                "load failed to find xpmemtool.so in target process",
            ));
        };

        let injector = ASMInjector::new(Pid::from_raw(self.pid), true)?;
        // tracing::debug!("updating injector instance");
        // injector.update()?;
        // tracing::info!(post_update_rip = %Hex(injector.saved_regs.rip), "after update");

        let new_regs = InputRegisters {
            r9: entry_addr,
            ..Default::default()
        };

        tracing::debug!("attempting to call entry of so");
        match injector.call(new_regs, true) {
            Ok(ret) if ret < 0 => {
                tracing::error!(ret, "load failed");
                return Err(Error::new(io::ErrorKind::NotFound, "something went wrong"));
            }
            Ok(ptr) => {
                tracing::info!(
                    memory_address = format_args!("{ptr:#x}"),
                    "load received success"
                );
                ptr
            }
            Err(e) => {
                let crash_signal = e
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<UnexpectedWaitStatus>())
                    .and_then(|uws| match uws.status {
                        WaitStatus::Stopped(_, sig) => Some(sig),
                        _ => None,
                    });

                match crash_signal {
                    Some(Signal::SIGABRT) => {
                        tracing::error!(
                            "entry point aborted (SIGABRT) — function called std::process::abort or a panic/assert fired"
                        );
                        return Err(Error::new(io::ErrorKind::Other, "entry point aborted"));
                    }
                    Some(Signal::SIGSEGV) => {
                        tracing::error!(
                            "entry point segfaulted (SIGSEGV) — bad pointer or invalid jump"
                        );
                        return Err(Error::new(io::ErrorKind::Other, "entry point segfaulted"));
                    }
                    Some(other_sig) => {
                        tracing::error!(?other_sig, "entry point hit unexpected signal");
                        return Err(Error::new(
                            io::ErrorKind::Other,
                            "entry point hit unexpected signal",
                        ));
                    }
                    None => {
                        tracing::error!(error = %e, "syscall failed");
                        return Err(Error::new(
                            io::ErrorKind::NotFound,
                            "something went horrifically wrong2 ",
                        ));
                    }
                }
            }
        };

        Ok(())
    }
}

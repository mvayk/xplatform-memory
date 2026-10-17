use nix::unistd::Pid;
use std::io;

use crate::{
    linux::{platform::ProcessPlatform, trace::SyscallInjector},
    types::Address,
};

impl ProcessPlatform {
    pub fn allocate_memory(&self, size: usize) -> io::Result<Address> {
        let injector = SyscallInjector::new(Pid::from_raw(self.pid))?;

        Ok(0x0)
    }
}

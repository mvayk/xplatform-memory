use crate::{
    linux::{map::MapEntry, platform::ProcessPlatform},
    types::AddyRange,
};
use std::{
    fs,
    io::{self, Error, ErrorKind},
    path::Path,
};

fn get_module_path(pid: i32, module_name: &str) -> io::Result<String> {
    if module_name.is_empty() {
        tracing::trace!("get_module_path called with empty module name");
        return Err(Error::new(ErrorKind::InvalidInput, "module_name was empty"));
    }
    tracing::debug!(%module_name, "get_module_path searching for module");
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;
    for line in maps.lines() {
        let path = match line.splitn(6, ' ').nth(5) {
            Some(p) => p.trim(),
            None => continue,
        };

        if !path.starts_with('/') {
            continue;
        }

        let matches = path == module_name
            || Path::new(path)
                .file_name()
                .is_some_and(|f| f == module_name);

        if matches {
            tracing::info!(%module_name, %path, "get_module_path found module");
            return Ok(path.to_string());
        }
    }

    tracing::error!(%module_name, "get_module_path failed to find module");
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("Failed to find module path for {}", module_name),
    ))
}

#[derive(Clone)]
pub struct ModuleP<'a> {
    pub name: String, /* file path */
    pub process: &'a ProcessPlatform,
    pub addresses: AddyRange,
}

impl<'a> ModuleP<'a> {
    pub fn get_regions(&self) -> io::Result<Vec<MapEntry>> {
        self.process.get_module_regions(self.name.as_str())
    }

    pub fn get_range(&self) -> io::Result<AddyRange> {
        self.process.get_module_range(self.name.as_str())
    }
}

impl ProcessPlatform {
    pub fn get_module(&self, module_name: &str) -> io::Result<ModuleP<'_>> {
        let path: String = get_module_path(self.pid, module_name)?;
        let range = self.get_module_range(path.as_str())?;

        tracing::info!(
            %module_name,
            %path,
            %range,
            pid = self.pid,
            "get_module successful"
        );

        Ok(ModuleP {
            name: path,
            process: self,
            addresses: range,
        })
    }

    pub fn get_module_regions(&self, name: &str) -> io::Result<Vec<MapEntry>> {
        let regions: Vec<MapEntry> = self
            .get_all_regions()?
            .into_iter()
            .filter(|r| r.module_name == name)
            .collect();

        if regions.is_empty() {
            tracing::error!(
                pid = self.pid,
                %name,
                "get_module_regions failed to find module regions"
            );
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("module {} not found", name)));
        }

        Ok(regions)
    }

    pub fn get_module_range(&self, name: &str) -> io::Result<AddyRange> {
        let module_regions = self.get_module_regions(name)?;
        let start = module_regions
            .iter()
            .map(|r| r.addresses.start)
            .min()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no regions found"))?;
        let end = module_regions
            .iter()
            .map(|r| r.addresses.end)
            .max()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no regions found"))?;

        for region in &module_regions {
            tracing::trace!(%region, %start, %end, "get_module_range processing region");
        }

        Ok((start..end).into())
    }
}

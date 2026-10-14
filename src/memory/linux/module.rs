use crate::{
    linux::{map::MapEntry, platform::ProcessPlatform},
    types::AddyRange,
};
use std::{fs, io, path::Path};

fn get_module_path(pid: i32, module_name: &str) -> io::Result<String> {
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
            tracing::info!(module_name, path, "get_module_path successful");
            return Ok(path.to_string());
        }
    }

    tracing::error!(module_name, "get_module_path failed");
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Failed to find module path",
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
            module_name,
            path,
            %range,
            self.pid,
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
                self.pid,
                name,
                "get_module_regions failed to find module regions"
            );
            return Err(io::Error::new(io::ErrorKind::NotFound, "module not found"));
        }
        Ok(regions)
    }

    pub fn get_module_range(&self, name: &str) -> io::Result<AddyRange> {
        let regions = self.get_module_regions(name)?;
        let start = regions.iter().map(|r| r.addresses.start).min().unwrap();
        let end = regions.iter().map(|r| r.addresses.end).max().unwrap();
        Ok((start..end).into())
    }
}

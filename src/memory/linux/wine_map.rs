use std::{fs::File, io, os::unix::fs::FileExt};

use crate::linux::map::MapEntry;

/* anthropic */
pub fn pe_size_of_image(mem: &File, base: u64) -> Option<u64> {
    // DOS header: "MZ" at 0, e_lfanew (offset of the NT headers) at 0x3c
    let mut dos = [0u8; 0x40];
    mem.read_exact_at(&mut dos, base).ok()?;
    if &dos[0..2] != b"MZ" {
        return None;
    }
    let lfanew = u32::from_le_bytes(dos[0x3c..0x40].try_into().ok()?) as u64;

    // NT headers: 4-byte "PE\0\0" + 20-byte COFF header + optional header.
    // SizeOfImage sits at offset 56 of the optional header (same for PE32 and PE32+).
    let mut nt = [0u8; 4 + 20 + 60];
    mem.read_exact_at(&mut nt, base + lfanew).ok()?;
    if &nt[0..4] != b"PE\0\0" {
        return None;
    }
    let off = 4 + 20 + 56;
    Some(u32::from_le_bytes(nt[off..off + 4].try_into().ok()?) as u64)
}

pub fn attribute_wine_modules(entries: &mut [MapEntry], pid: i32) -> io::Result<()> {
    let headers: Vec<(String, u64)> = entries
        .iter()
        .filter(|e| {
            let lower = e.module_name.to_ascii_lowercase();
            e.offset == 0 && (lower.ends_with(".dll") || lower.ends_with(".exe"))
        })
        .map(|e| (e.module_name.clone(), e.addresses.start))
        .collect();

    if headers.is_empty() {
        return Ok(());
    }

    let mem = File::open(format!("/proc/{pid}/mem"))?;

    let mut modules: Vec<(String, u64, u64)> = Vec::new();
    for (name, base) in headers {
        match pe_size_of_image(&mem, base) {
            Some(size) => modules.push((name, base, base + size)),
            None => tracing::warn!(path = %name, "no valid PE header at module base"),
        }
    }

    for e in entries.iter_mut().filter(|e| e.module_name.is_empty()) {
        if let Some((name, _, _)) = modules
            .iter()
            .find(|(_, base, end)| e.addresses.start >= *base && e.addresses.end <= *end)
        {
            e.module_name = name.clone();
        }
    }
    Ok(())
}

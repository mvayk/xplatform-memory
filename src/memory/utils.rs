pub fn parse_pattern(pattern: &str) -> Vec<Option<u8>> {
    pattern
        .split_whitespace()
        .map(|b| {
            if b == "??" || b == "?" {
                None
            } else {
                u8::from_str_radix(b, 16).ok()
            }
        })
        .collect()
}

pub fn pattern_scan_all(memory: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    if pattern.is_empty() || pattern.len() > memory.len() {
        return vec![];
    }
    memory
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(i, window)| {
            let matches = window
                .iter()
                .zip(pattern.iter())
                .all(|(byte, pat)| pat.map_or(true, |p| *byte == p));
            if matches { Some(i) } else { None }
        })
        .collect()
}

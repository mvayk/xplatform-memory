pub mod definitions;
pub mod formatter;
pub mod process;
pub mod utils;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

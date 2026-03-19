#[cfg(target_os = "windows")]
pub use windows::platform;

#[cfg(target_os = "linux")]
pub use linux::platform;

pub mod linux;
pub mod utils;
pub mod windows;
pub mod wrapper;

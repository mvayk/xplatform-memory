#[unsafe(no_mangle)]
pub extern "C" fn css_entry() {
    std::process::abort();
}

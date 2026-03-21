mod patch;

pub fn patch(process_name: &str) {
    match patch::patch(process_name) {
        Ok(returned) => println!("Patched {:?}", returned),
        Err(e) => eprintln!("failed: {e}"),
    }
}

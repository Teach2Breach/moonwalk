use std::env;
use moonwalk::find_dll_base;

fn main() {
    // Get target DLL name from command line or default to "ntdll.dll"
    let target_dll = env::args().nth(1).unwrap_or_else(|| "ntdll.dll".to_string());
    println!("Searching for: {}", target_dll);

    match find_dll_base(&target_dll) {
        Some(base_address) => println!("Found {} at: 0x{:X}", target_dll, base_address),
        None => println!("Failed to find {}", target_dll),
    }
}

use std::env;
use moonwalk::find_dll_base;

fn main() {
    let target_dll = env::args().nth(1).unwrap_or_else(|| "ntdll.dll".to_string());
    if let Some(base_address) = find_dll_base(&target_dll) {
        println!("{} base address: {:X}", target_dll, base_address);
    }
    else {
        println!("{} not found", target_dll);
    }
}

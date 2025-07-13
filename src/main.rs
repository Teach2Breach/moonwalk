use std::env;
use moonwalk::{find_dll_base, signature_scanner};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Usage: {} <dll_name> <function1> [function2 ...]", args[0]);
        println!("Example: {} ntdll.dll NtCreateFile NtQuerySystemTime", args[0]);
        return;
    }

    let target_dll = &args[1];
    let function_names = &args[2..];

    if let Some(base_address) = find_dll_base(target_dll) {
        println!("{} base address: 0x{:X}", target_dll, base_address);

        for function_name in function_names {
            if let Some(func_addr) = signature_scanner::find_function_by_signature(base_address, function_name) {
                println!("✓ Found {} at 0x{:X}", function_name, func_addr);
            } else {
                println!("✗ Could not find {}", function_name);
            }
        }
    } else {
        println!("{} not found", target_dll);
    }
}

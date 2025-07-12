# moonwalk: DLL Base Address Finder

This Rust library and CLI tool demonstrates an alternative method to find the base address of loaded DLLs without using a Process Environment Block (PEB) walk. This technique is particularly useful in scenarios where PEB walking might be detected or blocked.

## Branch Differences

This repository contains two branches with different approaches:

### Main Branch
- Uses `winapi` crate and `VirtualQuery` for memory validation
- Library functions (`lib.rs`) have no print statements for clean integration
- CLI tool (`main.rs`) includes debug output for proof of concept
- Good for learning and understanding the technique

### OPSEC Branch
- **No external dependencies** - completely self-contained
- **No Windows API calls** - uses direct memory access with exception handling instead of `VirtualQuery`
- **No print statements** in library functions
- **Enhanced stealth** - makes no API calls
- **Better for implants/tools** - leaves fewer traces and is harder to detect

Both branches are safe to use, but the OPSEC branch provides additional operational security benefits for scenarios where API calls might be monitored or blocked.

## How It Works

The program uses a stack walking approach to locate DLLs by:

1. **Accessing the Thread Environment Block (TEB)**:
   - Uses inline assembly to read the TEB pointer from the GS segment register (GS:[0x30])
   - Retrieves the stack base (GS:[0x08]) and stack limit (GS:[0x10]) from the TEB

2. **Stack Walking**:
   - Starts from the current stack pointer (RSP)
   - Walks up the stack looking for return addresses
   - Checks each address for executable memory
   - **Main branch**: Uses `VirtualQuery` to validate memory regions
   - **OPSEC branch**: Uses direct memory access with exception handling

3. **Module Identification**:
   - For each potential return address, checks if it points to executable memory
   - When executable memory is found, walks backwards to find the PE header
   - Validates the module by checking:
     - MZ signature (DOS header)
     - PE signature
     - DLL characteristics
     - 64-bit architecture
     - Module name from export directory

4. **Validation**:
   - Verifies the module is the target DLL by checking its name in the export directory
   - Confirms all PE header structures are valid

## Why This Approach?

Traditional methods of finding DLLs often involve walking the PEB's module list. While effective, this approach can be:
- Detected by security software
- Blocked in certain environments

This stack walking method provides an alternative that:
- Doesn't rely on the PEB
- Can work in environments where PEB walking is blocked
- **OPSEC branch**: Makes no API calls

## Requirements

- Rust (nightly toolchain)
- Windows x64
- **Main branch**: `winapi` crate
- **OPSEC branch**: No external dependencies

## Usage

### As a Library

Add to your `Cargo.toml`:

**Main branch:**
```toml
[dependencies]
moonwalk = { git = "https://github.com/Teach2Breach/moonwalk.git" }
```

**OPSEC branch:**
```toml
[dependencies]
moonwalk = { git = "https://github.com/Teach2Breach/moonwalk.git", branch = "opsec" }
```

Example usage in your code:
```rust
use moonwalk::find_dll_base;

fn main() {
    // Find ntdll.dll
    if let Some(ntdll_base) = find_dll_base("ntdll.dll") {
        println!("ntdll.dll base: 0x{:X}", ntdll_base);
    }

    // Case-insensitive, .dll extension optional
    if let Some(kernel32_base) = find_dll_base("KeRNEl32") {
        println!("kernel32.dll base: 0x{:X}", kernel32_base);
    }
}
```

### As a CLI Tool

Build:
```bash
cargo build --release
```

Run:
```bash
# Find ntdll.dll (default)
cargo run --release

# Find specific DLL (case insensitive, .dll extension optional)
cargo run --release kernel32.dll
cargo run --release KeRNEl32
cargo run --release USER32
```

## Example

Print statements are no longer included. This image is included for educational purposes. 

![Moonwalk DLL Base Address Finder Demo](2025-05-03_10-34.png)

## Notes

- DLL names are case-insensitive and the .dll extension is optional
- Only works with DLLs that are in the call stack
- **Main branch**: Uses `VirtualQuery` for safe memory access validation
- **OPSEC branch**: Uses direct memory access with exception handling for maximum stealth
- Both branches have clean library interfaces with no debug output
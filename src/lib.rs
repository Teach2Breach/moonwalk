#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_variables)]

use std::arch::asm;
use std::cell::Cell;
use std::mem;
use std::ptr;
use std::panic::UnwindSafe;

thread_local! {
    static STACK_BASE: Cell<u64> = Cell::new(0);
    static STACK_LIMIT: Cell<u64> = Cell::new(0);
    static TEB_ADDRESS: Cell<u64> = Cell::new(0);
}

const MIN_ADDRESS: u64 = 0x10000;  // Skip first 64KB
const MAX_ADDRESS: u64 = 0x7FFFFFFFFFFF;  // Max user-mode address on Windows x64

// Memory regions that would never contain a DLL
const SKIP_REGIONS: &[(u64, u64)] = &[
    (0x0000000000000000, 0x000000000000FFFF),  // NULL page
    (0x0000000000010000, 0x000000000001FFFF),  // First 64KB
    (0x0000000000020000, 0x000000000002FFFF),  // Second 64KB
    (0x0000000000030000, 0x000000000003FFFF),  // Third 64KB
    (0x0000000000040000, 0x000000000004FFFF),  // Fourth 64KB
    (0x0000000000050000, 0x000000000005FFFF),  // Fifth 64KB
    (0x0000000000060000, 0x000000000006FFFF),  // Sixth 64KB
    (0x0000000000070000, 0x000000000007FFFF),  // Seventh 64KB
    (0x0000000000080000, 0x000000000008FFFF),  // Eighth 64KB
    (0x0000000000090000, 0x000000000009FFFF),  // Ninth 64KB
    (0x00000000000A0000, 0x00000000000AFFFF),  // Tenth 64KB
    (0x00000000000B0000, 0x00000000000BFFFF),  // Eleventh 64KB
    (0x00000000000C0000, 0x00000000000CFFFF),  // Twelfth 64KB
    (0x00000000000D0000, 0x00000000000DFFFF),  // Thirteenth 64KB
    (0x00000000000E0000, 0x00000000000EFFFF),  // Fourteenth 64KB
    (0x00000000000F0000, 0x00000000000FFFFF),  // Fifteenth 64KB
    (0x0000000000100000, 0x000000000010FFFF),  // Sixteenth 64KB
];

// PE header structures
#[repr(C)]
#[derive(Copy, Clone)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IMAGE_OPTIONAL_HEADER64 {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

// Safe wrapper for reading memory that catches access violations
unsafe fn safe_read<T: Copy>(ptr: *const T) -> Option<T> {
    Some(unsafe { ptr::read(ptr) })
}

fn is_target_dll(base_address: usize, target_name: &str) -> bool {
    // Check if address is in skip regions
    for (start, end) in SKIP_REGIONS {
        if (base_address as u64) >= *start && (base_address as u64) <= *end {
            return false;
        }
    }

    unsafe {
        // First validate we can read the DOS header magic
        let dos_header = base_address as *const IMAGE_DOS_HEADER;
        let magic = match std::panic::catch_unwind(|| safe_read(dos_header)) {
            Ok(Some(header)) => header.e_magic,
            _ => return false
        };
        
        if magic != 0x5A4D {
            return false;
        }

        // Validate e_lfanew
        let e_lfanew = match std::panic::catch_unwind(|| safe_read(dos_header)) {
            Ok(Some(header)) => header.e_lfanew,
            _ => return false
        };
        
        if e_lfanew < 0x40 || e_lfanew > 0x1000 {
            return false;
        }

        let nt_headers_addr = base_address + e_lfanew as usize;
        
        // Validate we can read the NT headers
        let nt_headers = nt_headers_addr as *const IMAGE_NT_HEADERS64;
        let pe_sig = match std::panic::catch_unwind(|| safe_read(nt_headers)) {
            Ok(Some(headers)) => headers.Signature,
            _ => return false
        };
        
        if pe_sig != 0x00004550 {
            return false;
        }

        // Validate we can read the file header
        let file_header = match std::panic::catch_unwind(|| safe_read(nt_headers)) {
            Ok(Some(headers)) => headers.FileHeader,
            _ => return false
        };
        
        let characteristics = file_header.Characteristics;
        
        // Validate it's a DLL and x64
        if characteristics & 0x2000 == 0 {
            return false;
        }

        let machine = file_header.Machine;
        if machine != 0x8664 {
            return false;
        }

        // Validate we can read the optional header
        let opt_header = match std::panic::catch_unwind(|| safe_read(nt_headers)) {
            Ok(Some(headers)) => headers.OptionalHeader,
            _ => return false
        };
        
        let size_of_image = opt_header.SizeOfImage;
        
        // Validate image size is reasonable
        if size_of_image < 0x1000 || size_of_image > 0x10000000 {
            return false;
        }

        let export_dir_rva = opt_header.DataDirectory[0].VirtualAddress;
        let export_dir_size = opt_header.DataDirectory[0].Size;

        if export_dir_rva == 0 || export_dir_size == 0 {
            return false;
        }

        // Validate export directory RVA is within image bounds
        if export_dir_rva as u64 >= size_of_image as u64 {
            return false;
        }

        let export_dir = base_address + export_dir_rva as usize;
        
        // Validate we can read the name RVA
        let name_rva = match std::panic::catch_unwind(|| safe_read((export_dir as *const u32).add(3))) {
            Ok(Some(rva)) => rva,
            _ => return false
        };
        
        if name_rva == 0 || name_rva as u64 >= size_of_image as u64 {
            return false;
        }

        let name_ptr = base_address + name_rva as usize;
        
        // Read name byte-by-byte
        let mut name_bytes = Vec::new();
        let mut i = 0;
        while i < 256 {
            let current_ptr = (name_ptr as *const u8).add(i);
            
            // Ensure we're still within image bounds
            if (name_ptr + i) >= (base_address + size_of_image as usize) {
                break;
            }

            let byte = match std::panic::catch_unwind(|| safe_read(current_ptr)) {
                Ok(Some(b)) => b,
                _ => break
            };
            
            if byte == 0 {
                break;
            }
            name_bytes.push(byte);
            i += 1;
        }

        if let Ok(dll_name) = std::str::from_utf8(&name_bytes) {
            let found_name = dll_name.to_lowercase();
            let search_name = target_name.to_lowercase();
            
            let found_name = found_name.strip_suffix(".dll").unwrap_or(&found_name);
            let search_name = search_name.strip_suffix(".dll").unwrap_or(&search_name);
            
            found_name == search_name
        } else {
            false
        }
    }
}

// Validate if an address could be a DLL base by checking its contents
fn validate_potential_base(addr: usize) -> bool {
    unsafe {
        // Must be aligned
        if (addr & 0xFFF) != 0 {
            return false;
        }

        // Basic address range check
        if (addr as u64) < MIN_ADDRESS || (addr as u64) > MAX_ADDRESS {
            return false;
        }

        // Try to read DOS header
        let magic = match safe_read(addr as *const u16) {
            Some(m) => m,
            None => return false
        };
        
        if magic != 0x5A4D { // MZ signature
            return false;
        }

        // Read e_lfanew
        let e_lfanew_ptr = (addr as *const u8).add(0x3C);
        let e_lfanew = match safe_read(e_lfanew_ptr as *const i32) {
            Some(lfanew) => lfanew,
            None => return false
        };
        
        if e_lfanew <= 0 || e_lfanew > 0x1000 {
            return false;
        }

        // Validate PE header
        let pe_addr = addr + e_lfanew as usize;
        let pe_sig = match safe_read(pe_addr as *const u32) {
            Some(sig) => sig,
            None => return false
        };
        
        if pe_sig != 0x00004550 { // PE signature
            return false;
        }

        // Validate we can read the file header
        let file_header = (pe_addr + 4) as *const IMAGE_FILE_HEADER;
        let header = match safe_read(file_header) {
            Some(h) => h,
            None => return false
        };

        // Check if it's a DLL
        if header.Characteristics & 0x2000 == 0 {
            return false;
        }

        true
    }
}

pub fn find_dll_base(dll_name: &str) -> Option<usize> {
    let teb: *mut u64;
    unsafe {
        asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, nomem)
        );
    }

    // Store TEB address
    TEB_ADDRESS.with(|addr| addr.set(teb as u64));

    let stack_base: u64;
    unsafe {
        asm!(
            "mov {}, [{} + 0x08]",
            out(reg) stack_base,
            in(reg) teb,
            options(nostack, nomem)
        );
    }

    let stack_limit: u64;
    unsafe {
        asm!(
            "mov {}, [{} + 0x10]",
            out(reg) stack_limit,
            in(reg) teb,
            options(nostack, nomem)
        );
    }

    // Store stack region in thread local storage
    STACK_BASE.with(|base| base.set(stack_base));
    STACK_LIMIT.with(|limit| limit.set(stack_limit));

    let mut rsp: u64;
    unsafe {
        asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nostack, nomem)
        );
    }

    let mut current_stack = stack_base - 8; // Start from top of stack
    let mut addresses_checked = 0;
    let mut found_dlls = Vec::new();

    // Walk down the stack until we hit RSP
    while current_stack > rsp {
        // Read return address safely from stack
        let return_address = match unsafe { safe_read(current_stack as *const u64) } {
            Some(addr) => addr,
            None => {
                current_stack -= 8;
                continue;
            }
        };
        
        // Get page-aligned address and walk back to 64KB alignment
        let mut potential_base = return_address & !0xFFF;
        while potential_base % 0x10000 != 0 {
            potential_base -= 0x1000;
            
            // Basic range check
            if potential_base < 0x7FF000000000 || potential_base > 0x7FFFFFFFFFFF {
                break;
            }
        }

        // Skip if we've already checked this address
        if found_dlls.contains(&potential_base) {
            current_stack -= 8;
            continue;
        }

        // Skip addresses that are clearly not DLL bases
        if potential_base < 0x7FF000000000 || potential_base > 0x7FFFFFFFFFFF {
            current_stack -= 8;
            continue;
        }

        // For ntdll, check more thoroughly around the base
        if dll_name.to_lowercase() == "ntdll" {
            // Get the high part of the address (should be consistent within the module)
            let addr_high = potential_base & 0xFFFFFFFFF0000000;
            
            // Check if this could be ntdll (based on typical load ranges)
            if addr_high >= 0x7FF800000000 && addr_high <= 0x7FFFFFFF0000 {
                // Check the 64KB-aligned address and a few before it
                for i in 0..16 {  // Try up to 1MB back
                    let try_address = potential_base - (i * 0x10000);  // Try each 64KB-aligned address
                    if found_dlls.contains(&try_address) {
                        continue;
                    }
                    
                    match std::panic::catch_unwind(|| is_target_dll(try_address as usize, dll_name)) {
                        Ok(true) => return Some(try_address as usize),
                        _ => continue
                    }
                }
            }
        }

        // Try to validate this as a DLL base
        match std::panic::catch_unwind(|| is_target_dll(potential_base as usize, dll_name)) {
            Ok(true) => return Some(potential_base as usize),
            Ok(false) => {
                // Check if it's any DLL and log it
                if let Ok(true) = std::panic::catch_unwind(|| validate_potential_base(potential_base as usize)) {
                    found_dlls.push(potential_base);
                }
            }
            Err(_) => {
                // Access violation or other error, continue searching
                current_stack -= 8;
                continue;
            }
        }
        
        // Always decrement the stack pointer
        current_stack -= 8;
        addresses_checked += 1;
    }

    None
} 
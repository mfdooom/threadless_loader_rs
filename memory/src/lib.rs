use windows::Win32::Foundation::HANDLE;
use std::ffi::c_void;
use dinvoke;

pub type NtAllocateVirtualMemory= unsafe extern "system" fn (HANDLE, *mut *mut c_void, usize, *mut usize, u32, u32) -> i32;
pub type NtProtectVirtualMemory = unsafe extern "system" fn (HANDLE, *mut *mut c_void, *mut usize, u32, *mut u32) -> i32;
pub type NtWriteVirtualMemory = unsafe extern "system" fn (HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
pub type NtReadVirtualMemory =  unsafe extern "system" fn (HANDLE, *mut c_void, *mut c_void, usize, *mut usize) -> i32;
pub type NtFreeVirtualMemory =  unsafe extern "system" fn (HANDLE, *mut *mut c_void, *mut usize, u32) -> i32;



pub unsafe fn allocate_virtual_memory(h_process: HANDLE, base_address: usize, mut size: usize, protection: u32) -> (Option<i32>, usize){

    let ret: Option<i32>;
    let func_ptr: NtAllocateVirtualMemory;
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    let mut base_address: *mut c_void = std::mem::transmute(base_address);
    dinvoke::dynamic_invoke!(ntdll, "NtAllocateVirtualMemory", func_ptr, ret, h_process, &mut base_address, 0, &mut size, 0x1000 | 0x2000, protection);
    

    (ret, base_address as usize)
}

pub unsafe fn read_virtual_memory(h_process: HANDLE, base_address: usize, buf_ptr: *mut c_void, bytes_to_read: usize) -> Option<i32>
{
    let ret: Option<i32>;
    let func_ptr: NtReadVirtualMemory;
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    let base_address: *mut c_void = std::mem::transmute(base_address);

    let mut bytes_read = 0;

    dinvoke::dynamic_invoke!(ntdll, "NtReadVirtualMemory", func_ptr, ret, h_process, base_address, buf_ptr, bytes_to_read, &mut bytes_read );

    ret

}
pub unsafe fn protect_virtual_memory(h_process: HANDLE, base_address: usize, mut size: usize, protect: u32, old_protect: &mut u32) -> Option<i32>{
    let ret: Option<i32>;
    let func_ptr: NtProtectVirtualMemory;
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    let mut base_address: *mut c_void = std::mem::transmute(base_address);
    dinvoke::dynamic_invoke!(ntdll, "NtProtectVirtualMemory", func_ptr, ret, h_process, &mut base_address, &mut size, protect, old_protect );
    
    ret
}

pub unsafe fn write_virtual_memory(h_process: HANDLE, base_address: usize, buf_ptr: *mut c_void, buf_len: usize, bytes_written: &mut usize ) -> Option<i32>{
    let ret: Option<i32>;
    let func_ptr: NtWriteVirtualMemory;
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    let base_address: *mut c_void = std::mem::transmute(base_address);

    dinvoke::dynamic_invoke!(ntdll, "NtWriteVirtualMemory", func_ptr, ret, h_process, base_address, buf_ptr, buf_len, bytes_written);
    
    ret
}

pub unsafe fn write_virtual_memory_calc(h_process: HANDLE, base_address: usize, buf_ptr: *mut c_void, buf_len: usize, bytes_written: &mut usize ) -> usize{
    let ret: Option<i32>;
    let func_ptr: NtWriteVirtualMemory;
    let ntdll = dinvoke::get_module_base_address("ntdll.dll");

    let base_address: *mut c_void = std::mem::transmute(base_address);

    dinvoke::dynamic_invoke!(ntdll, "NtWriteVirtualMemory", func_ptr, ret, h_process, base_address, buf_ptr, buf_len, bytes_written);

    println!("error from write? {}", ret.unwrap());
    
    *bytes_written
}

pub unsafe fn free_virtual_memory(h_process: HANDLE, base_address: usize) -> Option<i32>{

        let ret: Option<i32>;
        let func_ptr: NtFreeVirtualMemory;
        let ntdll = dinvoke::get_module_base_address("ntdll.dll");
        let mut base_address: *mut c_void = std::mem::transmute(base_address);
        let mut region_size: usize = 0;
        dinvoke::dynamic_invoke!(ntdll, "NtFreeVirtualMemory", func_ptr, ret, h_process, &mut base_address, &mut region_size, 0x00008000);
        
        ret
}
use core::ffi::{c_void, c_char, CStr};
use r_efi::efi::Status;

#[no_mangle]
pub extern "efiapi" fn DebugPrintEnabled() -> bool { true }

#[no_mangle]
pub extern "efiapi" fn DebugPrintLevelEnabled(_level: usize) -> bool { true }

#[no_mangle]
pub unsafe extern "C" fn DebugPrint(_level: usize, message: *const i8, mut args: ...) {
    print!("[C] ");
    let c_str: &CStr = CStr::from_ptr(message);
    let c_str = c_str.to_string_lossy();

    let mut chars = c_str.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            if let Some(spec) = chars.next() {
                match spec {
                    'a' => {
                        let ptr: *const c_char = args.arg();
                        let cstr = CStr::from_ptr(ptr);
                        print!("{}", cstr.to_str().unwrap_or("<bad utf8>"));
                    }
                    'p' => {
                        let ptr: *const core::ffi::c_void = args.arg();
                        print!("{:x}", ptr as usize);
                    }
                    '%' => {
                        print!("%");
                    }
                    _ => {
                        print!("%{}", spec);
                    }
                }
            } else {
                print!("%");
            }
        } else {
            print!("{}", c);
        }
    }
}

#[no_mangle]
pub extern "efiapi" fn CopyMem(
    dest: *mut c_void,
    src: *const c_void,
    len: usize,
) {
    unsafe {
        std::ptr::copy_nonoverlapping(src, dest, len);
    }
}

#[no_mangle]
/// Returns the index of the first non-zero byte in the destination buffer.
pub extern "efiapi" fn CompareMem(
    dest: *const c_void,
    src: *const c_void,
    len: usize,
) -> usize {
    unsafe {
        let dest_slice = std::slice::from_raw_parts(dest as *const u8, len);
        let src_slice = std::slice::from_raw_parts(src as *const u8, len);
        for (i, (d, s)) in dest_slice.iter().zip(src_slice.iter()).enumerate() {
            if d != s {
                return i;
            }
        }
        0
    }
}

#[no_mangle]
/// Attempt to add and if it results in an overllow, return an error code.
pub extern "efiapi" fn SafeUintnAdd(
    a: usize,
    b: usize,
    result: *mut usize,
) -> Status {
    if result.is_null() {
        return Status::INVALID_PARAMETER;
    }

    match a.checked_add(b) {
        Some(value) => {
            unsafe { *result = value };
            Status::SUCCESS
        }
        None => Status::BUFFER_TOO_SMALL,
    }
}

#[no_mangle]
pub extern "efiapi" fn IsZeroBuffer(
    buffer: *const c_void,
    length: usize,
) -> bool {
    unsafe {
        let slice = std::slice::from_raw_parts(buffer as *const u8, length);
        slice.iter().all(|&b| b == 0)
    }
}

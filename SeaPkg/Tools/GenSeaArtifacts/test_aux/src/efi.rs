//! A module containing external functions necessary to consume the pre-compiled BasePeCoffValidationLib.obj file
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
use std::{
    ffi::{c_char, CStr},
    sync::atomic::AtomicBool,
};

use r_efi::efi::Status;

const STATUS_WIDTH: usize = 8usize * core::mem::size_of::<Status>();
const WARNING_MASK: usize = 0x0 << (STATUS_WIDTH - 8);
/// Custom warning status to indicate skipped test
pub const WARNING_SKIP_TEST: Status = Status::from_usize(8 | WARNING_MASK);

static DEBUG_PRINT_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_debug_print(enabled: bool) {
    DEBUG_PRINT_ENABLED.store(enabled, core::sync::atomic::Ordering::SeqCst);
}

pub struct PrettyStatus(pub Status);

impl core::fmt::Display for PrettyStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Status::SUCCESS => write!(f, "SUCCESS"),
            Status::INVALID_PARAMETER => write!(f, "INVALID_PARAMETER"),
            Status::BUFFER_TOO_SMALL => write!(f, "BUFFER_TOO_SMALL"),
            Status::SECURITY_VIOLATION => write!(f, "SECURITY_VIOLATION"),
            Status::COMPROMISED_DATA => write!(f, "COMPROMISED_DATA"),
            WARNING_SKIP_TEST => write!(f, "SKIPPED"),
            _ => write!(f, "Unknown status: {:?}", self.0),
        }
    }
}

#[no_mangle]
extern "C" fn GetMemoryAttributes(
    _pt_base: u64,
    _base_addr: u64,
    _size: u64,
    _mem_attr: *mut u64,
) -> Status {
    todo!()
}

#[no_mangle]
unsafe extern "C" fn DebugPrint(_error_level: usize, message: *const c_char, mut args: ...) {
    let fmt = CStr::from_ptr(message).to_str().unwrap();

    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let mut fill_zero = false;
            let mut width = 0usize;

            // Handle optional fill (like '0') and width (like '02')
            if let Some(next) = chars.clone().next() {
                if next == '0' {
                    fill_zero = true;
                    chars.next(); // consume '0'
                }
            }

            // Parse width if digits follow
            while let Some(digit @ '0'..='9') = chars.clone().next() {
                chars.next(); // consume digit
                width = width * 10 + (digit as usize - '0' as usize);
            }

            // Final specifier
            match chars.next() {
                Some('a') => {
                    let s_ptr: *const c_char = args.arg();
                    if !s_ptr.is_null() {
                        let cstr = unsafe { CStr::from_ptr(s_ptr) };
                        print!("{}", cstr.to_str().unwrap_or("(invalid utf-8)"));
                    } else {
                        print!("(null)");
                    }
                }
                Some('p') => {
                    let ptr: *const core::ffi::c_void = args.arg();
                    print!("{:x}", ptr as usize); // raw hex
                }
                Some('x') => {
                    let num: u64 = args.arg();
                    if fill_zero && width > 0 {
                        print!("{:0width$x}", num, width = width);
                    } else if width > 0 {
                        print!("{:width$x}", num, width = width);
                    } else {
                        print!("{:x}", num);
                    }
                }
                Some('%') => {
                    print!("%");
                }
                Some(other) => {
                    print!("%{}", other);
                }
                None => break,
            }
        } else {
            print!("{}", c);
        }
    }
}

#[no_mangle]
pub extern "C" fn DebugPrintEnabled() -> bool {
    DEBUG_PRINT_ENABLED.load(core::sync::atomic::Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn DebugPrintLevelEnabled(_level: u32) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn DebugCodeEnabled() -> bool {
    true
}

#[no_mangle]
pub extern "C" fn CopyMem(
    dst: *mut core::ffi::c_void,
    src: *const core::ffi::c_void,
    count: usize,
) {
    unsafe {
        core::ptr::copy(src as *const u8, dst as *mut u8, count);
    }
}

#[no_mangle]
pub extern "C" fn CompareMem(
    dest: *const core::ffi::c_void,
    src: *const core::ffi::c_void,
    len: usize,
) -> i32 {
    let dest = unsafe { core::slice::from_raw_parts(dest as *const u8, len) };
    let src = unsafe { core::slice::from_raw_parts(src as *const u8, len) };
    for i in 0..len {
        if dest[i] != src[i] {
            return dest[i] as i32 - src[i] as i32;
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn IsZeroBuffer(buffer: *const core::ffi::c_void, len: usize) -> bool {
    let buffer = unsafe { core::slice::from_raw_parts(buffer as *const u8, len) };
    for &byte in buffer {
        if byte != 0 {
            return false;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn SafeUintnAdd(augend: usize, addend: usize, result: *mut usize) -> Status {
    if result.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if let Some(res) = augend.checked_add(addend) {
        unsafe { *result = res };
        Status::SUCCESS
    } else {
        Status::BUFFER_TOO_SMALL
    }
}

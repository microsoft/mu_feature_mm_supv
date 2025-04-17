#![feature(c_variadic)]

mod efiapi;
pub use efiapi::*;

use r_efi::efi::Status;

use core::ffi::c_void;

struct PrettyStatus(Status);

impl core::fmt::Debug for PrettyStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self.0 {
            Status::SUCCESS => write!(f, "SUCCESS"),
            Status::LOAD_ERROR => write!(f, "LOAD_ERROR"),
            Status::INVALID_PARAMETER => write!(f, "INVALID_PARAMETER"),
            Status::UNSUPPORTED => write!(f, "UNSUPPORTED"),
            Status::BAD_BUFFER_SIZE => write!(f, "BAD_BUFFER_SIZE"),
            Status::BUFFER_TOO_SMALL => write!(f, "BUFFER_TOO_SMALL"),
            Status::NOT_READY => write!(f, "NOT_READY"),
            Status::DEVICE_ERROR => write!(f, "DEVICE_ERROR"),
            Status::WRITE_PROTECTED => write!(f, "WRITE_PROTECTED"),
            Status::OUT_OF_RESOURCES => write!(f, "OUT_OF_RESOURCES"),
            Status::VOLUME_CORRUPTED => write!(f, "VOLUME_CORRUPTED"),
            Status::VOLUME_FULL => write!(f, "VOLUME_FULL"),
            Status::NO_MEDIA => write!(f, "NO_MEDIA"),
            Status::MEDIA_CHANGED => write!(f, "MEDIA_CHANGED"),
            Status::NOT_FOUND => write!(f, "NOT_FOUND"),
            Status::ACCESS_DENIED => write!(f, "ACCESS_DENIED"),
            Status::NO_RESPONSE => write!(f, "NO_RESPONSE"),
            Status::NO_MAPPING => write!(f, "NO_MAPPING"),
            Status::TIMEOUT => write!(f, "TIMEOUT"),
            Status::NOT_STARTED => write!(f, "NOT_STARTED"),
            Status::ALREADY_STARTED => write!(f, "ALREADY_STARTED"),
            Status::ABORTED => write!(f, "ABORTED"),
            Status::ICMP_ERROR => write!(f, "ICMP_ERROR"),
            Status::TFTP_ERROR => write!(f, "TFTP_ERROR"),
            Status::PROTOCOL_ERROR => write!(f, "PROTOCOL_ERROR"),
            Status::INCOMPATIBLE_VERSION => write!(f, "INCOMPATIBLE_VERSION"),
            Status::SECURITY_VIOLATION => write!(f, "SECURITY_VIOLATION"),
            Status::CRC_ERROR => write!(f, "CRC_ERROR"),
            Status::END_OF_MEDIA => write!(f, "END_OF_MEDIA"),
            Status::END_OF_FILE => write!(f, "END_OF_FILE"),
            Status::INVALID_LANGUAGE => write!(f, "INVALID_LANGUAGE"),
            Status::COMPROMISED_DATA => write!(f, "COMPROMISED_DATA"),
            Status::IP_ADDRESS_CONFLICT => write!(f, "IP_ADDRESS_CONFLICT"),
            Status::HTTP_ERROR => write!(f, "HTTP_ERROR"),
            Status::HOST_UNREACHABLE => write!(f, "HOST_UNREACHABLE"),
            Status::PROTOCOL_UNREACHABLE => write!(f, "PROTOCOL_UNREACHABLE"),
            Status::PORT_UNREACHABLE => write!(f, "PORT_UNREACHABLE"),
            Status::CONNECTION_FIN => write!(f, "CONNECTION_FIN"),
            Status::CONNECTION_RESET => write!(f, "CONNECTION_RESET"),
            Status::CONNECTION_REFUSED => write!(f, "CONNECTION_REFUSED"),
            _ => write!(f, "Unknown status: {:?}", self.0),
        }
    }
}

extern "C" {
    pub fn PeCoffImageValidationNonZero (
        TargetImage: *const u8,
        Hdr: *const c_void,
    ) -> Status;
}

#[no_mangle]
pub extern "efiapi" fn GetMemoryAttributes(
    _page_table_base: u64,
    _base_address: u64,
    _length: u64,
    attributes: *mut u64,
) -> Status {
    // TODO: Implement this with a page table dump.
    unsafe { attributes.write(u64::MAX) };
    Status::SUCCESS
}

fn main() {
    // This is a placeholder for the main function.
    // The actual implementation would go here.
    println!("Hello, world!");

    let buffer = vec![1u8; 1024]; // Example buffer
    let header: *const c_void = std::ptr::null(); // Example header pointer
    let result = unsafe { PeCoffImageValidationNonZero(buffer.as_ptr(), header) };
    println!("Result: {:?}", PrettyStatus(result));
}
//! A module containing the definitions for the auxiliary file.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
use std::{fmt::Debug, io::Write};

use scroll::{ctx::TryIntoCtx, Endian, Pwrite};

/// A struct representing the auxiliary file that is generated from the PDB
#[derive(Debug, Default)]
pub struct AuxFile {
    /// The IMAGE_VALIDATION_DATA_HEADER that is written to the aux file.
    pub header: ImageValidationDataHeader,
    /// a list of KEY_SYMBOL C structs to be written to the aux file.
    pub key_symbols: Vec<KeySymbol>,
    /// A list of IMAGE_VALIDATION_ENTRY_HEADER's or derivations of it based on
    /// the validation_type field.
    pub entries: Vec<ImageValidationEntryHeader>,
    /// The raw data containing the default values of symbols that have rules.
    pub raw_data: Vec<u8>,
}

impl AuxFile {
    /// Adds a new validation entry to the aux file.
    pub fn add_entry(&mut self, mut entry: ImageValidationEntryHeader, raw_data: &[u8]) {
        assert_eq!(
            entry.size as usize,
            raw_data.len(),
            "Default value raw data must match the size being validated."
        );

        // If the raw data is all zeros, we will zero the memory range instead of copying it
        // from the aux file.
        if raw_data.iter().all(|&b| b == 0) {
            entry.offset_to_default = u32::MAX; // Indicate that we want to zero the memory.
            self.entries.push(entry);
            return;
        }

        self.entries.push(entry);
        self.raw_data.extend_from_slice(raw_data);
    }

    /// Adds a key symbol to the aux file.
    pub fn add_key_symbol(&mut self, key_symbol: KeySymbol) {
        self.key_symbols.push(key_symbol);
    }

    /// Finalizes the aux file by calculating and setting valid offsets and sizes throughout the file.
    pub fn finalize(&mut self) {
        // Reset values if we want to reuse the aux file.
        self.header = ImageValidationDataHeader::default();

        for _ in self.key_symbols.iter_mut() {
            self.header.key_symbol_count += 1;
            self.header.size += 8;
            self.header.offset_to_first_entry += 8;
        }

        if !self.key_symbols.is_empty() {
            self.header.offset_to_first_key_symbol = size_of::<ImageValidationDataHeader>() as u32;
        }

        let mut offset_to_default = size_of::<ImageValidationDataHeader>() as u32
            + self.key_symbols.len() as u32 * 8
            + self
                .entries
                .iter()
                .fold(0, |acc, entry| acc + entry.header_size());

        for entry in self.entries.iter_mut() {
            self.header.size += entry.header_size();
            self.header.entry_count += 1;

            // If the offset_to_default is u32::MAX, it means we are zeroing the memory instead of
            // copying it from the aux file, so we leave it as u32::MAX. The u32::MAX value is set when
            // the rule is added to this struct [Self::add_entry].
            if entry.offset_to_default != u32::MAX {
                entry.offset_to_default = offset_to_default;
                offset_to_default += entry.size;
                self.header.size += entry.size;
            }
        }

        // Now that all entries have been added, we can calculate the offset to
        // the raw data, and update the offset_to_default field in each entry.
        let offset_to_first_default = size_of::<ImageValidationDataHeader>() as u32
            + self
                .entries
                .iter()
                .fold(0, |acc, entry| acc + entry.header_size())
            + self.key_symbols.len() as u32 * 8;

        self.header.offset_to_first_default = offset_to_first_default;
    }

    /// Writes the aux file to the given file path.
    pub fn to_file(&self, file_path: impl AsRef<std::path::Path>) -> anyhow::Result<()> {
        let mut file = std::fs::File::create(file_path)?;
        file.write_all(&self.to_bytes()?)?;

        Ok(())
    }

    /// Writes the aux file to a byte vector.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut buffer = vec![0; self.header.size as usize];
        buffer.gwrite_with(self, &mut 0, scroll::LE)?;
        Ok(buffer)
    }
}

impl TryIntoCtx<Endian> for &AuxFile {
    type Error = scroll::Error;
    fn try_into_ctx(self, this: &mut [u8], ctx: Endian) -> Result<usize, Self::Error> {
        let mut offset = 0;

        this.gwrite_with(&self.header, &mut offset, ctx)?;

        for key_symbol in &self.key_symbols {
            this.gwrite_with(key_symbol, &mut offset, ctx)?;
        }

        for entry in &self.entries {
            this.gwrite_with(entry, &mut offset, ctx)?;
        }

        this.gwrite_with(self.raw_data.as_slice(), &mut offset, ())?;

        Ok(offset)
    }
}

/// A struct representing the header of the aux file.
#[derive(Debug, Pwrite)]
pub struct ImageValidationDataHeader {
    /// The signature of the header. Must be 0x444C4156
    signature: u32,
    /// The size of the entire aux file in bytes.
    size: u32,
    /// The number of entries in the aux file.
    entry_count: u32,
    /// The offset to the first entry in the aux file.
    /// This is the size of the IMAGE_VALIDATION_DATA_HEADER.
    offset_to_first_entry: u32,
    /// The offset to the first default value in the aux file.
    offset_to_first_default: u32,
    /// The number of key symbols in the aux file.
    key_symbol_count: u32,
    /// The offset to the first key_sybol in the aux file.
    offset_to_first_key_symbol: u32,
}

impl Default for ImageValidationDataHeader {
    fn default() -> Self {
        ImageValidationDataHeader {
            signature: 0x444C4156,
            size: 28,
            entry_count: 0,
            offset_to_first_entry: size_of::<Self>() as u32,
            offset_to_first_default: 0,
            key_symbol_count: 0,
            offset_to_first_key_symbol: 0,
        }
    }
}

/// A struct that represents an signature/address pair to be added to the
/// auxiliary file header.
#[derive(Default, Debug, Pwrite)]
pub struct KeySymbol {
    /// The signature that tells the firmware what to do with the address.
    pub signature: u32,
    /// The offset
    pub offset: u32,
}

impl KeySymbol {
    pub fn new(signature: [char; 4], offset: u32) -> Self {
        KeySymbol {
            signature: u32::from_le_bytes(signature.map(|c| c as u8)),
            offset,
        }
    }
}

/// A struct representing the header of an entry in the aux file.
/// Typically a IMAGE_VALIDATION_ENTRY_HEADER, but may be casted to a different
/// type depending on the validation_type field. The other possible header
/// types are:
///
/// - validation_type = 0x2: IMAGE_VALIDATION_CONTENT
/// - validation_type = 0x3: IMAGE_VALIDATION_MEM_ATTR
/// - validation_type = 0x4: IMAGE_VALIDATION_SELF_REF
pub struct ImageValidationEntryHeader {
    pub signature: u32,
    /// Offset of the value in the original image.
    pub offset: u32,
    /// Size of the value in bytes.
    pub size: u32,
    /// The type of validation to perform on the symbol. Contains the data
    /// necessary to perform the validation.
    pub validation_type: ValidationType,
    /// Offset of the default value in the aux file.
    pub offset_to_default: u32,
}

impl ImageValidationEntryHeader {
    /// Returns the size of ImageValidationEntryHeader in bytes. While the C
    /// struct IMAGE_VALIDATION_ENTRY_HEADER is 20 bytes, The actual header in
    /// the aux file can be larger as may be casted to a different type
    /// depending on the validation_type field. That is to say, if the
    /// validation_type is ValidationType::Content, the header header written
    /// to the aux file will  actually be IMAGE_VALIDATION_CONTENT.
    pub fn header_size(&self) -> u32 {
        20 + match &self.validation_type {
            ValidationType::None => 0,
            ValidationType::NonZero => 0,
            ValidationType::Content { content } => content.len() as u32,
            ValidationType::MemAttr { .. } => 24,
            ValidationType::Ref { .. } => 4,
            ValidationType::Pointer { .. } => 4,
        }
    }
}

impl Debug for ImageValidationEntryHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ImageValidationEntryHeader {{ offset: 0x{:08X}, size: 0x{:08X}, validation_type: {:?}, offset_to_default: 0x{:08X} }}",
            self.offset, self.size, self.validation_type, self.offset_to_default)
    }
}

impl Default for ImageValidationEntryHeader {
    fn default() -> Self {
        ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0,
            size: 0,
            validation_type: ValidationType::default(),
            offset_to_default: 0,
        }
    }
}

impl TryIntoCtx<Endian> for &ImageValidationEntryHeader {
    type Error = scroll::Error;
    fn try_into_ctx(self, this: &mut [u8], ctx: Endian) -> Result<usize, Self::Error> {
        let mut offset = 0;
        this.gwrite_with(self.signature, &mut offset, ctx)?;
        this.gwrite_with(self.offset, &mut offset, ctx)?;
        this.gwrite_with(self.size, &mut offset, ctx)?;
        this.gwrite_with(self.validation_type.idx(), &mut offset, ctx)?;
        this.gwrite_with(self.offset_to_default, &mut offset, ctx)?;
        this.gwrite_with(&self.validation_type, &mut offset, ctx)?;

        Ok(offset)
    }
}

/// An enum representing the type of validation to be performed on the symbol
///
/// This enum also contains the data required to perform the validation and is
/// written to the auxiliary file in the validation entry section. See the
/// TryIntoCtx impl for [ImageValidationEntryHeader] for more information.
///
/// ## Validation Type headers
///
/// None - IMAGE_VALIDATION_ENTRY_HEADER
/// NonZero - IMAGE_VALIDATION_ENTRY_HEADER
/// Content - IMAGE_VALIDATION_CONTENT
/// MemAttr - IMAGE_VALIDATION_MEM_ATTR
/// Ref - IMAGE_VALIDATION_SELF_REF
/// Pointer - IMAGE_VALIDATION_ENTRY_HEADER
///
#[derive(Debug, Default, PartialEq)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum ValidationType {
    /// Firmware will perform no validation on the symbol.
    #[default]
    None = 0,
    /// Firmware will validate that the symbol is not zero.
    NonZero = 1,
    /// Firmware will validate that the symbol matches the value of `content`.
    Content { content: Vec<u8> } = 2,
    /// Firmware will validate that the memory attributes are as expected.
    MemAttr {
        memory_size: u64,
        must_have: u64,
        must_not_have: u64,
    } = 3,
    /// Firmware will validate that two symbols are equal.
    Ref { address: u32 } = 4,
    /// Firmware will validate that the symbol is a pointer and is not null
    Pointer { in_mseg: bool } = 5,
}

impl ValidationType {
    pub fn idx(&self) -> u32 {
        match self {
            ValidationType::None { .. } => 0,
            ValidationType::NonZero { .. } => 1,
            ValidationType::Content { .. } => 2,
            ValidationType::MemAttr { .. } => 3,
            ValidationType::Ref { .. } => 4,
            ValidationType::Pointer { .. } => 5,
        }
    }
}

impl core::fmt::Display for ValidationType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ValidationType::None { .. } => write!(f, "None"),
            ValidationType::NonZero { .. } => write!(f, "NonZero"),
            ValidationType::Content { .. } => write!(f, "Content"),
            ValidationType::MemAttr { .. } => write!(f, "MemAttr"),
            ValidationType::Ref { .. } => write!(f, "Ref"),
            ValidationType::Pointer { .. } => write!(f, "Pointer"),
        }
    }
}

impl TryIntoCtx<Endian> for &ValidationType {
    type Error = scroll::Error;
    fn try_into_ctx(self, this: &mut [u8], ctx: Endian) -> Result<usize, Self::Error> {
        let mut offset = 0;

        match self {
            ValidationType::None { .. } => {}
            ValidationType::NonZero { .. } => {}
            ValidationType::Content { content } => {
                this.gwrite_with(content.as_slice(), &mut offset, ())?;
            }
            ValidationType::MemAttr {
                memory_size,
                must_have,
                must_not_have,
            } => {
                this.gwrite_with(memory_size, &mut offset, ctx)?;
                this.gwrite_with(must_have, &mut offset, ctx)?;
                this.gwrite_with(must_not_have, &mut offset, ctx)?;
            }
            ValidationType::Ref { address } => {
                this.gwrite_with(address, &mut offset, ctx)?;
            }
            ValidationType::Pointer { in_mseg } => {
                this.gwrite_with(*in_mseg as u32, &mut offset, ctx)?;
            }
        }
        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt::Write;
    use std::io::Read;

    #[test]
    fn test_key_symbol_signature_creation() {
        assert_eq!(
            KeySymbol::new(['A', 'B', 'C', 'D'], 0x0).signature,
            0x44_43_42_41
        );
        assert_eq!(
            KeySymbol::new(['a', 'b', 'c', 'd'], 0x0).signature,
            0x64_63_62_61
        );
        assert_eq!(
            KeySymbol::new(['1', '2', '3', '4'], 0x0).signature,
            0x34_33_32_31
        );
        assert_eq!(
            KeySymbol::new(['!', '@', '#', '$'], 0x0).signature,
            0x24_23_40_21
        );
    }

    #[test]
    fn test_image_validation_entry_header_to_bytes_validation_type_none() {
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::None,
            offset_to_default: 0x2000,
        };
        let mut buffer = vec![0; entry.header_size() as usize];
        entry.try_into_ctx(&mut buffer, scroll::LE).unwrap();

        let expected = [
            0x45, 0x4E, 0x54, 0x52, // signature
            0x00, 0x10, 0x00, 0x00, // offset
            0x20, 0x00, 0x00, 0x00, // size
            0x00, 0x00, 0x00, 0x00, // validation_type (None)
            0x00, 0x20, 0x00, 0x00, // offset_to_default
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_image_validation_entry_header_to_bytes_validation_type_non_zero() {
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::NonZero,
            offset_to_default: 0x2000,
        };
        let mut buffer = vec![0; entry.header_size() as usize];
        entry.try_into_ctx(&mut buffer, scroll::LE).unwrap();

        let expected = [
            0x45, 0x4E, 0x54, 0x52, // signature
            0x00, 0x10, 0x00, 0x00, // offset
            0x20, 0x00, 0x00, 0x00, // size
            0x01, 0x00, 0x00, 0x00, // validation_type (NonZero)
            0x00, 0x20, 0x00, 0x00, // offset_to_default
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_image_validation_entry_header_to_bytes_validation_type_content() {
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::Content {
                content: vec![0x01, 0x02, 0x03, 0x04],
            },
            offset_to_default: 0x2000,
        };
        let mut buffer = vec![0; entry.header_size() as usize];
        entry.try_into_ctx(&mut buffer, scroll::LE).unwrap();

        let expected = [
            0x45, 0x4E, 0x54, 0x52, // signature
            0x00, 0x10, 0x00, 0x00, // offset
            0x20, 0x00, 0x00, 0x00, // size
            0x02, 0x00, 0x00, 0x00, // validation_type (Content)
            0x00, 0x20, 0x00, 0x00, // offset_to_default
            0x01, 0x02, 0x03, 0x04, // content
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_image_validation_entry_header_to_bytes_validation_type_mem_attr() {
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::MemAttr {
                memory_size: 0x1000,
                must_have: 0x0001,
                must_not_have: 0x0002,
            },
            offset_to_default: 0x2000,
        };
        let mut buffer = vec![0; entry.header_size() as usize];
        entry.try_into_ctx(&mut buffer, scroll::LE).unwrap();

        let expected = [
            0x45, 0x4E, 0x54, 0x52, // signature
            0x00, 0x10, 0x00, 0x00, // offset
            0x20, 0x00, 0x00, 0x00, // size
            0x03, 0x00, 0x00, 0x00, // validation_type (MemAttr)
            0x00, 0x20, 0x00, 0x00, // offset_to_default
            // Memory attributes
            0x00, 0x10, 0x00, 0x00, // memory_size
            0x00, 0x00, 0x00, 0x00, // cont.
            0x01, 0x00, 0x00, 0x00, // must_have
            0x00, 0x00, 0x00, 0x00, // cont.
            0x02, 0x00, 0x00, 0x00, // must_not_have
            0x00, 0x00, 0x00, 0x00, // cont.
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_image_validation_entry_header_to_bytes_validation_type_ref() {
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::Ref { address: 0x2000 },
            offset_to_default: 0x2000,
        };
        let mut buffer = vec![0; entry.header_size() as usize];
        entry.try_into_ctx(&mut buffer, scroll::LE).unwrap();

        let expected = [
            0x45, 0x4E, 0x54, 0x52, // signature
            0x00, 0x10, 0x00, 0x00, // offset
            0x20, 0x00, 0x00, 0x00, // size
            0x04, 0x00, 0x00, 0x00, // validation_type (Ref)
            0x00, 0x20, 0x00, 0x00, // offset_to_default
            0x00, 0x20, 0x00, 0x00, // address
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_image_validation_entry_header_to_bytes_validation_type_pointer() {
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::Pointer { in_mseg: true },
            offset_to_default: 0x2000,
        };
        let mut buffer = vec![0; entry.header_size() as usize];
        entry.try_into_ctx(&mut buffer, scroll::LE).unwrap();

        let expected = [
            0x45, 0x4E, 0x54, 0x52, // signature
            0x00, 0x10, 0x00, 0x00, // offset
            0x20, 0x00, 0x00, 0x00, // size
            0x05, 0x00, 0x00, 0x00, // validation_type (Pointer)
            0x00, 0x20, 0x00, 0x00, // offset_to_default
            0x01, 0x0, 0x00, 0x00, // address
        ];

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_image_validation_entry_header_formatter() {
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::None,
            offset_to_default: 0x2000,
        };

        let mut s = String::new();
        write!(&mut s, "{:?}", entry).unwrap();

        assert!(s.contains("offset: 0x00001000"));
        assert!(s.contains("size: 0x00000020"));
        assert!(s.contains("offset_to_default: 0x00002000"));
    }

    #[test]
    fn test_validation_type_formatter() {
        let validation = ValidationType::default();
        assert_eq!(format!("{}", validation), "None");

        let validation = ValidationType::NonZero;
        assert_eq!(format!("{}", validation), "NonZero");

        let validation = ValidationType::Content {
            content: vec![0x01, 0x02, 0x03, 0x04],
        };
        assert_eq!(format!("{}", validation), "Content");

        let validation = ValidationType::MemAttr {
            memory_size: 0x1000,
            must_have: 0x0001,
            must_not_have: 0x0002,
        };

        assert_eq!(format!("{}", validation), "MemAttr");

        let validation = ValidationType::Ref { address: 0x2000 };
        assert_eq!(format!("{}", validation), "Ref");

        let validation = ValidationType::Pointer { in_mseg: true };
        assert_eq!(format!("{}", validation), "Pointer");
    }

    #[test]
    #[should_panic(expected = "Default value raw data must match the size being validated.")]
    fn test_aux_file_ensure_catch_mismatched_raw_data_size() {
        let mut aux_file = AuxFile::default();
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::NonZero,
            offset_to_default: 0x2000,
        };
        aux_file.add_entry(entry, &[0x01, 0x02]); // Incorrect size
    }

    #[test]
    fn test_aux_file_add_key_symbol() {
        let mut aux_file = AuxFile::default();
        let key_symbol = KeySymbol::new(['A', 'B', 'C', 'D'], 0x1000);
        aux_file.add_key_symbol(key_symbol);

        assert_eq!(aux_file.key_symbols.len(), 1);
        assert_eq!(aux_file.key_symbols[0].signature, 0x44434241);
        assert_eq!(aux_file.key_symbols[0].offset, 0x1000);
    }

    #[test]
    fn test_aux_file_finalize_no_key_symbol() {
        let mut aux_file = AuxFile::default();

        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::NonZero,
            offset_to_default: 0x2000,
        };
        aux_file.add_entry(entry, &[0x01; 32]);

        aux_file.finalize();

        assert_eq!(aux_file.header.key_symbol_count, 0);
        // this offset is set to 0 to indicate there is no key_symbol.
        assert_eq!(aux_file.header.offset_to_first_key_symbol, 0);
        assert_eq!(aux_file.header.entry_count, 1);
        assert!(aux_file.header.size > 0);
    }

    #[test]
    fn test_aux_file_finalize() {
        let mut aux_file = AuxFile::default();
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::NonZero,
            offset_to_default: 0x2000,
        };
        aux_file.add_entry(entry, &[0x01; 32]);

        let key_symbol = KeySymbol::new(['A', 'B', 'C', 'D'], 0x1000);
        aux_file.add_key_symbol(key_symbol);

        aux_file.finalize();

        assert_eq!(aux_file.header.key_symbol_count, 1);
        assert_eq!(
            aux_file.header.offset_to_first_key_symbol,
            size_of::<ImageValidationDataHeader>() as u32
        );
        assert_eq!(aux_file.header.entry_count, 1);
        assert_eq!(aux_file.header.offset_to_first_entry, 0x24);
        assert_eq!(aux_file.entries[0].offset_to_default, 0x38);

        // Add a new key symbol to ensure we calculate the offsets correctly
        let new_key_symbol = KeySymbol::new(['E', 'F', 'G', 'H'], 0x2000);
        aux_file.add_key_symbol(new_key_symbol);
        aux_file.finalize();

        assert_eq!(aux_file.header.offset_to_first_entry, 0x2C);
        assert_eq!(aux_file.header.offset_to_first_default, 0x40);

        // Add a new entry to ensure we calculate the offsets correctly
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 0x20,
            validation_type: ValidationType::NonZero,
            offset_to_default: 0x2000,
        };

        aux_file.add_entry(entry, &[0x01; 32]);
        aux_file.finalize();

        assert_eq!(aux_file.header.offset_to_first_entry, 0x2C);
        assert_eq!(aux_file.header.offset_to_first_default, 0x54);

        assert_eq!(aux_file.entries[0].offset_to_default, 0x54);
        assert_eq!(aux_file.entries[1].offset_to_default, 0x74);
    }

    #[test]
    fn test_aux_file_to_bytes() {
        // We already have tests that all the other structs can be converted to bytes,
        // so we will just do one simple call and validate.

        let mut aux_file = AuxFile::default();
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 4,
            validation_type: ValidationType::NonZero,
            offset_to_default: 0x2000,
        };

        aux_file.add_key_symbol(KeySymbol::new(['A', 'B', 'C', 'D'], 0x1000));
        aux_file.add_entry(entry, &[0xFF; 4]);
        aux_file.finalize();

        let bytes = aux_file
            .to_bytes()
            .expect("Failed to convert aux file to bytes");
        let expected = vec![
            0x56, 0x41, 0x4C, 0x44, // signature
            0x3C, 0x00, 0x00, 0x00, // size
            0x01, 0x00, 0x00, 0x00, // entry_count
            0x24, 0x00, 0x00, 0x00, // offset_to_first_entry
            0x38, 0x00, 0x00, 0x00, // offset_to_first_default
            0x01, 0x00, 0x00, 0x00, // key_symbol_count
            0x1C, 0x00, 0x00, 0x00, // offset_to_first_key_symbol
            // KeySymbol data
            0x41, 0x42, 0x43, 0x44, // KeySymbol signature (ABCD)
            0x00, 0x10, 0x00, 0x00, // KeySymbol offset
            // Entry data
            0x45, 0x4E, 0x54, 0x52, // signature
            0x00, 0x10, 0x00, 0x00, // offset
            0x04, 0x00, 0x00, 0x00, // size
            0x01, 0x00, 0x00, 0x00, // validation_type (NonZero)
            0x38, 0x00, 0x00, 0x00, // offset_to_default
            // Default value data
            0xff, 0xff, 0xff, 0xff,
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_aux_file_to_file() {
        let mut aux_file = AuxFile::default();
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x1000,
            size: 4,
            validation_type: ValidationType::NonZero,
            offset_to_default: 0x2000,
        };

        aux_file.add_key_symbol(KeySymbol::new(['A', 'B', 'C', 'D'], 0x1000));
        aux_file.add_entry(entry, &[0xFF; 4]);
        aux_file.finalize();

        let t_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        assert!(aux_file.to_file(t_file.path()).is_ok());
        assert!(t_file.bytes().fold(0, |acc, _| acc + 1) > 0);
    }
}

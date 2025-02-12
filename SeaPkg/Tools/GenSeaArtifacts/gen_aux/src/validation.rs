//! A module containing the objects used for working with Validation rules.
//! 
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//! 
use pdb::TypeInformation;
use scroll::{ctx, Endian, Pwrite};
use serde::{Serialize, Deserialize};

use crate::Symbol;

/// A struct representing a validation rule that is defined in the config file.
/// A [ImageValidationEntryHeader](crate::auxgen::ImageValidationEntryHeader)
/// is created for each rule and written to the auxillary file. Each entry is
/// used to run the appropriate validation on the symbol in the firmware, and
/// also revert the symbol to it's original value.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidationRule {
    /// The symbol that the rule is associated with.
    pub symbol: String,
    /// An optional field that can be used to specify a field within the
    /// symbol, if the symbol is a class, that the validation should be
    /// performed on.
    pub field: Option<String>,
    /// The type of validation to be performed on the symbol.
    pub validation: ValidationType,
    /// An optional field that can be used to specify an offset from the symbol
    /// address that the validation should be performed on. Not to be combined
    /// with the `field` attribute.
    pub offset: Option<i64>,
    /// The size of the symbol that the validation should be performed on. This
    /// is used in conjunction with the `offset` attribute only.
    pub size: Option<u32>,
    /// A scope that the validation rule should be applied to. This validation
    /// rule is only applied if it's scope matches any of the scopes passed to
    /// the tool on the command line. If the rule has no scope, it is always
    /// applied.
    pub scope: Option<String>
}

impl ValidationRule {
    /// Creates a new empty validation rule with the given symbol name.
    pub fn new(symbol: String) -> Self {
        ValidationRule {
            symbol,
            field: None,
            validation: ValidationType::None,
            offset: None,
            size: None,
            scope: None
        }
    }

    /// Resolve any symbols in the rule to their actual addresses
    pub fn resolve(&mut self, symbol: &Symbol, symbols: &Vec<Symbol>, info: &TypeInformation) -> anyhow::Result<()> {
        
        // Resolve the field to an offset and size if it exists
        if let (Some(attribute), Some(index)) = (&self.field, &symbol.type_index) {
            let (field_offset, field_size) = crate::util::find_field_offset_and_size(info, &index, attribute, &symbol.name).unwrap();
            self.offset = Some(field_offset as i64);
            if self.size.is_none() {
                self.size = Some(field_size as u32);
            }
        }

        // Resolve the reference in the SELF validation type to an address
        match &self.validation {
            ValidationType::Ref{reference, ..} => {
                if let Some(reference) = reference {
                    if let Some(symbol) = symbols.iter().find(|&entry| &entry.name == reference) {
                        self.validation = ValidationType::Ref{reference: None, address: Some(symbol.address)};
                    } else {
                        return Err(anyhow::anyhow!("Could not find symbol {} for self reference rule.", reference))
                    }
                }
            },
            _ => {}
        }

        Ok(())
    }

    /// Returns true if the rule is in scope
    pub fn is_in_scope(&self, scopes: &[String]) -> bool {
        if let Some(scope) = &self.scope {
            return scopes.iter().any(|s| s.eq_ignore_ascii_case(scope));
        }
        true
    }
}

impl From<&Symbol> for ValidationRule {
    fn from(symbol: &Symbol) -> Self {
        ValidationRule {
            symbol: symbol.name.clone(),
            field: None,
            validation: ValidationType::Content{ content: 0xDEADBEEFu32.to_le_bytes().to_vec() },
            offset: None,
            size: Some(2),
            scope: None,
        }
    }
}

/// An enum representing the type of validation to be performed on the symbol
///
/// This enum also contains the data required to perform the validation and is
/// written to the auxiliary file in the validation entry section. See the
/// TryIntoCtx impl for
/// [ImageValidationEntryHeader](crate::auxgen::ImageValidationEntryHeader) for
/// more information.
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
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
#[repr(u32)]
#[serde(tag = "type")]
pub enum ValidationType {
    /// Firmware will perform no validation on the symbol.
    #[default]
    #[serde(alias = "NONE", alias = "none")]
    None = 0,
    /// Firmware will validate that the symbol is not zero.
    #[serde(alias = "NON_ZERO", alias = "nonzero", alias = "non zero", alias = "Non Zero")]
    NonZero = 1,
    /// Firmware will validate that the symbol matches the value of `content`.
    #[serde(alias = "CONTENT", alias = "content")]
    Content{content: Vec<u8>} = 2,
    /// Firmware will validate that the memory attributes are as expected.
    #[serde(alias = "MEM_ATTR", alias = "memattr", alias = "mem attr", alias = "Mem Attr")]
    MemAttr{memory_size: u64, must_have: u64, must_not_have: u64} = 3,
    /// Firmware will validate that two symbols are equal.
    #[serde(alias = "SELF", alias = "Self", alias = "self")]
    Ref{reference: Option<String>, address: Option<u32>} = 4,
    /// Firmware will validate that the symbol is a pointer and is not null
    #[serde(alias = "POINTER", alias = "pointer")]
    Pointer = 5,
}

impl Into<u32> for &ValidationType {
    fn into(self) -> u32 {
        match self {
            ValidationType::None{..} => 0,
            ValidationType::NonZero{..} => 1,
            ValidationType::Content{..} => 2,
            ValidationType::MemAttr{..} => 3,
            ValidationType::Ref{..} => 4,
            ValidationType::Pointer{..} => 5,
        }
    }
}

impl <'a> ctx::TryIntoCtx<Endian> for &ValidationType {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], ctx: Endian) -> Result<usize, Self::Error> {
        let value: u32 = self.into();
        this.pwrite_with(value, 0, ctx)?;
        Ok(4)
    }
}

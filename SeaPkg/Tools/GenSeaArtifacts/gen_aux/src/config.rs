//! A module containing the definitions for the configuration file used to generate the auxiliary file.
//!
//! Each entry in the configuration file is mapped back to a structure in the [AuxFile](crate::file::AuxFile) via the
//! [PdbMetadata](crate::metadata::PdbMetadata) object.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};

/// The configuration file for generating an auxiliary file.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// The overall configuration for the auxiliary file.
    #[serde(default, rename = "config")]
    pub config: Config,
    /// Key symbols to be added to the auxiliary file.
    #[serde(default, rename = "key")]
    pub keys: Vec<Key>,
    /// Validation rules that create a validation entry in the auxiliary file.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

impl ConfigFile {
    /// Creates a new config file from the given file path.
    pub fn from_file(file_path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(file_path)?;
        let config: ConfigFile = toml::from_str(contents.as_str())?;
        Ok(config)
    }

    /// Writes the config file to the given file path.
    pub fn to_file(&self, file_path: impl AsRef<std::path::Path>) -> anyhow::Result<()> {
        let contents = toml::to_string(self)?;
        std::fs::write(file_path, contents)?;
        Ok(())
    }

    /// Removes rules that do not match the given scopes.
    ///
    /// Rules without a scope are always applied.
    pub fn filter_by_scopes(&mut self, scopes: &[String]) -> anyhow::Result<()> {
        self.rules.retain(|rule| {
            if let Some(ref scope) = rule.scope {
                return scopes.iter().any(|s| s.eq_ignore_ascii_case(scope));
            }
            true
        });

        Ok(())
    }
}

/// Configuration options available in the config file.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Aux File generation will abort if any symbols are found that do not have a corresponding rule in the config.
    #[serde(default)]
    pub no_missing_rules: bool,
}

/// A struct representing a key symbol to be added to the auxiliary file header.
///
/// Maps to the [KeySymbol](crate::file::KeySymbol) in the auxiliary file.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    /// The signature that tells the firmware what to do with the address.
    pub signature: [char; 4],
    /// The offset
    pub symbol: String,
}

/// A struct representing a rule that should be applied to a symbol in the auxiliary file.
///
/// Maps to the [ImageValidationEntryHeader](crate::file::ImageValidationEntryHeader) in the auxiliary file.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The symbol that the rule is associated with.
    pub symbol: String,
    /// The field inside the symbol that the rule is associated with.
    pub field: Option<String>,
    /// The scope that the rule is associated with. If the rule has no scope, it is always applied.
    pub scope: Option<String>,
    /// If the symbol is an array, this configuration is applied to the symbol.
    pub array: Option<Array>,
    /// The type of validation to be performed on the symbol.
    pub validation: Validation,
}

/// Configuration for a symbol that is an array of an underlying type.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Array {
    /// The last index of the array is a sentinel value, thus creating a different validation rule for the last index.
    #[serde(default)]
    pub sentinel: bool,
    /// The index (or range of indexes) to apply the specified [Validation] to.
    ///
    /// If `None`, the validation is applied to all indexes of the array.
    #[serde(default, deserialize_with = "deserialize_range")]
    pub index: Option<RangeInclusive<usize>>,
}

/// A custom deserializer for the `index` field in the [Array] configuration.
fn deserialize_range<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<RangeInclusive<usize>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use core::fmt;
    use serde::de::{Error, SeqAccess, Visitor};

    struct RangeVisitor;

    impl<'de> Visitor<'de> for RangeVisitor {
        type Value = Option<RangeInclusive<usize>>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("An integer or two-element array of integers")
        }

        fn visit_none<E>(self) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(value as usize..=value as usize))
        }

        fn visit_i64<E>(self, value: i64) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value < 0 {
                return Err(E::custom("Negative value for range"));
            }
            Self::visit_u64(self, value as u64)
        }

        fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let start = seq
                .next_element()?
                .ok_or_else(|| A::Error::custom("Expected start of range"))?;
            let end = seq
                .next_element()?
                .ok_or_else(|| A::Error::custom("Expected end of range"))?;

            let extra = seq.next_element::<usize>();
            if extra.is_err() || extra.is_ok_and(|x| x.is_some()) {
                return Err(A::Error::custom("Expected only two elements in range"));
            }
            if start > end {
                return Err(A::Error::custom(
                    "Start of range must be less than or equal to end",
                ));
            }
            Ok(Some(start..=end))
        }
    }

    deserializer.deserialize_any(RangeVisitor)
}

/// The type of validation to generate for the symbol.
///
/// Maps to the [ValidationType](crate::file::ValidationType) in the auxiliary file.
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Validation {
    /// There is no validation for this symbol.
    #[default]
    #[serde(rename = "none")]
    None,
    /// The symbol is validated not to be zero.
    #[serde(rename = "non zero")]
    NonZero,
    /// The symbol is validated to be a specific value.
    #[serde(rename = "content")]
    Content { content: Vec<u8> },
    /// The symbol's memory attributes are validated
    #[serde(rename = "mem attr")]
    MemAttr {
        memory_size: u64,
        must_have: u64,
        must_not_have: u64,
    },
    /// The symbol is validated to be equal to another symbol.
    #[serde(rename = "self")]
    Ref { reference: String },
    /// The symbol is validated to be a pointer, not null, and in or out of mseg.
    #[serde(rename = "pointer")]
    Pointer {
        #[serde(default)]
        in_mseg: bool,
    },
}

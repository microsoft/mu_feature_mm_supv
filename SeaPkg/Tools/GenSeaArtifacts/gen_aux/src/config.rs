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

use r_efi::efi::Guid;
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
    /// People associated with reviewing this rule.
    #[serde(
        default,
        rename = "reviewed-by",
        deserialize_with = "deserialize_reviewers"
    )]
    pub reviewers: Vec<String>,
    /// The date [YYYY-MM-DD] when the rule was last reviewed.
    #[serde(
        default,
        rename = "last-reviewed",
        deserialize_with = "deserialize_date"
    )]
    pub last_reviewed: String,
    /// Any additional remarks / context for the rule.
    #[serde(default)]
    pub remarks: String,
}

fn deserialize_date<'de, D>(deserializer: D) -> core::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Deserialize, Error};

    let date: String = String::deserialize(deserializer)?;

    // Validate the date format YYYY-MM-DD
    let Ok(re) = regex::Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$") else {
        return Err(D::Error::custom(
            "Failed to compile regex for date validation.",
        ));
    };

    if !re.is_match(&date) {
        return Err(D::Error::custom(
            "Invalid date format. Expected YYYY-MM-DD.",
        ));
    }
    Ok(date)
}

fn deserialize_reviewers<'de, D>(deserializer: D) -> core::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Deserialize, Error};

    let reviewers: Vec<String> = Vec::deserialize(deserializer)?;
    let Ok(re) = regex::Regex::new(r"^[A-Z][a-z]+ [A-Z][a-z]+ <[^<>@]+@[^<>@]+\.[^<>@]+>$") else {
        return Err(D::Error::custom(
            "Failed to compile regex for reviewer validation.",
        ));
    };

    for reviewer in &reviewers {
        if !re.is_match(reviewer) {
            return Err(D::Error::custom(
                "Invalid reviewer format. Expected `[F]irst [L]ast <email>`.",
            ));
        }
    }

    Ok(reviewers)
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
    /// The symbol is validated against a GUID as a Content rule.
    #[serde(rename = "guid")]
    Guid {
        /// The GUID to validate against.
        #[serde(
            deserialize_with = "deserialize_guid",
            serialize_with = "serialize_guid"
        )]
        guid: Guid,
    },
}

/// A custom deserializer for a [Guid].
fn deserialize_guid<'de, D>(deserializer: D) -> core::result::Result<Guid, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use core::fmt;
    use serde::de::{Error, SeqAccess, Visitor};

    struct RangeVisitor;

    impl<'de> Visitor<'de> for RangeVisitor {
        type Value = Guid;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("A sequence of [u32, u16, u16 [u8; 8]]")
        }

        fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let f1: u32 = seq
                .next_element()?
                .ok_or_else(|| A::Error::custom("Expected index 0 to be u32"))?;
            let f2: u16 = seq
                .next_element()?
                .ok_or_else(|| A::Error::custom("Expected index 1 to be u16"))?;
            let f3: u16 = seq
                .next_element()?
                .ok_or_else(|| A::Error::custom("Expected index 2 to be u16"))?;
            let f4: [u8; 8] = seq
                .next_element()?
                .ok_or_else(|| A::Error::custom("Expected index 3 to be [u8; 8]"))?;

            Ok(Guid::from_fields(
                f1,
                f2,
                f3,
                f4[0],
                f4[1],
                &[f4[2], f4[3], f4[4], f4[5], f4[6], f4[7]],
            ))
        }
    }

    deserializer.deserialize_any(RangeVisitor)
}

/// A custom serializer for a `Guid` that outputs it as [u32, u16, u16, [u8; 8]]
fn serialize_guid<S>(guid: &Guid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeTuple;

    // Decompose the GUID into its fields
    let (data1, data2, data3, data4_0, data4_1, data4_tail) = guid.as_fields();

    // Reconstruct full [u8; 8] from (u8, u8, &[u8; 6])
    let mut data4 = [0u8; 8];
    data4[0] = data4_0;
    data4[1] = data4_1;
    data4[2..].copy_from_slice(data4_tail);

    let mut tuple = serializer.serialize_tuple(4)?;
    tuple.serialize_element(&data1)?;
    tuple.serialize_element(&data2)?;
    tuple.serialize_element(&data3)?;
    tuple.serialize_element(&data4)?;
    tuple.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_date_valid() {
        let date = "\"2023-10-01\"";
        let mut deserializer = serde_json::de::Deserializer::from_str(date);
        let result: Result<String, _> = deserialize_date(&mut deserializer);
        assert!(result.is_ok_and(|s| s == *"2023-10-01"));
    }

    #[test]
    fn test_deserialize_date_invalid_format_dd_mm_yyyy() {
        let data = "\"01-10-2023\"";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<String, _> = deserialize_date(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_date_invalid_month() {
        let data = "\"2025-13-01\"";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<String, _> = deserialize_date(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_date_completely_invalid() {
        let data = "\"invalid-date\"";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<String, _> = deserialize_date(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_date_not_a_string() {
        let data = "12345";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<String, _> = deserialize_date(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_date_invalid_day() {
        let data = "\"2025-12-32\"";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<String, _> = deserialize_date(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_range_valid() {
        let data = "[1, 5]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let range: Option<RangeInclusive<usize>> = deserialize_range(&mut deserializer).unwrap();
        assert_eq!(range, Some(1..=5));
    }

    #[test]
    fn test_deserialize_range_single_value() {
        let data = "3";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let range: Option<RangeInclusive<usize>> = deserialize_range(&mut deserializer).unwrap();
        assert_eq!(range, Some(3..=3));
    }

    #[test]
    fn test_deserialize_range_one_element() {
        let data = "[1]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<Option<RangeInclusive<usize>>, _> = deserialize_range(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_range_more_than_two_elements() {
        let data = "[1, 2, 3]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<Option<RangeInclusive<usize>>, _> = deserialize_range(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_range_elements_reversed() {
        let data = "[5, 1]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<Option<RangeInclusive<usize>>, _> = deserialize_range(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_range_elements_not_numbers() {
        let data = "[1, 'a']";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let result: Result<Option<RangeInclusive<usize>>, _> = deserialize_range(&mut deserializer);
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_guid() {
        let data = "[305419896,4660,22136,[18,52,86,120,154,188,222,240]]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let guid = deserialize_guid(&mut deserializer).unwrap();
        assert_eq!(
            guid.as_fields(),
            (
                0x12345678,
                0x1234,
                0x5678,
                0x12,
                0x34,
                &[0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
            )
        );
    }

    #[test]
    fn test_serialize_guid() {
        let guid = Guid::from_fields(
            0x12345678,
            0x1234,
            0x5678,
            0x12,
            0x34,
            &[0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        );
        let mut serializer = serde_json::ser::Serializer::new(Vec::new());
        assert!(serialize_guid(&guid, &mut serializer).is_ok());

        let string = String::from_utf8(serializer.into_inner()).unwrap();
        assert_eq!(
            string,
            "[305419896,4660,22136,[18,52,86,120,154,188,222,240]]"
        );
    }

    #[test]
    fn test_deserialize_reviewers_valid() {
        let data = "[\"John Doe <john.doe@example.com>\"]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let reviewers: Vec<String> = deserialize_reviewers(&mut deserializer).unwrap();
        assert_eq!(reviewers.len(), 1);
        assert_eq!(reviewers[0], "John Doe <john.doe@example.com>");
    }

    #[test]
    fn test_deserialize_multiple_reviewers_valid() {
        let data = "[\"John Doe <john.doe@example.com>\", \"Jane Smith <jane.smith@example.com>\"]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        let reviewers: Vec<String> = deserialize_reviewers(&mut deserializer).unwrap();
        assert_eq!(reviewers.len(), 2);
        assert_eq!(reviewers[0], "John Doe <john.doe@example.com>");
        assert_eq!(reviewers[1], "Jane Smith <jane.smith@example.com>");
    }

    #[test]
    fn test_deserialize_reviewers_invalid_format_missing_last() {
        let data = "[\"John <john.doe@example.com>\"]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        assert!(deserialize_reviewers(&mut deserializer).is_err());
    }

    #[test]
    fn test_deserialize_reviewers_invalid_format_too_many_names() {
        let data = "[\"John Doe Smith <john.doe.smith@example.com>\"]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        assert!(deserialize_reviewers(&mut deserializer).is_err());
    }

    #[test]
    fn test_deserialize_reviewers_invalid_format_missing_carrot() {
        let data = "[\"John Doe <john.doe@example.com\"]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        assert!(deserialize_reviewers(&mut deserializer).is_err());
    }

    #[test]
    fn test_deserialize_reviewers_invalid_format_bad_email() {
        let data = "[\"John Doe <john.doe.smithexample.com>\"]";
        let mut deserializer = serde_json::de::Deserializer::from_str(data);
        assert!(deserialize_reviewers(&mut deserializer).is_err());
    }

    #[test]
    fn test_from_file_valid() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("test")
            .join("example.toml");

        assert!(path.exists(), "Test file does not exist: {:?}", path);

        // Attempt to read the config file
        let result = ConfigFile::from_file(path);
        assert!(result.is_ok());

        // Check that removing rules by scope works
        let mut config = result.unwrap();
        let scopes = vec!["debug".to_string()];
        let rule_count = config.rules.len();
        config.filter_by_scopes(&scopes).unwrap();
        assert!(
            config.rules.len() < rule_count,
            "Expected some rules to be filtered out"
        );

        // Attempt to write the config file back to a temporary location
        let temp = tempfile::NamedTempFile::new().unwrap();
        let result = config.to_file(temp.path());
        assert!(result.is_ok());
    }
}

//! A module containing the definitions for the configuration file used to generate the auxiliary file.
use serde::{Serialize, Deserialize};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
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
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Key {
    /// The signature that tells the firmware what to do with the address.
    pub signature: [char; 4],
    /// The offset
    pub symbol: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The symbol that the rule is associated with.
    pub symbol: String,
    /// The field inside the symbol that the rule is associated with.
    pub field: Option<String>,
    /// The offset inside the symbol that the rule is associated with.
    pub offset: Option<u32>,
    /// The scope that the rule is associated with. If the rule has no scope, it is always applied.
    pub scope: Option<String>,
    /// If the symbol is an array, this configuration is applied to the symbol.
    pub array: Option<Array>,
    /// The type of validation to be performed on the symbol.
    pub validation: Validation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Array {
    /// The last index of the array is a sentinel value, thus creating a different validation rule for the last index.
    #[serde(default)]
    pub sentinel: bool,
    /// The index to apply the validation to, or all indexes if not set.
    pub index: Option<usize>,
}

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
    MemAttr { memory_size: u64, must_have: u64, must_not_have: u64 },
    /// The symbol is validated to be equal to another symbol.
    #[serde(rename = "self")]
    Ref { reference: String },
    /// The symbol is validated to be a pointer, not null, and in or out of mseg.
    #[serde(rename = "pointer")]
    Pointer {
        #[serde(default)]
        in_mseg: bool
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    #[test]
    fn can_we_parse_this() {
        let string = std::fs::read_to_string(r"C:\src\sea_release\BinaryReleasePkg\Config\LNL.sea.cfg").unwrap();
        let config: ConfigFile = toml::from_str(&string).unwrap();
    }
}
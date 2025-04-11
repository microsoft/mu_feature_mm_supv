//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//! 
use std::{collections::HashMap, path::PathBuf};
use pdb::FallibleIterator;

use clap::Parser;
use pdb::PDB;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use scroll::Pread;

pub mod auxgen;
pub mod util;
pub mod validation;
pub mod report;
pub mod type_info;

use auxgen::{Symbol, SymbolType, AuxBuilder};
use validation::{ValidationRule, ValidationType};
use report::CoverageReport;

pub const POINTER_LENGTH: u64 = 8;

/// Command line arguments for the Auxiliary File Generator.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Generate a config file with a failed validation entry for every symbol
    #[arg(long)]
    pub generate_config: bool,
    /// Path to the PDB file to parse.
    #[arg(short, long)]
    pub pdb: PathBuf,
    /// Path to the efi file to parse.
    #[arg(short, long)]
    pub efi: PathBuf,
    /// Path to the output auxillary file.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Path to the config file to read (or write to if generating a config).
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// A list of scopes to include in the auxiliary file. Rules without scopes
    /// are always applied. Rules with scopes are only applied if the scope is
    /// also provided via this argument.
    #[arg(short, long = "scope")]
    pub scopes: Vec<String>,
    // Display the parse Symbol information.
    #[arg(short, long)]
    pub debug: bool
}

/// A struct that represents an signature/address pair to be added to the
/// auxiliary file header.
#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct KeySymbol {
    /// The symbol name to calculate the offset of.
    pub symbol: Option<String>,
    /// The offset
    pub offset: Option<u32>,
    /// The signature that tells the firmware what to do with the address.
    signature: [char; 4],
}

impl KeySymbol {
    pub fn resolve(&mut self, symbols: &Vec<Symbol>) -> anyhow::Result<()> {
        if let Some(symbol) = symbols.iter().find(|&entry| &entry.name == self.symbol.as_ref().unwrap()) {
            self.offset = Some(symbol.address as u32);
        }

        if self.offset.is_none() {
            return Err(anyhow::anyhow!("Could not resolve offset for symbol {}.", self.symbol.as_ref().unwrap()))
        }
        Ok(())
    }

    pub fn signature(&self) -> u32 {
        let buffer = self.signature.iter().map(|&c| c as u8).collect::<Vec<u8>>();
        buffer.pread::<u32>(0).unwrap()
    }
}

impl std::fmt::Debug for KeySymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(offset) = &self.offset {
            write!(f, "KeySymbol {{ offset: 0x{:08X}, signature: 0x{:4X} }}", offset, self.signature())
        } else if let Some(symbol) = &self.symbol {
            write!(f, "KeySymbol {{ symbol: {}, signature: 0x{:4X} }}", symbol, self.signature())
        } else {
            write!(f, "KeySymbol {{ signature: 0x{:4X} }}", self.signature())
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// An option that if true, will generate a validation entry of 
    /// verification type NONE for every symbol without a rule in the config
    /// file.
    #[serde(default, alias = "AutoGen", alias = "autogen")]
    pub auto_gen: bool,
    /// An option that if true, will cause the generator to abort if any
    /// symbols are found that do not have a corresponding rule in the config
    #[serde(default, alias = "NoMissingRules")]
    pub no_missing_rules: bool,
    /// A list of symbols to exclude from including in the auxiliary file.
    #[serde(default, alias = "ExcludedSymbols")]
    pub excluded_symbols: Vec<String>,
}

/// Configuration options available in the config file.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(alias = "config", default = "Config::default")]
    pub config: Config,
    /// A list of key symbols to be added to the auxiliary file header.
    #[serde(alias = "key", default = "Vec::new")]
    pub key_symbols: Vec<KeySymbol>,
    /// A list of validation rules that ultimately create a validation entry in
    /// the auxiliary file.
    #[serde(alias = "rule", default = "Vec::new", rename = "rule")]
    pub rules: Vec<ValidationRule>,
}

pub fn main() -> Result<()> {
    let args = Args::parse();

    let file = std::fs::File::open(args.pdb)?;
    let mut pdb = PDB::open(file)?;

    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    let type_information = pdb.type_information()?;
    let debug_information = pdb.debug_information()?;
    let sections = pdb.sections()?.unwrap_or_default();
    let sections = sections.iter().map(|section| {
        let range = section.virtual_address..section.virtual_address + section.virtual_size;
        (range, section.characteristics)
    }).collect::<Vec<_>>();

    let mut raw_symbol_iter = symbol_table.iter();
    let mut parsed_symbols: HashMap<String, Symbol> = HashMap::new();
    
    // Add symbols from the individual modules
    let mut modules = debug_information.modules()?;
    while let Some(module) = modules.next()? {
        let module_info = pdb.module_info(&module)?.unwrap();
        let mut symbols = module_info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            util::add_symbol(&mut parsed_symbols, symbol, &address_map, &type_information, &*sections)?;
        }
    }

    // Add symbols from the global scope
    while let Some(symbol) = raw_symbol_iter.next()? {
        util::add_symbol(&mut parsed_symbols, symbol, &address_map, &type_information, &*sections)?;
    }
    if args.generate_config {
        let rules: Vec<ValidationRule> = parsed_symbols
            .values()
            .filter(|symbol| symbol.in_read_write_section())
            .map(|symbol| symbol.into())
            .collect();

        let config = ConfigFile {
            rules,
            ..Default::default()
        };

        let output = args.config.unwrap_or("config.toml".into());
        let config_string = toml::to_string(&config)?;
        std::fs::write(output, config_string)?;
    } else {
        let output = args.output.unwrap_or(args.efi.with_extension("aux"));
        let efi = std::fs::read(args.efi)?;
        let aux = AuxBuilder::default()
            .with_image(&efi)?
            .with_config(args.config)?
            .with_symbols(parsed_symbols.values().cloned().collect())
            .generate(&type_information, args.scopes)?;
    
        if args.debug {
            println!("{:?}", aux.header);
            for symbol in aux.key_symbols.iter() {
                println!("  {:?}", symbol);
            }
            for entry in aux.entries.iter() {
                println!("  {:?}", entry);
            }
        }

        let symbols: Vec<Symbol> = parsed_symbols.values().cloned().collect();
        let report = CoverageReport::build(&efi, &aux, &symbols)?;

        report.to_file(output.with_extension("json"))?;
        aux.to_file(output)?;
    }

    Ok(())
}

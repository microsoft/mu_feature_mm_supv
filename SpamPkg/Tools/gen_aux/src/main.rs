use std::{collections::HashMap, path::PathBuf};
use pdb::FallibleIterator;

use clap::Parser;
use pdb::PDB;
use anyhow::Result;
use serde::Deserialize;

pub mod auxgen;
pub mod util;
pub mod validation;

use auxgen::{Symbol, AuxBuilder};
use validation::{ValidationRule, ValidationType};

pub const POINTER_LENGTH: u64 = 8;

/// Command line arguments for the Auxillary File Generator.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Path to the PDB file to parse.
    #[arg(short, long)]
    pub pdb: PathBuf,
    /// Path to the efi file to parse.
    #[arg(short, long)]
    pub efi: PathBuf,
    /// Path to the output auxillary file.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Path to the config file.
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    // Display the parse Symbol information.
    #[arg(short, long)]
    pub debug: bool
}

/// A struct that represents an signature/address pair to be added to the
/// auxillary file header.
#[derive(Deserialize, Default)]
pub struct KeySymbol {
    /// The symbol name to calculate the offset of.
    pub symbol: Option<String>,
    /// The offset
    pub offset: Option<u32>,
    /// The signature that tells the firmware what to do with the address.
    pub signature: u32,
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
}

impl std::fmt::Debug for KeySymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(offset) = &self.offset {
            write!(f, "KeySymbol {{ offset: 0x{:08X}, signature: 0x{:4X} }}", offset, self.signature)
        } else if let Some(symbol) = &self.symbol {
            write!(f, "KeySymbol {{ symbol: {}, signature: 0x{:4X} }}", symbol, self.signature)
        } else {
            write!(f, "KeySymbol {{ signature: {} }}", self.signature)
        }
    }
}

/// Configuration options available in the config file.
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    /// A list of key symbols to be added to the auxillary file header.
    #[serde(alias = "key", default = "Vec::new")]
    pub key_symbols: Vec<KeySymbol>,
    /// A list of validation rules that ultimately create a validation entry in
    /// the auxillary file.
    #[serde(alias = "rule", default = "Vec::new")]
    pub rules: Vec<ValidationRule>,
    /// An option that if true, will generate a validation entry of 
    /// verification type NONE for every symbol without a rule in the config
    /// file.
    #[serde(default, alias = "AutoGen", alias = "autogen")]
    pub auto_gen: bool,
}

pub fn main() -> Result<()> {
    let args = Args::parse();

    let file = std::fs::File::open(args.pdb)?;
    let mut pdb = PDB::open(file)?;

    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    let type_information = pdb.type_information()?;
    let debug_information = pdb.debug_information()?;

    let mut raw_symbol_iter = symbol_table.iter();
    let mut parsed_symbols: HashMap<String, Symbol> = HashMap::new();
    
    // Add symbols from the individual modules
    let mut modules = debug_information.modules()?;
    while let Some(module) = modules.next()? {
        let module_info = pdb.module_info(&module)?.unwrap();
        let mut symbols = module_info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            util::add_symbol(&mut parsed_symbols, symbol, &address_map, &type_information)?;
        }
    }

    // Add symbols from the global scope
    while let Some(symbol) = raw_symbol_iter.next()? {
        util::add_symbol(&mut parsed_symbols, symbol, &address_map, &type_information)?;
    }

    let output = args.output.unwrap_or(args.efi.with_extension("aux"));
    let efi = std::fs::read(args.efi)?;
    let aux = AuxBuilder::default()
        .with_image(&efi)?
        .with_config(args.config)?
        .with_symbols(parsed_symbols.values().cloned().collect())
        .generate(&type_information)?;

    if args.debug {
        println!("{:?}", aux.header);
        for symbol in aux.key_symbols.iter() {
            println!("  {:?}", symbol);
        }
        for entry in aux.entries.iter() {
            println!("  {:?}", entry);
        }
    }

    aux.to_file(output)?;

    Ok(())
}

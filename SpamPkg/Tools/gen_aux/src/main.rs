use std::{collections::HashMap, path::PathBuf};
use pdb::FallibleIterator;

use clap::Parser;
use pdb::PDB;
use anyhow::Result;
use serde::Deserialize;

mod auxgen;
mod util;
mod validation;

use auxgen::{Symbol, AuxBuilder};
use validation::{ValidationRule, ValidationType};

const POINTER_LENGTH: u64 = 8;

/// Command line arguments for the Auxillary File Generator.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the PDB file to parse.
    #[arg(short, long)]
    pdb: PathBuf,
    /// Path to the efi file to parse.
    #[arg(short, long)]
    efi: PathBuf,
    /// Path to the output auxillary file.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Path to the config file.
    #[arg(short, long)]
    config: Option<PathBuf>,
    // Display the parse Symbol information.
    #[arg(short, long)]
    debug: bool
}

/// Configuration options available in the config file.
#[derive(Debug, Deserialize, Default)]
pub struct Config {
    /// A list of validation rules that ultimately create a validation entry in
    /// the auxillary file.
    #[serde(alias = "rule", default = "Vec::new")]
    rules: Vec<ValidationRule>,
    /// An option that if true, will generate a validation entry of 
    /// verification type NONE for every symbol without a rule in the config
    /// file.
    #[serde(default, alias = "AutoGen", alias = "autogen")]
    pub auto_gen: bool,
}

impl Config {
    /// Converts a list of validation rules into a map of validation rules
    /// indexed by the symbol name they are associated with.
    pub fn to_rule_map(self) -> HashMap<String, Vec<ValidationRule>> {
        let mut map = HashMap::new();
        for rule in self.rules.into_iter() {
            map.entry(rule.symbol.clone()).or_insert(Vec::new()).push(rule.clone());
        }
        map
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let file = std::fs::File::open(args.pdb)?;
    let mut pdb = PDB::open(file)?;

    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    let type_information = pdb.type_information()?;
    let debug_information = pdb.debug_information()?;

    let mut type_finder = type_information.finder();
    let mut iter = type_information.iter();
    while let Some(_) = iter.next()? {
        type_finder.update(&iter);
    }

    let mut raw_symbol_iter = symbol_table.iter();
    let mut parsed_symbols: HashMap<String, Symbol> = HashMap::new();
    
    // Add symbols from the individual modules
    let mut modules = debug_information.modules()?;
    while let Some(module) = modules.next()? {
        let module_info = pdb.module_info(&module)?.unwrap();
        let mut symbols = module_info.symbols()?;
        while let Some(symbol) = symbols.next()? {
            util::add_symbol(&mut parsed_symbols, symbol, &address_map, &type_finder)?;
        }
    }

    // Add symbols from the global scope
    while let Some(symbol) = raw_symbol_iter.next()? {
        util::add_symbol(&mut parsed_symbols, symbol, &address_map, &type_finder)?;
    }

    let output = args.output.unwrap_or(args.efi.with_extension("aux"));
    let efi = std::fs::read(args.efi)?;
    let aux = AuxBuilder::default()
        .with_image(&efi)?
        .with_config(args.config)?
        .with_symbols(parsed_symbols.values().cloned().collect())
        .generate(&type_finder)?;

    if args.debug {
        println!("{:?}", aux.header);
        for entry in aux.entries.iter() {
            println!("  {:?}", entry);
        }
    }

    aux.to_file(output)?;

    Ok(())
}

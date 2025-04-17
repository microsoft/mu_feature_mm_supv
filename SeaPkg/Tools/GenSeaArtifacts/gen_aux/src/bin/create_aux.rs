use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use auxfile::prelude::*;

#[derive(Parser, Debug)]
struct Args {
    /// Path to the PDB file to parse.
    #[arg(short, long)]
    pdb: PathBuf,
    /// Path to the efi file to parse.
    #[arg(short, long)]
    efi: PathBuf,
    /// Path to the output auxiliary file.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Path to the config file to read (or write to if generating a config).
    #[arg(short, long)]
    config: PathBuf,
    #[arg(short, long = "scope")]
    /// A list of scopes to include in the auxiliary file. Rules without scopes
    /// are always applied. Rules with scopes are only applied if the scope is
    /// also provided via this argument.
    scopes: Vec<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut metadata = PdbMetadata::new(args.pdb, args.efi.clone())?;

    let mut config: ConfigFile = ConfigFile::from_file(args.config)?;
    config.filter_by_scopes(&args.scopes)?;

    let mut aux = AuxFile::default();

    for key in config.keys.iter() {
        let key_symbol = metadata.build_key_symbol(key)?;
        aux.add_key_symbol(key_symbol);
    }

    for rule in config.rules.iter() {
        for (entry, default) in metadata.build_entries(rule)? {
            aux.add_entry(entry, &default);
        }
    }

    aux.finalize();

    let report = Coverage::build(&aux, &mut metadata)?;
    for data in metadata.create_padding_entries(&report)? {
        aux.add_entry(data.0, &data.1);
    }

    aux.finalize();
    let report = Coverage::build(&aux, &mut metadata)?;

    if config.config.no_missing_rules {
        let missing = report.segments(|s| !s.covered());
        if !missing.is_empty() {
            log::error!(
                "The following symbols are missing rules in the config file: {:#?}",
                missing
            );
            return Err(anyhow::anyhow!(
                "Missing rules in the config file. See the log for details."
            ));
        }
    }

    let output = args.output.unwrap_or(args.efi.with_extension("aux"));
    aux.to_file(&output)?;
    report.to_file(PathBuf::from(&output.with_extension("json")))?;
    Ok(())
}

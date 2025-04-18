use anyhow::Result;
use auxfile::prelude::*;
use clap::Parser;

use std::{io::Write, path::PathBuf};

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
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut metadata = PdbMetadata::new(args.pdb, args.efi.clone()).unwrap();
    let report = Coverage::build(&AuxFile::default(), &mut metadata)?;

    // Writing the config file with serde prints it ugly, so we do it manually
    let mut buffer = String::new();
    buffer.push_str("[config]\nno_missing_rules = true\n\n");
    for segment in report
        .segments(|s| !s.covered() && !s.symbol().is_empty())
        .iter()
    {
        buffer.push_str(&format!(
            "[[rule]]\nsymbol = \"{}\"\nvalidation.type = \"none\"\n\n",
            segment.symbol()
        ))
    }

    let file_path = args
        .output
        .unwrap_or_else(|| args.efi.with_extension("toml"));
    if file_path.exists() {
        return Err(anyhow::anyhow!(
            "Output file already exists: {}",
            file_path.display()
        ));
    }

    let mut file = std::fs::File::create(file_path)?;
    file.write_all(buffer.as_bytes())?;

    Ok(())
}

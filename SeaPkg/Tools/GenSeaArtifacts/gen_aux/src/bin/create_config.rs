use anyhow::Result;
use auxfile::prelude::*;
use clap::Parser;

use std::{fs::File, io::Write, path::PathBuf};

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
    /// Verbosity level. Can be used multiple times for increased verbosity.
    /// 0 = error, 1 = info, 2 = debug, 3 = trace.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let level = match args.verbose {
        0 => log::Level::Error,
        1 => log::Level::Info,
        2 => log::Level::Debug,
        _ => log::Level::Trace,
    };

    simple_logger::init_with_level(level)?;

    let mut metadata = PdbMetadata::<File>::new(args.pdb, args.efi.clone()).unwrap();
    let report = Coverage::build(&AuxFile::default(), &mut metadata)?;

    // Writing the config file with serde prints it ugly, so we do it manually
    let mut buffer = String::new();
    buffer.push_str("[config]\nno_missing_rules = true\n\n");
    for segment in report
        .segments(|s| !s.covered() && !s.symbol().is_empty())
        .iter()
    {
        buffer.push_str(&format!(
            "[[rule]]\nsymbol = \"{}\"\nvalidation.type = \"none\"\nlast_reviewed = \"{}\"\n\n",
            segment.symbol(),
            chrono::Local::now().format("%Y-%m-%d")
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

use std::{fs::File, path::PathBuf};

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
    /// Path to a linker map file, used to recover symbols the PDB file does not name.
    #[arg(short, long)]
    map: Option<PathBuf>,
    /// Path to the output auxiliary file.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Path to the config file to read (or write to if generating a config).
    #[arg(short, long)]
    config: PathBuf,
    /// A list of scopes to include in the auxiliary file. Rules without scopes
    /// are always applied. Rules with scopes are only applied if the scope is
    /// also provided via this argument.
    #[arg(short, long = "scope")]
    scopes: Vec<String>,
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

    let mut metadata = PdbMetadata::<File>::new(args.pdb, args.efi.clone())?;
    if let Some(map) = args.map {
        metadata.add_map_symbols(&std::fs::read_to_string(map)?);
    }

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
            log::error!("The following regions are not covered by any rule:");
            for segment in missing.iter() {
                let size = segment.end() - segment.start();
                if segment.symbol().is_empty() {
                    // Nothing names this region, so report what it holds. A region that is not
                    // zero is not padding, whatever the absence of a name might suggest.
                    let content = metadata
                        .loaded_image_range(segment.start(), segment.end())
                        .map(|bytes| {
                            bytes
                                .iter()
                                .take(16)
                                .map(|byte| format!("{:02X}", byte))
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_default();
                    log::error!(
                        "  [{:#x}..{:#x}] ({:#x} bytes) is named by neither the PDB file nor the \
                         linker map, and holds [{}{}]. Add a rule for the symbol that owns it; if \
                         the PDB file does not name it, supply a linker map with `--map`.",
                        segment.start(),
                        segment.end(),
                        size,
                        content,
                        if size > 16 { " ..." } else { "" }
                    );
                } else {
                    log::error!(
                        "  [{:#x}..{:#x}] ({:#x} bytes) {}",
                        segment.start(),
                        segment.end(),
                        size,
                        segment.symbol()
                    );
                }
            }
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

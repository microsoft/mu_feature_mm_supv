use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use aux_file::{aux_file::AuxFile, config::ConfigFile, metadata::PdbMetadata, report2::CoverageReport};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    pdb: PathBuf,
    #[arg(short, long)]
    config: PathBuf,
    #[arg(short, long)]
    efi: PathBuf,
    #[arg(short, long = "scope")]
    scopes: Vec<String>,
}

fn main() -> Result<()> {

    let args = Args::parse();

    let mut metadata = PdbMetadata::new(args.pdb, args.efi)?;

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

    let report = CoverageReport::build(&aux, &mut metadata)?;
    for data in metadata.build_padding_entries(&report)? {
        aux.add_entry(data.0, &data.1);
    }

    aux.finalize();
    let report = CoverageReport::build(&aux, &mut metadata)?;

    if config.config.no_missing_rules {
        let missing = report.segments(|s| !s.covered());
        if !missing.is_empty() {
            println!("The following symbols are missing rules in the config file: {:#?}", missing);
            log::error!("The following symbols are missing rules in the config file: {:#?}", missing);
            return Err(anyhow::anyhow!("Missing rules in the config file. See the log for details."));
        }
    }

    aux.to_file(PathBuf::from("C:\\src\\sea_release\\Feature\\MM_SUPV\\SeaPkg\\Tools\\GenSeaArtifacts\\gen_aux\\aux.bin"))?;

    report.to_file(PathBuf::from("C:\\src\\sea_release\\Feature\\MM_SUPV\\SeaPkg\\Tools\\GenSeaArtifacts\\gen_aux\\report.json"))?;
    Ok(())
}

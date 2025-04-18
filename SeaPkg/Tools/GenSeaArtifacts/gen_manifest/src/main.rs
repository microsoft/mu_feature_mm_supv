mod manifest_v1;

use anyhow::{anyhow, Result};
use std::{io::Write, path::PathBuf};

use clap::Parser;
use manifest_v1::Algorithm;
use scroll::Pwrite;

#[derive(Debug, Parser)]
/// A Tool to generate a Manifest for verifying the STM firmware binary file.
struct Args {
    /// The path to the STM firmware binary file.
    #[clap(default_value = "stm.bin")]
    file: PathBuf,
    /// The version of the STM firmware binary file. A pre-release tag will override svn to 0.
    #[clap(long, default_value = "0.0.1")]
    sea_version: String,
    /// The output path for the generated Rust code.
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// The algorithm to use for the manifest.
    #[clap(short, long, default_value = Algorithm::all(), value_delimiter = ',')]
    algorithm: Vec<manifest_v1::Algorithm>,

    /// The Security Version Number.
    #[clap(long, default_value = "0")]
    security_version: u64,

    /// Prints the format of the manifest and exits.
    #[clap(long, default_value = "false")]
    format: bool,

    /// The version of the manifest.
    #[clap(short, long, default_value = "1.0")]
    manifest_version: String,
}

enum Manifest {
    V1(manifest_v1::SeaManifestV1),
}

impl Manifest {
    fn write(&self, output: PathBuf) -> Result<()> {
        let buffer = match self {
            Self::V1(manifest) => {
                let mut buffer = vec![0; manifest.size()];
                buffer.gwrite_with(manifest, &mut 0, scroll::LE)?;
                buffer
            }
        };

        let mut file = std::fs::File::create(output)?;
        file.write_all(&buffer)?;

        Ok(())
    }
}

fn parse_manifest_version(version: &str) -> Result<(u16, u16)> {
    let mut iter = version.split('.');

    let major = iter
        .next()
        .ok_or_else(|| anyhow!("Invalid manifest version."))?
        .parse::<u16>()
        .map_err(|err| anyhow!("Failed to parse major version: [{}] Err: {}", version, err))?;
    let minor = iter
        .next()
        .unwrap_or("0")
        .parse::<u16>()
        .map_err(|err| anyhow!("Failed to parse minor version: [{}], Err: {}", version, err))?;

    if iter.next().is_some() {
        return Err(anyhow!(
            "Manifest version does not support patch level: [{}]",
            version
        ));
    }

    Ok((major, minor))
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (manifest_version_major, manifest_version_minor) =
        parse_manifest_version(&args.manifest_version)?;

    if args.format {
        match manifest_version_major {
            1 => println!("{}", manifest_v1::MANIFEST_V1_FORMAT),
            _ => println!("Unknown manifest version."),
        }
        return Ok(());
    }

    if !args.file.exists() {
        return Err(anyhow!("File [{}] does not exist.", &args.file.display()));
    }

    let manifest = match manifest_version_major {
        1 => Manifest::V1(manifest_v1::SeaManifestV1::build(
            args.file,
            manifest_version_minor,
            args.sea_version,
            args.security_version,
            args.algorithm,
        )?),
        _ => return Err(anyhow!("Unknown manifest version.")),
    };

    manifest.write(args.output.unwrap_or_else(|| PathBuf::from("manifest.bin")))?;

    Ok(())
}

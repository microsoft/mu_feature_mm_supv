use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use coswid_core::*;
use digest::Digest;
use std::path::PathBuf;

const STM_BIN_GUID: &str = "C7600D63-09A2-4A30-A105-DAA22DE2D0FE";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a RIM for the STM firmware binary file
    Generate(GenerateArgs),
    /// Generates the structure that needs to be signed
    Signing(SigningArgs),
}

#[derive(Parser)]
struct GenerateArgs {
    /// The path to the STM firmware binary file, or the RIM file to update if --update_signature is used.
    file: PathBuf,
    /// Software Creator company name
    #[arg(long)]
    company_name: Option<String>,
    /// Software Creator company URL
    #[arg(long)]
    company_url: Option<String>,
    /// Generates a new RIM from an existing RIM, updating the signature value
    #[arg(short, long, default_value = "false")]
    update_signature: bool,
    /// The version of the STM firmware binary file
    #[arg(short, long, default_value = "0.0.1")]
    rim_version: String,
    /// A binary file where the bytes are the signature to use
    #[arg(short, long)]
    signature: Option<PathBuf>,
    /// The output path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Parser)]
struct SigningArgs {
    /// The path to the STM firmware binary file, or the RIM file to use for signing
    file: PathBuf,
    /// Software Creator company name
    #[arg(long)]
    company_name: Option<String>,
    /// Software Creator company URL
    #[arg(long)]
    company_url: Option<String>,
    /// The version of the STM firmware binary file
    #[arg(short, long, default_value = "0.0.1")]
    rim_version: String,
    /// Generate the structure that needs to be signed from an existing RIM file
    #[arg(short, long, default_value = "false")]
    from_rim: bool,
    /// The output path
    #[arg(short, long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate(args) => generate_rim(args)?,
        Commands::Signing(args) => generate_signing(args)?,
    }

    Ok(())
}

/// Generates a RIM for the STM from the provided STM binary file, or updates an existing RIM file with a new signature.
fn generate_rim(args: GenerateArgs) -> Result<()> {
    // If the --update_signature flag is set, the provided file is a RIM file that needs to be updated
    if args.update_signature {
        let Some(signature) = args.signature else {
            return Err(anyhow!(
                "--signature is required when using --update-signature"
            ));
        };

        let bytes = std::fs::read(&args.file)?;
        let mut rim = minicbor::decode::<CoseSign1<ConciseSwidTag<Vec<FileMeasurement>>>>(&bytes)
            .map_err(|e| anyhow!(e))?;
        rim.signature = std::fs::read(&signature)?.into();

        let mut buffer = Vec::new();
        minicbor::encode(&rim, &mut buffer).map_err(|e| anyhow!(e))?;
        std::fs::write(args.output.unwrap_or(args.file), buffer)?;
        return Ok(());
    }

    // Generate the STM measurements
    let measurements = generate_measurements(&args.file)?;
    let (Some(company_name), Some(company_url)) = (args.company_name, args.company_url) else {
        return Err(anyhow!("--company-name and --company-url are required"));
    };

    // Generate the RIM
    let cosesign1_payload: ConciseSwidTag<Vec<FileMeasurement>> =
        ConciseSwidTag::new(STM_BIN_GUID, 0, format!("{} STM Binary", company_url))
            .with_software_version(args.rim_version)
            .with_version_scheme("1")
            .with_software_meta(SoftwareMetaEntry::new().with_product("STM Binary"))
            .with_entity(
                EntityEntry::new(company_name)
                    .with_reg_id(company_url)
                    .with_role("tag-creator")
                    .with_reg_id("software-creator"),
            )
            .with_payload(measurements);

    let signature = match args.signature {
        Some(path) => std::fs::read(&path)?,
        None => vec![0xFF, 0xFF],
    };

    let cosesign1: CoseSign1<ConciseSwidTag<Vec<FileMeasurement>>> = CoseSign1::new(
        ProtectedHeader::new(-39, "application/swid+cbor"),
        UnprotectedHeader::new(),
        cosesign1_payload,
        signature,
    );

    // Write the RIM to a file
    let mut buffer = Vec::new();
    minicbor::encode(&cosesign1, &mut buffer).map_err(|e| anyhow!(e))?;
    std::fs::write(args.output.unwrap_or(PathBuf::from("RIM.bin")), buffer)?;
    Ok(())
}

fn generate_signing(args: SigningArgs) -> Result<()> {
    if args.from_rim {
        let bytes = std::fs::read(&args.file).unwrap();
        let rim = minicbor::decode::<CoseSign1<ConciseSwidTag<Vec<FileMeasurement>>>>(&bytes)
            .map_err(|e| anyhow!(e))?;

        let sig_structure: SigStructure<ConciseSwidTag<Vec<FileMeasurement>>> =
            SigStructure::new(rim.payload.0, rim.protected.0);
        let mut buffer = Vec::new();
        minicbor::encode(&sig_structure, &mut buffer).map_err(|e| anyhow!(e))?;
        std::fs::write(args.output, buffer)?;
        return Ok(());
    }

    let measurements = generate_measurements(&args.file)?;
    let (Some(company_name), Some(company_url)) = (args.company_name, args.company_url) else {
        return Err(anyhow!("--company-name and --company-url are required"));
    };

    let cosesign1_payload: ConciseSwidTag<Vec<FileMeasurement>> =
        ConciseSwidTag::new(STM_BIN_GUID, 0, format!("{} STM Binary", company_url))
            .with_software_version(args.rim_version)
            .with_version_scheme("1")
            .with_software_meta(SoftwareMetaEntry::new().with_product("STM Binary"))
            .with_entity(
                EntityEntry::new(company_name)
                    .with_reg_id(company_url)
                    .with_role("tag-creator")
                    .with_reg_id("software-creator"),
            )
            .with_payload(measurements);

    let sig_structure: SigStructure<ConciseSwidTag<Vec<FileMeasurement>>> = SigStructure::new(
        cosesign1_payload,
        ProtectedHeader::new(-39, "application/swid+cbor"),
    );
    let mut buffer = Vec::new();
    minicbor::encode(&sig_structure, &mut buffer).map_err(|e| anyhow!(e))?;
    std::fs::write(args.output, buffer)?;
    Ok(())
}

fn generate_measurements(file: &PathBuf) -> Result<Vec<FileMeasurement>> {
    // https://www.iana.org/assignments/named-information/named-information.xhtml
    const SHA256_ID: i16 = 1; // Standard
    const SHA384_ID: i16 = 7; // Standard
    const SHA512_ID: i16 = 8; // Standard
    const SM3_ID: i16 = 30; // Not Standard

    if !file.exists() {
        return Err(anyhow!("Path does not exist: {:?}", file));
    }
    if !file.is_file() {
        return Err(anyhow!("Path is not a file: {:?}", file));
    }
    let file_len = file.metadata()?.len();
    let file_name = file.file_name().expect("Is a File").to_string_lossy();
    Ok(vec![
        FileMeasurement::new(
            file_name.clone(),
            "ALGO_SHA256",
            file_len,
            SHA256_ID,
            hash_file::<sha2::Sha256>(file)?,
        ),
        FileMeasurement::new(
            file_name.clone(),
            "ALGO_SHA384",
            file_len,
            SHA384_ID,
            hash_file::<sha2::Sha384>(file)?,
        ),
        FileMeasurement::new(
            file_name.clone(),
            "ALGO_SHA512",
            file_len,
            SHA512_ID,
            hash_file::<sha2::Sha512>(file)?,
        ),
        FileMeasurement::new(
            file_name.clone(),
            "ALGO_SM3",
            file_len,
            SM3_ID,
            hash_file::<sm3::Sm3>(file)?,
        ),
    ])
}

fn hash_file<D: Digest>(file: &PathBuf) -> Result<Vec<u8>> {
    Ok(D::digest(std::fs::read(file)?).to_vec())
}

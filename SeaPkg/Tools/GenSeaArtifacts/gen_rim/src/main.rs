//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use anyhow::{anyhow, Result};
use clap::Parser;
use coswid_core::*;
use digest::Digest;
use std::{io::Write, path::PathBuf};

const STM_BIN_GUID: &str = "C7600D63-09A2-4A30-A105-DAA22DE2D0FE";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
/// Generates measurement hashes for the STM firmware binary file and wraps it in a swid+cbor RIM
/// containing the following hashes: SHA256, SHA384, SHA512, SM3-256.
struct Args {
    /// Path to the STM firmware binary file to be measured
    pub file: PathBuf,
    /// Version of the STM firmware binary file
    #[arg(short, long)]
    pub rim_version: Option<String>,
    /// Path to place the generated RIM file. Defaults to the current directory.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    /// Company name for registering the Software Creator in the RIM
    pub company_name: String,
    /// Company URL for registering the Software Creator in the RIM
    #[arg(long)]
    pub company_url: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let measurement_payloads = generate_measurements(&args.file)?;

    let cosesign1_payload: ConciseSwidTag<(), Vec<FileMeasurement>> =
        ConciseSwidTag::new(STM_BIN_GUID, 0, format!("{} STM Binary", args.company_url))
            .with_software_version(args.rim_version.unwrap_or("1.0.0".to_string()))
            .with_version_scheme("1")
            .with_software_meta(SoftwareMetaEntry::new().with_product("STM Binary"))
            .with_entity(
                EntityEntry::new(args.company_name)
                    .with_reg_id(args.company_url)
                    .with_role("tag-creator")
                    .with_reg_id("software-creator"),
            )
            .with_payload(measurement_payloads);

    let cosesign1: CoseSign1<(), ConciseSwidTag<(), Vec<FileMeasurement>>> = CoseSign1::new(
        ProtectedHeader::new(-39, "application/swid+cbor"),
        UnprotectedHeader::new(),
        cosesign1_payload,
        "F".repeat(256),
    );

    let mut buffer = Vec::new();
    minicbor::encode(&cosesign1, &mut buffer).unwrap();
    let mut file = std::fs::File::create(args.output.unwrap_or(PathBuf::from("RIM.bin"))).unwrap();
    file.write_all(&buffer).unwrap();
    Ok(())
}

fn generate_measurements(file: &PathBuf) -> Result<Vec<FileMeasurement>> {
    const SHA256_ID: i16 = 18556 + 5; // Standard
    const SHA384_ID: i16 = 18556 + 6; // Standard
    const SHA512_ID: i16 = 18556 + 7; // Standard
    const SM3_ID: i16 = 18556 + 30; // Not Standard

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

fn hash_file<D: Digest>(file: &PathBuf) -> Result<String> {
    Ok(hex::encode(D::digest(std::fs::read(file)?)))
}

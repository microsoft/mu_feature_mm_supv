//! A binary for building and testing an auxiliary file against a dumped MM Supervisor core.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
#![feature(c_variadic)]

mod efi;

use anyhow::{anyhow, Result};
use auxfile::{
    config::ConfigFile,
    file::{AuxFile, ImageValidationEntryHeader, ValidationType},
    prelude::PdbMetadata,
    report::Coverage,
};
use clap::Parser;
use efi::{set_debug_print, PrettyStatus};
use r_efi::efi::Status;
use scroll::{Pwrite, LE};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use std::{
    ffi::c_void,
    fmt::Write,
    io::Cursor,
    path::{Path, PathBuf},
};

const MM_SUPV_PDB: &[u8] = include_bytes!(env!("TEST_AUX_MM_SUPERVISOR_CORE_PDB_PATH"));
const MM_SUPV_EFI: &[u8] = include_bytes!(env!("TEST_AUX_MM_SUPERVISOR_CORE_EFI_PATH"));

// The external function signatures for the BasePeCoffValidationLib
extern "C" {
    fn PeCoffImageValidationNonZero(target_image: *const c_void, hdr: *const c_void) -> Status;
    fn PeCoffImageValidationContent(
        target_image: *const c_void,
        hdr: *const c_void,
        aux: *const c_void,
    ) -> Status;
    // fn PeCoffImageValidationMemAttr(target_image: *const c_void, hdr: *const c_void, pt_base: u64) -> Status;
    fn PeCoffImageValidationSelfRef(
        target_image: *const c_void,
        hdr: *const c_void,
        address: u64,
    ) -> Status;
    fn PeCoffImageValidationPointer(
        target_image: *const c_void,
        hdr: *const c_void,
        mseg_base: u64,
        mseg_size: u64,
    ) -> Status;
}

/// A Command line tool to test a auxiliary file against a dumped MM Supervisor core.
#[derive(Parser)]
struct Args {
    /// Path to the config file to use to generate the auxiliary file
    #[arg(short, long)]
    aux_config: PathBuf,
    /// Path to the config file for this tool
    #[arg(short, long)]
    config: PathBuf,
    /// 0..n scopes used to filter validation rules on for the the auxiliary file generation.
    #[arg(name = "scope", short, long)]
    scopes: Vec<String>,
}

/// A structure representing all configuration data dumped from the run log.
#[derive(Deserialize)]
struct CmdConfig {
    /// The MSEG base address
    #[serde(rename = "MsegBase")]
    pub mseg_base: String,
    /// The MSEG size
    #[serde(rename = "MsegSize")]
    pub mseg_size: String,
    /// The LoadAddress of the MmSupervisorCore.efi
    #[serde(rename = "MmSupervisorBase")]
    pub mm_supv_address: String,
    /// The dump of the post-execution MM Supervisor core
    #[serde(rename = "MmSupervisor")]
    pub mm_supv_core: String,
}

impl CmdConfig {
    /// Creates a new instance of CmdConfig from the provided file path.
    pub fn from_file(file_path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(file_path)?;
        let config: CmdConfig = toml::from_str(contents.as_str())?;
        Ok(config)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.aux_config.exists() {
        return Err(anyhow!("Auxiliary config file does not exist."));
    }

    if !args.config.exists() {
        return Err(anyhow!("Config file does not exist."));
    }

    let (aux, metadata) = build_aux(&args.aux_config, &args.scopes)?;

    let test_suite = TestSuite::new(&args.config, aux.to_bytes()?)?;

    display_test_information(&args.aux_config, &test_suite);

    let tests = aux
        .entries
        .iter()
        .map(|entry| {
            let name = metadata
                .context_from_address(&entry.offset)
                .map(|c| c.name.clone())
                .unwrap_or("Padding".to_string());
            (name, entry)
        })
        .collect::<Vec<_>>();

    let results = test_suite.run_tests(&tests, false)?;

    let results = results
        .into_iter()
        .zip(tests)
        .map(|(status, (name, entry))| (name, entry, status))
        .collect::<Vec<_>>();

    display_results_summary(&results);

    display_results_table(&results);

    let failed = results
        .into_iter()
        .filter_map(|(name, hdr, result)| {
            if result != Status::SUCCESS {
                Some((name, hdr))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if !failed.is_empty() {
        println!("\nFailed Test Details:");
        test_suite.run_tests(&failed, true)?;
    }

    Ok(())
}

/// The metadata necessary to properly execute all validation tests.
struct TestSuite {
    /// The address that MSEG starts at
    mseg_base: u64,
    /// The size of the MSEG
    mseg_size: u64,
    /// The address the MmSupervisorCore.efi was loaded at at runtime.
    mm_supv_address: u64,
    /// The byte dump of the post-execution MM Supervisor core
    mm_supv_core: Vec<u8>,
    /// The byte dump of the generated auxiliary file
    aux: Vec<u8>,
}

impl TestSuite {
    /// Creates a new instance of TestSuite from the provided configuration file and auxiliary file.
    pub fn new(config: &PathBuf, aux: Vec<u8>) -> Result<Self> {
        let config = CmdConfig::from_file(config)?;
        let mm_supv_address = Self::from_hex_str(&config.mm_supv_address)?;
        let mm_supv_core = Self::process_mm_supv_core(&config.mm_supv_core)?;
        let mseg_base = Self::from_hex_str(&config.mseg_base)?;
        let mseg_size = Self::from_hex_str(&config.mseg_size)?;

        Ok(Self {
            mseg_base,
            mseg_size,
            mm_supv_address,
            mm_supv_core,
            aux,
        })
    }

    /// Runs the tests against the auxiliary file.
    fn run_tests(
        &self,
        tests: &[(String, &ImageValidationEntryHeader)],
        verbose: bool,
    ) -> Result<Vec<Status>> {
        let mut results = Vec::new();
        for (name, entry) in tests {
            if verbose {
                println!("\nTest [START]");
                println!("  Symbol Name: {}", name);
                println!("  Symbol Offset: {:#x}", entry.offset);
                println!("  Symbol Size: {:#x}", entry.size);
                println!("  Validation Type: {:?}", entry.validation_type);
                println!("\n---- Test Log Dump [START] ----");
            }
            let status = self.run_test(entry, verbose)?;
            if verbose {
                println!("\n---- Test Log Dump [END] ----\n");
                println!("  Status: {}", PrettyStatus(status));
                println!("Test [END]");
            }
            results.push(status);
        }
        Ok(results)
    }

    /// Processes a string representation of a hexadecimal number
    fn from_hex_str(value: &str) -> Result<u64> {
        let value = value.to_lowercase();
        let value = value.strip_prefix("0x").unwrap_or(&value);
        u64::from_str_radix(value, 16)
            .map_err(|_| anyhow!("Invalid load address format: {}", value))
    }

    /// Processes the core dump and extracts the bytes from it.
    fn process_mm_supv_core(dump: &str) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for line in dump.lines() {
            bytes.extend(Self::extract_bytes(line)?);
        }

        Ok(bytes)
    }

    /// Extracts the bytes from the provided line.
    ///
    /// The line is expected to be in the format of:
    /// 15:38:58.981 :     0003EEE0: 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  *................*
    fn extract_bytes(line: &str) -> Result<Vec<u8>> {
        let parts: Vec<&str> = line.split(":").collect();
        if parts.len() < 3 {
            return Err(anyhow!("Invalid line format: {}", line));
        }

        // Remaining part after this line:
        // 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  *................*
        let target = parts[4].trim();

        // Remaining part after this line:
        // 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        let target = target
            .split('*')
            .next()
            .unwrap_or("")
            .trim()
            .replace('-', " ");

        let bytes: Vec<u8> = target
            .split_whitespace()
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if bytes.len() != 16 {
            return Err(anyhow!("Invalid line format: {}", line));
        }

        Ok(bytes)
    }

    /// Runs a single test against the auxiliary file.
    fn run_test(&self, test: &ImageValidationEntryHeader, verbose: bool) -> Result<Status> {
        // Find the header in the aux file
        let mut bytes = vec![0; test.header_size() as usize];
        bytes.pwrite_with(test, 0, LE)?;

        let index = self
            .aux
            .windows(bytes.len())
            .position(|window| window == bytes)
            .ok_or(anyhow!("Header not found in aux file"))?;

        let aux = self.aux.as_ptr() as *const c_void;
        let hdr = unsafe { aux.add(index) };
        let target_image = self.mm_supv_core.as_ptr() as *const c_void;
        let mm_supv_address = self.mm_supv_address;
        let mseg_base = self.mseg_base;
        let mseg_size = self.mseg_size;

        set_debug_print(verbose);

        Ok(match test.validation_type {
            ValidationType::None => Status::SUCCESS,
            ValidationType::NonZero => unsafe { PeCoffImageValidationNonZero(target_image, hdr) },
            ValidationType::Content { .. } => unsafe {
                PeCoffImageValidationContent(target_image, hdr, aux)
            },
            ValidationType::Ref { .. } => unsafe {
                PeCoffImageValidationSelfRef(target_image, hdr, mm_supv_address)
            },
            ValidationType::Pointer { .. } => unsafe {
                PeCoffImageValidationPointer(target_image, hdr, mseg_base, mseg_size)
            },
            _ => Status::SUCCESS, // Skip PeCoffImageValidationMemAttr for now
        })
    }
}

/// Builds the auxiliary file based off the provided configuration file.
pub fn build_aux(
    config: &PathBuf,
    scopes: &[String],
) -> Result<(AuxFile, PdbMetadata<'static, Cursor<&'static [u8]>>)> {
    let mut metadata = PdbMetadata::<Cursor<&'static [u8]>>::new(MM_SUPV_PDB, MM_SUPV_EFI)?;
    let mut config = ConfigFile::from_file(config)?;
    config.filter_by_scopes(scopes)?;

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
    for (entry, raw_data) in metadata.create_padding_entries(&report)? {
        aux.add_entry(entry, &raw_data);
    }

    aux.finalize();

    Ok((aux, metadata))
}

/// Prints information about the test scenario.
fn display_test_information(aux_path: &Path, test_suite: &TestSuite) {
    println!("Test Information:");
    println!(
        "  MmSupervisor Load Address: 0x{:0X}",
        test_suite.mm_supv_address
    );
    println!("  Aux Config: {}", aux_path.display());
    println!(
        "  MmSupervisorCore.efi SHA256: {}",
        Sha256::digest(MM_SUPV_EFI)
            .to_vec()
            .iter()
            .fold(String::new(), |mut output, b| {
                let _ = write!(output, "{:02X}", b);
                output
            })
    );
    println!(
        "  MmSupervisorCore.pdb SHA256: {}",
        Sha256::digest(MM_SUPV_PDB)
            .to_vec()
            .iter()
            .fold(String::new(), |mut output, b| {
                let _ = write!(output, "{:02X}", b);
                output
            })
    );
}

/// Displays the results summary.
fn display_results_summary(results: &[(String, &ImageValidationEntryHeader, Status)]) {
    let failed = results
        .iter()
        .filter(|(_, _, result)| *result != Status::SUCCESS)
        .count();
    let passed = results.len() - failed;

    println!("\nTest Results (Summary):");
    println!("  Failed: {}", failed);
    println!("  Passed: {}", passed);
    println!("  Total Executed: {}\n", results.len());
}

/// Displays the results table.
fn display_results_table(results: &[(String, &ImageValidationEntryHeader, Status)]) {
    // Calculate the max width of each column
    let c1 = results.iter().map(|(s, _, _)| s.len()).max().unwrap_or(0);
    let c2 = "Offset".len().max(
        results
            .iter()
            .map(|(_, entry, _)| format!("0x{:X}", entry.offset).len())
            .max()
            .unwrap_or(0),
    );
    let c3 = "Size".len().max(
        results
            .iter()
            .map(|(_, entry, _)| format!("0x{:X}", entry.size).len())
            .max()
            .unwrap_or(0),
    );
    let c4 = "Test Type".len().max(
        results
            .iter()
            .map(|(_, entry, _)| entry.validation_type.to_string().len())
            .max()
            .unwrap_or(0),
    );
    let c5 = "Status".len().max(
        results
            .iter()
            .map(|(_, _, s)| PrettyStatus(*s).to_string().len())
            .max()
            .unwrap_or(0),
    );

    // print the table
    println!(
        "| {:c1$} | {:c2$} | {:c3$} | {:c4$} | {:c5$} |",
        "Name", "Offset", "Size", "Test Type", "Status"
    );
    println!(
        "| {:-<c1$} | {:-<c2$} | {:-<c3$} | {:-<c4$} | {:-<c5$} |",
        "", "", "", "", ""
    );
    for (name, hdr, result) in results {
        let status = PrettyStatus(*result).to_string();
        let test_type = hdr.validation_type.to_string();
        let offset = format!("0x{:X}", hdr.offset);
        let size = format!("0x{:X}", hdr.size);
        println!(
            "| {:c1$} | {:c2$} | {:c3$} | {:c4$} | {:c5$} |",
            name, offset, size, test_type, status
        );
    }
    println!(
        "| {:-<c1$} | {:-<c2$} | {:-<c3$} | {:-<c4$} | {:-<c5$} |",
        "", "", "", "", ""
    );
}

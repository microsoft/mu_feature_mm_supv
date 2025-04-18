//! A crate for generating an auxiliary file for post image execution validation of firmware images.
//!
//! This crate consists of several modules that work together to extract information from the PDB file and transform
//! it into a validation file using a configuration file.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
pub mod config;
pub mod file;
pub mod metadata;
pub mod report;

/// A prelude module that re-exports commonly used types and functions from the crate.
pub mod prelude {
    pub use crate::config::ConfigFile;
    pub use crate::file::AuxFile;
    pub use crate::metadata::PdbMetadata;
    pub use crate::report::Coverage;
}

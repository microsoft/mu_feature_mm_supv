//! A crate for converting PDB and configuration file into an auxiliary validation file
//! 
//! This crate consists of several modules that work together to extract information from the PDB file and transform
//! it into a validation file using a configuration file.
//! 
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//! 
pub mod aux_file;
pub mod config;
pub mod metadata;
pub mod report2;

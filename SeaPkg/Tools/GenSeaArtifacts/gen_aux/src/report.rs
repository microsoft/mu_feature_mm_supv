//! A module for generating a report showing the the coverage of the validation rules.
//! 
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use serde::Serialize;

use std::io::Write;

use crate::{auxgen::ImageValidationEntryHeader, validation::ValidationType};

#[derive(Serialize)]
pub struct CoverageReport {
    size: String,
    covered: String,
    uncovered: String,
    cov_percent: String,
    segments: Vec<Segment>,
}

impl CoverageReport {
    pub fn from_validation_entries(image: &[u8], entries: &[ImageValidationEntryHeader]) -> anyhow::Result<Self> {
        let pe = goblin::pe::PE::parse(image)?;
        let optional_header = pe
            .header
            .optional_header
            .ok_or(anyhow::anyhow!("No optional header found"))?;
        let size_of_image = optional_header.windows_fields.size_of_image;
        
        let mut rules: Vec<Segment> = entries.iter().map(|entry| entry.into()).collect();
        rules.sort_by_key(|rule| rule._start);
        let rules = Self::fill_rule_gaps(rules, size_of_image);

        let covered: u32 = rules.iter().filter_map(|rule| {
            if rule.covered {
                Some(rule._end - rule._start)
            } else {
                None
            }
        }).sum();

        let uncovered: u32 = rules.iter().filter_map(|rule| {
            if !rule.covered {
                Some(rule._end - rule._start)
            } else {
                None
            }
        }).sum();

        let cov_percent = (covered as f32 / size_of_image as f32) * 100.0;

        Ok(CoverageReport {
            size: format!("{:#x}", size_of_image),
            covered: format!("{:#x}", covered),
            uncovered: format!("{:#x}", uncovered),
            cov_percent: format!("{:.2}%", cov_percent),
            segments: rules,
        })
    }

    /// Fills any sections of the image that are not covered by a rule with a segment marked as uncovered.
    fn fill_rule_gaps(segments: Vec<Segment>, end: u32) -> Vec<Segment> {
        let mut ret = Vec::new();
        let mut cur = 0;

        for seg in segments.into_iter() {
            if cur < seg._start {
                ret.push(Segment::new(cur, seg._start, false, "".to_string()));
            }

            cur = seg._end.clone();
            ret.push(seg);
        }

        if cur < end {
            ret.push(Segment::new(cur, end, false, "".to_string()));
        }

        ret
    }

    /// Writes the report to a file
    pub fn to_file(&self, path: std::path::PathBuf) -> anyhow::Result<()> {
        let mut file = std::fs::File::create(path)?;
        let buffer = serde_json::to_vec_pretty(&self)?;
        file.write_all(&buffer)?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct Segment  {
    start: String,
    #[serde(skip)]
    _start: u32,
    end: String,
    #[serde(skip)]
    _end: u32,
    size: String,
    covered: bool,
    rule: String,
}

impl Segment {
    pub fn new(start: u32, end: u32, covered: bool, rule: String) -> Self {
        Segment {
            start: format!("{:#x}", start),
            _start: start,
            end: format!("{:#x}", end),
            _end: end,
            size: format!("{:#x}", end - start),
            covered,
            rule,
        }
    } 
}

impl From<&ImageValidationEntryHeader> for Segment {
    fn from(header: &ImageValidationEntryHeader) -> Self {
        let validation = &header.validation_type;
        Segment {
            start: format!("{:#x}", header.offset),
            _start: header.offset,
            end: format!("{:#x}", header.offset + header.size),
            _end: header.offset + header.size,
            size: format!("{:#x}", header.size),
            covered: *validation != ValidationType::None,
            rule: validation.into(),
        }
    }
}

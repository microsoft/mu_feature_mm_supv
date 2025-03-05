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
use std::cmp::Ordering;

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
    pub fn build(image: &[u8], sections: &[pdb::ImageSectionHeader], entries: &[ImageValidationEntryHeader]) -> anyhow::Result<Self> {
        let pe = goblin::pe::PE::parse(image)?;
        let optional_header = pe
            .header
            .optional_header
            .ok_or(anyhow::anyhow!("No optional header found"))?;
        let size_of_image = optional_header.windows_fields.size_of_image;

        let mut segments = SegmentList::new(size_of_image);
        segments.add_ro_sections(sections);
        segments.add_entry_headers(entries);
        let rules = segments.into_inner();

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

    /// Writes the report to a file
    pub fn to_file(&self, path: std::path::PathBuf) -> anyhow::Result<()> {
        let mut file = std::fs::File::create(path)?;
        let buffer = serde_json::to_vec_pretty(&self)?;
        file.write_all(&buffer)?;
        Ok(())
    }
}

/// A wrapper around a list of segments that allows for inserting new segments into the list.
struct SegmentList {
    segments: Vec<Segment>,
}

impl SegmentList {
    fn new(size: u32) -> Self {
        SegmentList {
            segments: vec![Segment::new(0, size, false, "".to_string())],
        }
    }

    /// Consumes the list and returns the inner vector of segments.
    pub fn into_inner(self) -> Vec<Segment> {
        self.segments
    }

    /// Inserts a new segment into the list, splitting any existing segments as necessary.
    fn insert(&mut self, new: Segment) {
        for i in 0..self.segments.len() {
            let seg = self.segments[i].clone();
            match (new._start.cmp(&seg._start), new._end.cmp(&seg._end)) {
                // The new segment is entirely contained within the old segment
                (Ordering::Greater, Ordering::Less) => {
                    let left = Segment::new(seg._start, new._end, seg.covered, seg.reason.clone());
                    let right = Segment::new(new._end, seg._end, seg.covered, seg.reason.clone());
                    self.segments[i] = left;
                    self.segments.insert(i + 1, new);
                    self.segments.insert(i + 2, right);
                    return;
                },
                // The new and old segments start at the same address, but the new segment ends before the old segment
                (Ordering::Equal, Ordering::Less) => {
                    let right = Segment::new(new._end, seg._end, seg.covered, seg.reason.clone());
                    self.segments[i] = new;
                    self.segments.insert(i + 1, right);
                    return;
                },
                // The new segment starts before the old segment, but ends at the same address
                (Ordering::Greater, Ordering::Equal) => {
                    let left = Segment::new(seg._start, new._start, seg.covered, seg.reason.clone());
                    self.segments[i] = left;
                    self.segments.insert(i + 1, new);
                    return;
                },
                _ => continue,
            }
        }
        panic!("oh no");
    }

    /// Adds a section (as one or more segments) if the section is read-only.
    pub fn add_ro_sections(&mut self, sections: &[pdb::ImageSectionHeader]) {
        for section in sections.iter() {
            if section.characteristics.read() && !section.characteristics.write() && !section.characteristics.execute() {
                self.insert(Segment::new(section.virtual_address, section.virtual_address + section.virtual_size, true, "ReadOnlySection".to_string()));
            }
        }
    }

    /// Adds a list of image validation entries as covered segments.
    pub fn add_entry_headers(&mut self, entries: &[ImageValidationEntryHeader]) {
        for entry in entries.iter() {
            self.insert(entry.into());
        }
    }
}

#[derive(Serialize, Clone)]
pub struct Segment  {
    start: String,
    #[serde(skip)]
    _start: u32,
    end: String,
    #[serde(skip)]
    _end: u32,
    size: String,
    covered: bool,
    reason: String,
}

impl Segment {
    pub fn new(start: u32, end: u32, covered: bool, reason: String) -> Self {
        Segment {
            start: format!("{:#x}", start),
            _start: start,
            end: format!("{:#x}", end),
            _end: end,
            size: format!("{:#x}", end - start),
            covered,
            reason,
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
            reason: validation.into(),
        }
    }
}

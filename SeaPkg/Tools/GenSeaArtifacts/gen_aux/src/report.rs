//! A module for generating a report showing the the coverage of the validation rules.
//! 
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use anyhow::{anyhow, Result};
use serde::Serialize;

use std::io::Write;
use std::cmp::Ordering;

use crate::auxgen::{AuxFile, ImageValidationEntryHeader};

/// A struct representing the coverage report for the firmware image.
/// 
/// This struct is serialized to a JSON file for easy viewing.
#[derive(Serialize)]
pub struct CoverageReport {
    /// The total number of bytes that can be considered covered. e.g. the loaded image size.
    coverable: String,
    /// The total number of bytes that are considered covered under any circumstances.
    covered: String,
    /// The percentage of the total number of bytes that are covered.
    covered_percent: String,
    /// The total number of bytes that can be considered covered by validation rules.
    coverable_by_rules: String,
    /// The total number of bytes that are covered by validation rules.
    covered_by_rules: String,
    /// The percentage of the total number of bytes that are covered by validation rules.
    covered_by_rules_percent: String,
    /// A list of sections in the loaded image and their coverage status.
    sections: Vec<Section>,
    /// A list of segments of the loaded image and their coverage status.
    segments: Vec<Segment>,
}

impl CoverageReport {
    /// Generates a coverage report from the given image and auxiliary file.
    pub fn build(image: &[u8], aux_file: &AuxFile) -> anyhow::Result<Self> {
        let size_of_image = {
            let pe = goblin::pe::PE::parse(image)?;
            let optional_header = pe
                .header
                .optional_header
                .ok_or(anyhow::anyhow!("No optional header found"))?;
            optional_header.windows_fields.size_of_image
        };

        let mut sections = SectionList::new(size_of_image);
        sections.add_sections_from_image(image)?;

        let mut segments = SegmentList::new(size_of_image);
        segments.add_segments_from_image(image)?;
        segments.add_segments_from_aux_entries(&aux_file.entries)?;

        let padding_size = segments.get_size_by_reason("Padding");
        let header_size = segments.get_size_by_reason("PE Header");
        let covered_rule_size = segments.get_size(|seg| seg.reason.starts_with("Validation Rule") && seg.covered);
        let covered_section = segments.get_size(|seg| seg.reason.starts_with("Section") && seg.covered);

        let total_covered = covered_rule_size + covered_section;
        let total_coverable = size_of_image - padding_size - header_size;
        
        let covered_by_rules = covered_rule_size;
        let coverable_by_rules = total_coverable - covered_section;

        Ok(CoverageReport {
            coverable: format!("{:#x}", total_coverable),
            covered: format!("{:#x}", total_covered),
            covered_percent: format!("{:.2}%", (total_covered as f32 / total_coverable as f32) * 100.0),
            covered_by_rules: format!("{:#x}", covered_by_rules),
            coverable_by_rules: format!("{:#x}", coverable_by_rules),
            covered_by_rules_percent: format!("{:.2}%", (covered_by_rules as f32 / coverable_by_rules as f32) * 100.0),
            segments: segments.into_inner(),
            sections: sections.into_inner(),
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

/// A wrapper around a list of sections that allows for inserting new sections into the list.
struct SectionList {
    size_of_image: u32,
    sections: Vec<Section>,
}

impl SectionList {
    /// Create an empty section list with the given image size.
    pub fn new(size: u32) -> Self {
        SectionList {
            size_of_image: size,
            sections: Vec::new(),
        }
    }

    /// Consumes the list and returns the inner vector of sections.
    pub fn into_inner(self) -> Vec<Section> {
        self.sections
    }

    /// Adds a new section to the list with the given name, start address, and end address.
    fn add_section(&mut self, name: String, start: u32, end: u32) {
        self.sections.push(Section::new(name, format!("{:#x}", start), format!("{:#x}", end)));
    }

    /// Adds sections to the report based off the PE image.
    pub fn add_sections_from_image(&mut self, image: &[u8]) -> Result<()> {
        let pe = goblin::pe::PE::parse(image)?;
        let sections = pe.sections;

        assert!(!sections.is_empty(), "No sections found in PE image.");
        self.add_section("PE Header".to_string(), 0, sections[0].virtual_address);

        for i in 0..sections.len() {
            let section = &sections[i];
            let next_section_start = if i + 1 < sections.len() {
                sections[i + 1].virtual_address
            } else {
                self.size_of_image
            };

            self.add_section(
                section.name().map(|name| name.to_string()).unwrap_or_else(|_| format!("{:?}", section.name)),
                section.virtual_address,
                next_section_start,
            );
        }

        Ok(())
    }
}

/// A wrapper around a list of segments that allows for inserting new segments into the list.
struct SegmentList {
    size_of_image: u32,
    segments: Vec<Segment>,
}

impl SegmentList {
    /// Creates a new segment list with a single segment that spans the entire image.
    fn new(size: u32) -> Self {
        SegmentList {
            size_of_image: size,
            segments: vec![Segment::new(0, size, false, "".to_string())],
        }
    }

    /// Consumes the list and returns the inner vector of segments.
    pub fn into_inner(self) -> Vec<Segment> {
        self.segments
    }

    fn get_size_by_reason(&self, reason: &str) -> u32
    {
        self.get_size(|seg| seg.reason == reason)
    }

    fn get_size(&self, filter: impl Fn(&&Segment) -> bool) -> u32
    {
        self.segments.iter().filter(filter).map(|seg| seg._end - seg._start).sum()
    }

    /// Adds segments to the report based off the PE image.
    pub fn add_segments_from_image(&mut self, image: &[u8]) -> Result<()> {
        self.add_ro_sections(image)?;
        self.add_section_padding(image)?;
        self.add_pe_header(image)?;
        Ok(())
    }

    /// Adds a section (as one or more segments) if the section is read-only, including the padding at the end of the section.
    fn add_ro_sections(&mut self, image: &[u8]) -> Result<()> {
        let pe = goblin::pe::PE::parse(image)?;
        let sections = pe.sections;

        fn read(characteristics: u32) -> bool {
            characteristics & 0x40000000 != 0
        }

        fn write(characteristics: u32) -> bool {
            characteristics & 0x80000000 != 0
        }

        fn execute(characteristics: u32) -> bool {
            characteristics & 0x20000000 != 0
        }

        for i in 0..sections.len() {
            let section = &sections[i];
            let next_section_start = if i + 1 < sections.len() {
                sections[i + 1].virtual_address
            } else {
                self.size_of_image
            };

            let c = section.characteristics;
            match (read(c), write(c), execute(c)) {
                (true, false, false) => {
                    self.insert(Segment::new(section.virtual_address, next_section_start, true, "Section: R".to_string()))?
                },
                (true, false, true) => {
                    self.insert(Segment::new(section.virtual_address, next_section_start, true, "Section: RE".to_string()))?
                }
                (a, b, c) => {
                    let mut s = String::new();
                    if a { s.push('R'); }
                    if b { s.push('W'); }
                    if c { s.push('X'); }
                    self.insert(Segment::new(section.virtual_address, next_section_start, false, format!("Section: {}", s)))?
                }
            }
        }

        Ok(())
    }

    /// Finds the padding at the end of each section and adds it as a covered segment.
    fn add_section_padding(&mut self, image: &[u8]) -> Result<()> {
        let pe = goblin::pe::PE::parse(image)?;
        let sections = pe.sections;

        // Calculate the padding at the end of each section
        for i in 0..sections.len() {
            let section = &sections[i];
            let next_section_start = if i + 1 < sections.len() {
                sections[i + 1].virtual_address
            } else {
                self.size_of_image
            };

            let padding_start = section.virtual_size.max(section.size_of_raw_data) + section.virtual_address;
            let padding_end = next_section_start;

            self.insert(Segment::new(padding_start, padding_end, true, "Padding".to_string()))?;
        }
        Ok(())
    }

    /// Adds the PE header and any padding as covered segments.
    fn add_pe_header(&mut self, image: &[u8]) -> Result<()> {
        let pe = goblin::pe::PE::parse(image)?;
        let header = pe.header.optional_header.ok_or(anyhow::anyhow!("No optional header found"))?;
        let header_size = header.windows_fields.size_of_headers;
        let start = pe.sections[0].virtual_address;

        self.insert(Segment::new(0, header_size, true, "PE Header".to_string()))?;
        self.insert(Segment::new(header_size, start, true, "Padding".to_string()))?;
        Ok(())
    }

    /// Adds a list of image validation entries as covered segments.
    pub fn add_segments_from_aux_entries(&mut self, entries: &[ImageValidationEntryHeader]) -> Result<()> {
        for entry in entries.iter() {
            self.insert(entry.into())?;
        }
        Ok(())
    }

    /// Inserts a new segment into the list, splitting any existing segments as necessary.
    fn insert(&mut self, new: Segment)->Result<()> {
        for i in 0..self.segments.len() {
            let seg = self.segments[i].clone();
            match (new._start.cmp(&seg._start), new._end.cmp(&seg._end)) {
                // The segments are exactly the same
                (Ordering::Equal, Ordering::Equal) => {
                    self.segments[i] = new;
                    return Ok(());
                },
                // The new segment is entirely contained within the old segment
                (Ordering::Greater, Ordering::Less) => {
                    let left = Segment::new(seg._start, new._start, seg.covered, seg.reason.clone());
                    let right = Segment::new(new._end, seg._end, seg.covered, seg.reason.clone());
                    self.segments[i] = left;
                    self.segments.insert(i + 1, new);
                    self.segments.insert(i + 2, right);
                    return Ok(());
                },
                // The new and old segments start at the same address, but the new segment ends before the old segment
                (Ordering::Equal, Ordering::Less) => {
                    let right = Segment::new(new._end, seg._end, seg.covered, seg.reason.clone());
                    self.segments[i] = new;
                    self.segments.insert(i + 1, right);
                    return Ok(());
                },
                // The new segment starts before the old segment, but ends at the same address
                (Ordering::Greater, Ordering::Equal) => {
                    let left = Segment::new(seg._start, new._start, seg.covered, seg.reason.clone());
                    self.segments[i] = left;
                    self.segments.insert(i + 1, new);
                    return Ok(());
                },
                _ => continue,
            }
        }

        println!("Failed to insert segment");
        println!("This only happens if the segment to insert spans multiple existing segments.");
        println!("Segment to insert: {:?}", new);
        println!("Existing segments:");
        for seg in self.segments.iter() {
            println!("  {:?}", seg);
        }
        Err(anyhow!("Failed to insert segment."))
    }
}

/// A PDB section in the image.
#[derive(Serialize, Clone, Debug)]
struct Section {
    /// The name of the section.
    name: String,
    /// The start address of the section.
    start: String,
    /// The end address of the section.
    end: String,
}

impl Section {
    /// Creates a new section with the given name, start address, and end address.
    pub fn new(name: String, start: String, end: String) -> Self {
        Section {
            name,
            start,
            end,
        }
    }
}

/// A segment of the image with metadata about its coverage status.
#[derive(Serialize, Clone, Debug)]
pub struct Segment  {
    /// The symbol from the PDB file that this segment is associated with.
    symbol: String,
    /// A hex string representation of the start address of the segment.
    start: String,
    /// The start address of the segment as a u32.
    #[serde(skip)]
    _start: u32,
    /// A hex string representation of the end address of the segment.
    end: String,
    /// The end address of the segment as a u32.
    #[serde(skip)]
    _end: u32,
    /// Whether the segment is covered by a validation rule.
    covered: bool,
    /// The reason the segment is covered or not.
    reason: String,
}

impl Segment {
    /// Creates a new segment with the given start and end addresses, coverage status, and reason.
    pub fn new(start: u32, end: u32, covered: bool, reason: String) -> Self {
        Segment {
            symbol: "".to_string(),
            start: format!("{:#x}", start),
            _start: start,
            end: format!("{:#x}", end),
            _end: end,
            covered,
            reason,
        }
    } 
}

impl From<&ImageValidationEntryHeader> for Segment {
    fn from(header: &ImageValidationEntryHeader) -> Self {
        let validation = &header.validation_type;
        let rule: String = validation.into();
        Segment {
            symbol: header.symbol.clone(),
            start: format!("{:#x}", header.offset),
            _start: header.offset,
            end: format!("{:#x}", header.offset + header.size),
            _end: header.offset + header.size,
            covered: true,
            reason: format!("Validation Rule: {}", rule),
        }
    }
}

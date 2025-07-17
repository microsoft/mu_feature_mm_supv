//! A module for generating a report showing the the coverage of the validation rules.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
use anyhow::{anyhow, Result};
use pdb::Source;
use serde::Serialize;

use std::cmp::Ordering;
use std::fmt::Debug;
use std::io::Write;

use crate::file::{AuxFile, ImageValidationEntryHeader};
use crate::metadata::PdbMetadata;

/// A struct representing the coverage report for the firmware image.
///
/// This struct is serialized to a JSON file for easy viewing.
#[derive(Serialize)]
pub struct Coverage {
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

impl Coverage {
    /// Generates a coverage report from the given image and auxiliary file.
    pub fn build<'a, S: Source<'a> + 'a>(
        aux_file: &AuxFile,
        metadata: &mut PdbMetadata<'a, S>,
    ) -> anyhow::Result<Self> {
        let size_of_image = metadata.image_size() as u32;

        let mut sections = SectionList::new(size_of_image);
        sections.add_sections_from_image(metadata.unloaded_image())?;

        let mut segments = SegmentList::new(size_of_image);
        segments.add_segments_from_image(metadata.unloaded_image())?;
        segments.add_segments_from_aux_entries(&aux_file.entries, metadata)?;
        segments.update_missing_symbol_names(metadata)?;

        let padding_size = segments.get_size_by_reason("Padding");
        let header_size = segments.get_size_by_reason("PE Header");
        let covered_rule_size =
            segments.get_size(|seg| seg.reason.starts_with("Validation Rule") && seg.covered);
        let covered_section =
            segments.get_size(|seg| seg.reason.starts_with("Section") && seg.covered);

        let total_covered = covered_rule_size + covered_section;
        let total_coverable = size_of_image - padding_size - header_size;

        let covered_by_rules = covered_rule_size;
        let coverable_by_rules = total_coverable - covered_section;

        Ok(Self {
            coverable: format!("{:#x}", total_coverable),
            covered: format!("{:#x}", total_covered),
            covered_percent: format!(
                "{:.2}%",
                (total_covered as f32 / total_coverable as f32) * 100.0
            ),
            covered_by_rules: format!("{:#x}", covered_by_rules),
            coverable_by_rules: format!("{:#x}", coverable_by_rules),
            covered_by_rules_percent: format!(
                "{:.2}%",
                (covered_by_rules as f32 / coverable_by_rules as f32) * 100.0
            ),
            segments: segments.into_inner(),
            sections: sections.into_inner(),
        })
    }

    pub fn segments<F: Fn(&Segment) -> bool>(&self, filter: F) -> Vec<&Segment> {
        self.segments.iter().filter(|seg| filter(seg)).collect()
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
        self.sections.push(Section::new(
            name,
            format!("{:#x}", start),
            format!("{:#x}", end),
        ));
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
                section
                    .name()
                    .map(|name| name.to_string())
                    .unwrap_or_else(|_| format!("{:?}", section.name)),
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

    fn get_size_by_reason(&self, reason: &str) -> u32 {
        self.get_size(|seg| seg.reason == reason)
    }

    fn get_size(&self, filter: impl Fn(&&Segment) -> bool) -> u32 {
        self.segments
            .iter()
            .filter(filter)
            .map(|seg| seg._end - seg._start)
            .sum()
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
                (true, false, false) => self.insert(Segment::new(
                    section.virtual_address,
                    next_section_start,
                    true,
                    "Section: R".to_string(),
                ))?,
                (true, false, true) => self.insert(Segment::new(
                    section.virtual_address,
                    next_section_start,
                    true,
                    "Section: RE".to_string(),
                ))?,
                (a, b, c) => {
                    let mut s = String::new();
                    if a {
                        s.push('R');
                    }
                    if b {
                        s.push('W');
                    }
                    if c {
                        s.push('X');
                    }
                    self.insert(Segment::new(
                        section.virtual_address,
                        next_section_start,
                        false,
                        format!("Section: {}", s),
                    ))?
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

            let padding_start =
                section.virtual_size.max(section.size_of_raw_data) + section.virtual_address;
            let padding_end = next_section_start;

            self.insert(Segment::new(
                padding_start,
                padding_end,
                true,
                "Padding".to_string(),
            ))?;
        }
        Ok(())
    }

    /// Adds the PE header and any padding as covered segments.
    fn add_pe_header(&mut self, image: &[u8]) -> Result<()> {
        let pe = goblin::pe::PE::parse(image)?;
        let header = pe
            .header
            .optional_header
            .ok_or(anyhow::anyhow!("No optional header found"))?;
        let header_size = header.windows_fields.size_of_headers;
        let start = pe.sections[0].virtual_address;

        self.insert(Segment::new(0, header_size, true, "PE Header".to_string()))?;
        self.insert(Segment::new(
            header_size,
            start,
            true,
            "Padding".to_string(),
        ))?;
        Ok(())
    }

    /// Adds a list of image validation entries as covered segments.
    pub fn add_segments_from_aux_entries<'a, S: Source<'a> + 'a>(
        &mut self,
        entries: &[ImageValidationEntryHeader],
        metadata: &mut PdbMetadata<'a, S>,
    ) -> Result<()> {
        for entry in entries.iter() {
            self.insert(Segment::from_entry(entry, metadata))?;
        }
        Ok(())
    }

    /// Inserts a new segment into the list, splitting any existing segments as necessary.
    fn insert(&mut self, new: Segment) -> Result<()> {
        for i in 0..self.segments.len() {
            let seg = self.segments[i].clone();
            match (new._start.cmp(&seg._start), new._end.cmp(&seg._end)) {
                // The segments are exactly the same
                (Ordering::Equal, Ordering::Equal) => {
                    self.segments[i] = new;
                    return Ok(());
                }
                // The new segment is entirely contained within the old segment
                (Ordering::Greater, Ordering::Less) => {
                    let left =
                        Segment::new(seg._start, new._start, seg.covered, seg.reason.clone());
                    let right = Segment::new(new._end, seg._end, seg.covered, seg.reason.clone());
                    self.segments[i] = left;
                    self.segments.insert(i + 1, new);
                    self.segments.insert(i + 2, right);
                    return Ok(());
                }
                // The new and old segments start at the same address, but the new segment ends before the old segment
                (Ordering::Equal, Ordering::Less) => {
                    let right = Segment::new(new._end, seg._end, seg.covered, seg.reason.clone());
                    self.segments[i] = new;
                    self.segments.insert(i + 1, right);
                    return Ok(());
                }
                // The new segment starts before the old segment, but ends at the same address
                (Ordering::Greater, Ordering::Equal) => {
                    let left =
                        Segment::new(seg._start, new._start, seg.covered, seg.reason.clone());
                    self.segments[i] = left;
                    self.segments.insert(i + 1, new);
                    return Ok(());
                }
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

    /// Attempts to update segments that are uncovered and have no symbol name.
    ///
    /// We must loop through each byte of each uncovered segment for three reasons:
    /// 1. A segment may contain multiple symbols
    /// 2. If a rule only covers part of a symbol (using a field), we need to ensure all other
    ///    parts of the same symbol that are not covered have their names correctly set.
    /// 3. There may be padding between symbols for alignment purposes
    pub fn update_missing_symbol_names<'a, S: Source<'a> + 'a>(
        &mut self,
        metadata: &mut PdbMetadata<'a, S>,
    ) -> Result<()> {
        let mut to_insert = Vec::new();
        for segment in &self.segments {
            if !segment.symbol.is_empty() || segment.covered {
                continue;
            }

            let mut cur = segment._start;
            while cur < segment._end {
                if let Some(symbol) = metadata.symbol_from_address(&cur) {
                    let end = std::cmp::min(cur + symbol.size(), segment._end);
                    let mut segment = Segment::new(cur, end, false, segment.reason.clone());
                    segment.symbol = symbol.name.clone();
                    to_insert.push(segment);
                    cur = end;
                } else {
                    cur += 1;
                }
            }
        }

        for segment in to_insert.into_iter() {
            self.insert(segment)?;
        }

        Ok(())
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
        Section { name, start, end }
    }
}

/// A segment of the image with metadata about its coverage status.
#[derive(Serialize, Clone)]
pub struct Segment {
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
    /// The people associated with reviewing this segment.
    ///
    /// This field is only used when the segment is covered by a validation rule.
    reviewers: Vec<String>,
    /// The date the segment was last reviewed.
    last_reviewed: String,
    /// Comments about the segment.
    remarks: String,
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
            reviewers: Vec::new(),
            last_reviewed: String::new(),
            remarks: String::new(),
        }
    }

    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    pub fn start(&self) -> u32 {
        self._start
    }

    pub fn end(&self) -> u32 {
        self._end
    }

    /// Returns if this segment is covered.
    pub fn covered(&self) -> bool {
        self.covered
    }

    pub fn from_entry<'a, S: Source<'a> + 'a>(
        entry: &ImageValidationEntryHeader,
        metadata: &PdbMetadata<'a, S>,
    ) -> Self {
        let validation = &entry.validation_type;
        let rule = validation.to_string();
        let (symbol, reviewers, last_reviewed, remarks) =
            metadata.context_from_address(&entry.offset).map_or(
                (
                    "Symbol Padding".to_string(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                ),
                |c| {
                    (
                        c.name.clone(),
                        c.reviewers.clone(),
                        c.last_reviewed.clone(),
                        c.remarks.clone(),
                    )
                },
            );
        Segment {
            symbol,
            start: format!("{:#x}", entry.offset),
            _start: entry.offset,
            end: format!("{:#x}", entry.offset + entry.size),
            _end: entry.offset + entry.size,
            covered: true,
            reason: format!("Validation Rule: {}", rule),
            reviewers,
            last_reviewed,
            remarks,
        }
    }
}

impl Debug for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("symbol", &self.symbol)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("covered", &self.covered)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{file::ImageValidationEntryHeader, metadata};

    fn create_metadata() -> metadata::PdbMetadata<'static, Cursor<&'static [u8]>> {
        let pdb = include_bytes!("../resources/test/example.pdb");
        let efi = include_bytes!("../resources/test/example.efi");
        let Ok(metadata) = metadata::PdbMetadata::<'_, Cursor<_>>::new(pdb, efi) else {
            panic!("Failed to create PdbMetadata");
        };
        metadata
    }

    #[test]
    fn test_debug_creates_expected_output() {
        use super::*;
        let segment = Segment::new(0x1000, 0x2000, true, "Test".to_string());
        let output = format!("{:?}", segment);
        assert!(output.contains("Segment"));
        assert!(output.contains("symbol: \"\""));
        assert!(output.contains("start: \"0x1000\""));
        assert!(output.contains("end: \"0x2000\""));
        assert!(output.contains("covered: true"));
    }

    #[test]
    fn test_segment_from_entry() {
        let mut metadata = create_metadata();

        // Generate the header to test creating a segment.
        let Ok(headers) = metadata.build_entries(&crate::config::Rule {
            symbol: "gMpInformation2HobGuid".to_string(),
            field: None,
            scope: None,
            array: None,
            validation: crate::config::Validation::None,
            reviewers: vec!["Test Reviewer <Test@example.com>".to_string()],
            last_reviewed: "2025-07-11".to_string(),
            remarks: "An Amazing Rule".to_string(),
        }) else {
            panic!("Failed to build entries");
        };

        assert_eq!(headers.len(), 1);
        let (entry, data) = &headers[0];

        // Just validate the header is correct for the actual test below.
        assert_eq!(entry.signature, 0x52544E45);
        assert_eq!(entry.offset, 0x37020);
        assert_eq!(entry.size, 0x10);
        assert_eq!(entry.offset_to_default, 0x0); // This is the first rule, so its offset is 0
        assert_eq!(data.len(), 0x10);

        let segment = Segment::from_entry(entry, &metadata);

        assert_eq!(segment.symbol(), "gMpInformation2HobGuid");
        assert_eq!(segment.start(), 0x37020);
        assert_eq!(segment.start, "0x37020");
        assert_eq!(segment.end(), 0x37030);
        assert_eq!(segment.end, "0x37030");
        assert!(segment.covered());
        assert_eq!(segment.reason, "Validation Rule: None");
        assert_eq!(
            segment.reviewers,
            vec!["Test Reviewer <Test@example.com>".to_string()]
        );
        assert_eq!(segment.last_reviewed, "2025-07-11".to_string());
        assert_eq!(segment.remarks, "An Amazing Rule".to_string());
    }

    #[test]
    fn test_segment_list_insert_split_middle() {
        let mut segments = SegmentList::new(0x1000);
        assert_eq!(segments.segments.len(), 1);

        // Insert a segment that will split an existing segment in two
        segments
            .insert(Segment::new(0x400, 0x600, true, "Test".to_string()))
            .unwrap_or_else(|_| panic!("Failed to insert segment"));
        assert_eq!(segments.segments.len(), 3);
        assert_eq!(segments.segments[0]._start, 0x0);
        assert_eq!(segments.segments[0]._end, 0x400);
        assert_eq!(segments.segments[1]._start, 0x400);
        assert_eq!(segments.segments[1]._end, 0x600);
        assert_eq!(segments.segments[1].reason, "Test");
        assert_eq!(segments.segments[2]._start, 0x600);
        assert_eq!(segments.segments[2]._end, 0x1000);
    }

    #[test]
    fn test_segment_list_insert_split_exact() {
        let mut segments = SegmentList::new(0x1000);
        assert_eq!(segments.segments.len(), 1);
        assert_eq!(segments.segments[0]._start, 0x0);
        assert_eq!(segments.segments[0]._end, 0x1000);
        assert!(!segments.segments[0].covered());

        segments
            .insert(Segment::new(0x0, 0x1000, true, "Test".to_string()))
            .unwrap_or_else(|_| panic!("Failed to insert segment"));
        assert_eq!(segments.segments.len(), 1);
        assert_eq!(segments.segments[0]._start, 0x0);
        assert_eq!(segments.segments[0]._end, 0x1000);
        assert!(segments.segments[0].covered());
        assert_eq!(segments.segments[0].reason, "Test");
    }

    #[test]
    fn test_segment_list_insert_left() {
        let mut segments = SegmentList::new(0x1000);
        assert_eq!(segments.segments.len(), 1);

        // Insert a segment that will be to the left of the existing segment
        segments
            .insert(Segment::new(0x0, 0x400, true, "Test".to_string()))
            .unwrap_or_else(|_| panic!("Failed to insert segment"));
        assert_eq!(segments.segments.len(), 2);
        assert_eq!(segments.segments[0]._start, 0x0);
        assert_eq!(segments.segments[0]._end, 0x400);
        assert_eq!(segments.segments[0].reason, "Test");
        assert!(segments.segments[0].covered());
        assert_eq!(segments.segments[1]._start, 0x400);
        assert_eq!(segments.segments[1]._end, 0x1000);
    }

    #[test]
    fn test_segment_list_insert_right() {
        let mut segments = SegmentList::new(0x1000);
        assert_eq!(segments.segments.len(), 1);

        // Insert a segment that will be to the right of the existing segment
        segments
            .insert(Segment::new(0x600, 0x1000, true, "Test".to_string()))
            .unwrap_or_else(|_| panic!("Failed to insert segment"));
        assert_eq!(segments.segments.len(), 2);
        assert_eq!(segments.segments[0]._start, 0x0);
        assert_eq!(segments.segments[0]._end, 0x600);
        assert_eq!(segments.segments[1]._start, 0x600);
        assert_eq!(segments.segments[1]._end, 0x1000);
        assert_eq!(segments.segments[1].reason, "Test");
        assert!(segments.segments[1].covered());
    }

    #[test]
    fn test_segment_list_add_section_padding() {
        let mut segments = SegmentList::new(0x3d400);
        assert_eq!(segments.segments.len(), 1);

        // Passing the wrong file type should fail
        assert!(segments
            .add_section_padding(include_bytes!("../resources/test/example.pdb"))
            .is_err());

        // Passing the correct file type should succeed
        assert!(segments
            .add_section_padding(include_bytes!("../resources/test/example.efi"))
            .is_ok());

        // (1) PE Header + .text Section
        // (2) .text Section Padding (COVERED)
        // (3) .rdata Section
        // (4) .rdata Section Padding (COVERED)
        // (5) .data Section
        // (6) .data Section Padding (COVERED)
        // (7) (unnamed) Section
        // (8) (unnamed) Section Padding (COVERED)
        // (9) .xdata Section
        // (10) .xdata Section Padding (COVERED)
        // (11) .reloc Section
        // (12) .reloc Section Padding (COVERED)
        assert_eq!(segments.segments.len(), 12);

        let segments = segments.into_inner();
        for segment in segments.iter().skip(1).step_by(2) {
            assert!(segment.covered())
        }

        for segment in segments.iter().step_by(2) {
            assert!(!segment.covered())
        }
    }

    #[test]
    fn test_segment_list_insert_overlapping() {
        let mut segments = SegmentList::new(0x3d400);
        assert_eq!(segments.segments.len(), 1);

        // Insert a segment that overlaps with the existing segment
        segments
            .insert(Segment::new(0x200, 0x800, true, "Test".to_string()))
            .unwrap_or_else(|_| panic!("Failed to insert segment"));

        // This should panic because the segment overlaps with the existing segment
        assert!(segments
            .insert(Segment::new(0x100, 0x300, true, "Test".to_string()))
            .is_err());
    }

    #[test]
    fn test_segment_list_add_pe_header() {
        let pe = include_bytes!("../resources/test/example.efi");
        let mut segments = SegmentList::new(pe.len() as u32);
        assert_eq!(segments.segments.len(), 1);

        let Ok(_) = segments.add_pe_header(pe) else {
            panic!("Failed to add PE header");
        };

        // (1) The PE header
        // (2) The padding after the PE header
        // (3) The rest of the image
        assert_eq!(segments.segments.len(), 3);

        // These values are hardcoded as we know the correct values for this test image.
        assert_eq!(segments.segments[0].start(), 0x0);
        assert_eq!(segments.segments[0].end(), 0x400);

        assert_eq!(segments.segments[1].start(), 0x400);
        assert_eq!(segments.segments[1].end(), 0x1000);

        assert_eq!(segments.segments[2].start(), 0x1000);
        assert_eq!(segments.segments[2].end(), pe.len() as u32);
    }

    #[test]
    fn test_segment_list_get_size() {
        let mut segments = SegmentList::new(0x3d400);
        segments
            .add_segments_from_image(include_bytes!("../resources/test/example.efi"))
            .unwrap_or_else(|_| panic!("Failed to add segments from image"));

        assert_eq!(segments.get_size(|seg| seg._start == 0x0), 0x400); // Hardcoded truth for this exact binary
        assert_eq!(segments.get_size(|seg| seg.reason == "PE Header"), 0x400); // Hardcoded truth for this exact binary
    }

    #[test]
    fn test_segment_list_get_size_by_reason() {
        let mut segments = SegmentList::new(0x3d400);
        segments
            .add_segments_from_image(include_bytes!("../resources/test/example.efi"))
            .unwrap_or_else(|_| panic!("Failed to add segments from image"));

        assert_eq!(segments.get_size_by_reason("PE Header"), 0x400); // Hardcoded truth for this exact binary
        assert_eq!(segments.get_size_by_reason("Section: R"), 0x10A00); // Hardcoded truth for this exact binary
        assert_eq!(segments.get_size_by_reason("Padding"), 0x3A30); // Hardcoded truth for this exact binary
    }

    #[test]
    fn test_segment_list_add_segments_from_aux_entries() {
        let mut metadata = create_metadata();
        let mut segments = SegmentList::new(metadata.image_size() as u32);

        // Generate a header to populate the context map.
        let Ok(headers) = metadata.build_entries(&crate::config::Rule {
            symbol: "gMpInformation2HobGuid".to_string(),
            field: None,
            scope: None,
            array: None,
            validation: crate::config::Validation::None,
            reviewers: vec!["Test Reviewer <Test@example.com>".to_string()],
            last_reviewed: "2025-07-11".to_string(),
            remarks: "An Amazing Rule".to_string(),
        }) else {
            panic!("Failed to build entries");
        };

        assert_eq!(headers.len(), 1);
        let guid_size = headers[0].0.size;

        assert_eq!(
            segments.get_size(|seg| seg.symbol() == "gMpInformation2HobGuid"),
            0
        );

        let headers: Vec<ImageValidationEntryHeader> =
            headers.into_iter().map(|(h, _)| h).collect::<Vec<_>>();
        segments
            .add_segments_from_aux_entries(headers.as_slice(), &mut metadata)
            .unwrap_or_else(|_| panic!("Failed to add segments from aux entries"));

        assert_eq!(
            segments.get_size(|seg| seg.symbol() == "gMpInformation2HobGuid"),
            guid_size
        );
    }

    #[test]
    fn test_segment_list_update_missing_symbol_names() {
        let mut segments = SegmentList::new(0x3d400);

        let mut metadata = create_metadata();

        assert_eq!(
            segments.get_size(|seg| seg.symbol() == "gMpInformation2HobGuid"),
            0
        );
        segments
            .update_missing_symbol_names(&mut metadata)
            .unwrap_or_else(|_| panic!("Failed to update missing symbol names"));
        assert!(segments.get_size(|seg| seg.symbol() == "gMpInformation2HobGuid") > 0);
    }

    #[test]
    fn test_section_list_add_sections_from_image() {
        let mut sections = SectionList::new(0x3d400);
        assert_eq!(sections.sections.len(), 0);

        sections
            .add_sections_from_image(include_bytes!("../resources/test/example.efi"))
            .unwrap_or_else(|_| panic!("Failed to add sections from image"));

        // 6 sections + 1 for the PE header, which we include here
        assert_eq!(sections.sections.len(), 7);

        let sections = sections.into_inner();

        // Test that the entire binary is covered by the sections
        let test_bin_section_names = [
            ".text",
            ".rdata",
            ".data",
            ".xdata",
            ".reloc",
            "PE Header",
            "",
            "PE Header",
        ];

        let mut cur_size = 0x0;
        for section in sections.iter() {
            let section_start = section.start.trim_start_matches("0x");
            let section_end = section.end.trim_start_matches("0x");
            let section_start = u32::from_str_radix(section_start, 16)
                .unwrap_or_else(|e| panic!("Failed to parse section start address: [{e}]"));
            let section_end = u32::from_str_radix(section_end, 16)
                .unwrap_or_else(|e| panic!("Failed to parse section end address: [{e}]"));
            assert_eq!(cur_size, section_start);
            assert!(test_bin_section_names.contains(&section.name.as_str()));
            assert!(section_start < section_end);
            cur_size = section_end;
        }
    }

    #[test]
    fn test_update_missing_symbol_names() {
        let mut metadata = create_metadata();

        // Generate a header to populate the context map.
        let Ok(_) = metadata.build_entries(&crate::config::Rule {
            symbol: "gMpInformation2HobGuid".to_string(),
            field: None,
            scope: None,
            array: None,
            validation: crate::config::Validation::None,
            reviewers: vec!["Test Reviewer <Test@example.com>".to_string()],
            last_reviewed: "2025-07-11".to_string(),
            remarks: "An Amazing Rule".to_string(),
        }) else {
            panic!("Failed to build entries");
        };

        let segments = SegmentList::new(metadata.image_size() as u32);
        assert!(segments.get_size(|seg| seg.symbol() == "gMpInformation2HobGuid") == 0);
    }

    #[test]
    fn test_coverage_build() {
        // Honestly this is more of an integration test.
        let mut metadata = create_metadata();
        let mut aux_file = AuxFile::default();
        let entry = ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0x37020,
            size: 0x10,
            offset_to_default: 0x0,
            validation_type: crate::file::ValidationType::None,
        };
        aux_file.add_entry(entry, vec![0; 0x10].as_ref());

        let Ok(report) = Coverage::build(&aux_file, &mut metadata) else {
            panic!("Failed to build report");
        };

        assert_eq!(report.covered_by_rules, "0x10");
        assert_eq!(report.coverable_by_rules, "0x23d0"); // Hardcoded truth for this exact binary
        assert_eq!(report.covered_by_rules_percent, "0.17%");

        let covered = report
            .segments(|seg| seg.covered())
            .iter()
            .fold(0, |acc, seg| acc + seg.end() - seg.start());
        assert!(covered > 0, "No segments were covered in the report");
    }

    #[test]
    fn test_coverage_to_file() {
        let mut metadata = create_metadata();
        let aux_file = AuxFile::default();

        let Ok(_) = Coverage::build(&aux_file, &mut metadata) else {
            panic!("Failed to build report");
        };
    }
}

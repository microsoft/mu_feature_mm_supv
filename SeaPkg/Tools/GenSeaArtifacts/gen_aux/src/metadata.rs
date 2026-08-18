//! A module containing the metadata from the PDB file used to convert the configuration file into the auxiliary file.
//!
//! The [PdbMetadata] struct is the core functionality coming from this module and is responsible for parsing the PDB
//! file and converting the Configuration file into the auxiliary file using the metadata from the parsed PDB file.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
use std::{collections::HashMap, fmt::Formatter, fs::File, io::Cursor, ops::Range, path::PathBuf};

use anyhow::{anyhow, Result};
use pdb::{
    AddressMap, DataSymbol, FallibleIterator, Item, PrimitiveKind, Source, TypeData, TypeIndex,
    TypeInformation, PDB,
};

use crate::{config, file, report};

const POINTER_LENGTH: u64 = 8;

/// A class or union record reduced to the parts this module needs, so one code path handles both.
struct Aggregate<'t> {
    name: pdb::RawString<'t>,
    size: u64,
    /// A class may have no field list; a union always has one.
    fields: Option<TypeIndex>,
    forward_reference: bool,
}

impl<'t> Aggregate<'t> {
    fn new(data: &TypeData<'t>) -> Option<Self> {
        let (name, size, fields, properties) = match data {
            TypeData::Class(c) => (c.name, c.size, c.fields, c.properties),
            TypeData::Union(u) => (u.name, u.size, Some(u.fields), u.properties),
            _ => return None,
        };

        Some(Self {
            name,
            size,
            fields,
            forward_reference: properties.forward_reference(),
        })
    }
}

/// Additional context associated with a rule
pub struct Context {
    pub name: String,
    pub reviewers: Vec<String>,
    pub last_reviewed: String,
    pub remarks: String,
}

impl Context {
    fn new(name: String, reviewers: Vec<String>, last_reviewed: String, remarks: String) -> Self {
        Context {
            name,
            reviewers,
            last_reviewed,
            remarks,
        }
    }
}

/// A struct containing all metadata from the PDB necessary to generate the auxiliary file.
pub struct PdbMetadata<'a, S: Source<'a>> {
    pdb: PDB<'a, S>,
    sections: Vec<Section>,
    context_map: HashMap<u32, Context>,
    unloaded_image: Vec<u8>,
    loaded_image: Vec<u8>,
}

impl PdbMetadata<'_, File> {
    pub fn new(pdb_path: PathBuf, efi_path: PathBuf) -> Result<Self> {
        let file = File::open(pdb_path)?;
        let mut pdb = PDB::open(file)?;

        let sections = Self::get_sections(&mut pdb)?;
        let unloaded_image = std::fs::read(efi_path)?;
        let loaded_image = Self::load_image(&unloaded_image)?;
        let context_map = HashMap::new();

        let mut metadata = PdbMetadata {
            pdb,
            sections,
            context_map,
            unloaded_image,
            loaded_image,
        };

        metadata.fill_sections()?;

        Ok(metadata)
    }
}

impl<'a> PdbMetadata<'a, Cursor<&'a [u8]>> {
    pub fn new(pdb: &'a [u8], efi: &[u8]) -> Result<Self> {
        let file = Cursor::new(pdb);
        let mut pdb = PDB::open(file)?;

        let sections = Self::get_sections(&mut pdb)?;
        let unloaded_image = efi.to_vec();
        let loaded_image = Self::load_image(&unloaded_image)?;
        let context_map = HashMap::new();

        let mut metadata = PdbMetadata {
            pdb,
            sections,
            context_map,
            unloaded_image,
            loaded_image,
        };

        metadata.fill_sections()?;

        Ok(metadata)
    }
}

impl<'a, S: Source<'a> + 'a> PdbMetadata<'a, S> {
    /// Create a new ImageValidationEntryHeader from the given rule.
    pub fn build_entries(
        &mut self,
        rule: &config::Rule,
    ) -> Result<Vec<(file::ImageValidationEntryHeader, Vec<u8>)>> {
        let symbol = self.find_symbol(&rule.symbol).clone();
        self.validate_rule(&symbol, rule)?;

        let extent = self.rule_extent(&symbol, rule)?;

        let mut ret = Vec::new();

        for i in 0..extent.count {
            if !rule
                .array
                .as_ref()
                .and_then(|arr| arr.index.clone())
                .unwrap_or(i..=i)
                .contains(&i)
            {
                continue;
            }

            let size = extent.size;

            let validation_type = if rule
                .array
                .as_ref()
                .is_some_and(|a| a.sentinel && i == extent.count - 1)
            {
                file::ValidationType::Content {
                    content: vec![0; size as usize],
                }
            } else {
                self.build_validation_type(&rule.validation)?
            };

            let entry = file::ImageValidationEntryHeader {
                offset: symbol.address + extent.field_offset + extent.stride * i as u32,
                size,
                validation_type,
                ..Default::default()
            };

            let default = self.loaded_image
                [entry.offset as usize..(entry.offset + entry.size) as usize]
                .to_vec();

            // The index belongs to whichever array the rule iterates: the array member named by
            // `array.field`, or the symbol itself.
            let mut name = rule.symbol.clone();
            match rule.array.as_ref().and_then(|array| array.field.as_deref()) {
                Some(array_field) => name += format!(".{}[{}]", array_field, i).as_str(),
                None if extent.count > 1 => name += format!("[{}]", i).as_str(),
                None => {}
            }
            if let Some(field) = &rule.field {
                name += format!(".{}", field).as_str();
            }
            self.context_map.insert(
                entry.offset,
                Context::new(
                    name,
                    rule.reviewers.clone(),
                    rule.last_reviewed.clone(),
                    rule.remarks.clone(),
                ),
            );

            ret.push((entry, default));
        }

        Ok(ret)
    }

    /// Creates a new KeySymbol from the given key.
    pub fn build_key_symbol(&mut self, key: &config::Key) -> Result<file::KeySymbol> {
        let symbol = self.find_symbol(&key.symbol).clone();
        let mut address = symbol.address;

        if let Some(field) = &key.field {
            let type_information = &mut self.pdb.type_information()?;
            let type_id = symbol.type_info.type_id().ok_or_else(|| {
                anyhow!(
                    "Symbol [{}] has no type information. Cannot resolve field [{}].",
                    symbol.name(),
                    field
                )
            })?;
            let (field_offset, _) = Symbol::find_field_offset_and_size(
                type_information,
                &type_id,
                field,
                symbol.name(),
            )?;
            address += field_offset;
        }

        Ok(file::KeySymbol::new(key.signature, address))
    }

    /// Creates new zero content rules for padding that should always be all zeros.
    /// This padding includes:
    /// 1. Padding between sections
    /// 2. Padding between symbols
    /// 3. Padding between fields of a class
    pub fn create_padding_entries(
        &mut self,
        report: &report::Coverage,
    ) -> Result<Vec<(file::ImageValidationEntryHeader, Vec<u8>)>> {
        let mut ret = Vec::new();
        ret.extend(self.build_symbol_padding_entries(report)?);
        ret.extend(self.build_field_padding_entries(report)?);

        Ok(ret)
    }

    /// Returns the unloaded image bytes.
    pub fn unloaded_image(&self) -> &[u8] {
        &self.unloaded_image
    }

    /// Returns the loaded image bytes.
    pub fn image_size(&self) -> usize {
        self.loaded_image.len()
    }

    /// Provides the general symbol information for the symbol containing the given address.
    pub fn symbol_from_address(&self, address: &u32) -> Option<&Symbol> {
        self.sections
            .iter()
            .flat_map(|section| section.symbols.iter())
            .find(|symbol| {
                (symbol.address..symbol.address + symbol.type_info.total_size()).contains(address)
            })
    }

    /// Returns the context associated with the given address, if any.
    pub fn context_from_address(&self, address: &u32) -> Option<&Context> {
        self.context_map.get(address)
    }

    pub fn symbol_fields(&mut self, symbol: &str) -> Option<Vec<String>> {
        let info = self.pdb.type_information().ok()?;
        let symbol = self.find_symbol(symbol);
        let data = TypeInfo::find_type(&info, symbol.type_info.type_id()?).ok()?;

        // Get the class, return None if it is not a class.
        let Some(pdb::TypeData::Class(class)) = data.parse().ok() else {
            return None;
        };

        // Get the fields of the class, return None if there are no fields.
        let fields = TypeInfo::find_type(&info, class.fields?).ok()?;
        let Some(pdb::TypeData::FieldList(data)) = fields.parse().ok() else {
            return None;
        };

        let names = data
            .fields
            .iter()
            .map(|field| field.name().unwrap_or_default().to_string().to_string())
            .collect::<Vec<_>>();

        Some(names)
    }

    /// If the symbol is an array, returns the index of the element at the given address.
    fn symbol_idx(&mut self, symbol: &str, address: u32) -> Option<usize> {
        let symbol = self.find_symbol(symbol);
        if symbol.type_info.element_count() == 1 {
            return None;
        }
        let offset = address - symbol.address;
        Some((offset / symbol.type_info.element_size()) as usize)
    }

    /// Returns the offset of a rule's field within its symbol, along with the field's type.
    fn resolve_field(&mut self, symbol: &Symbol, field: &str) -> Result<(u32, TypeInfo)> {
        let type_id = symbol.type_info.type_id().ok_or_else(|| {
            anyhow!(
                "Symbol [{}] has no type information. Cannot resolve field [{}].",
                symbol.name(),
                field
            )
        })?;

        let info = self.pdb.type_information()?;
        Symbol::find_field(&info, &type_id, field, symbol.name())
    }

    /// Returns what a rule iterates over, and how large each entry it produces is.
    ///
    /// A rule produces one entry per element of the symbol, validating the same field within each.
    /// A rule that names [config::Array::field] iterates that array member of the symbol instead,
    /// so the elements of a nested array can be validated individually.
    fn rule_extent(&mut self, symbol: &Symbol, rule: &config::Rule) -> Result<RuleExtent> {
        if let Some(array_field) = rule.array.as_ref().and_then(|array| array.field.as_deref()) {
            return self.array_field_extent(symbol, array_field, rule.field.as_deref());
        }

        let stride = symbol.type_info.element_size();
        let count = symbol.type_info.element_count();

        let Some(field) = &rule.field else {
            return Ok(RuleExtent {
                field_offset: 0,
                stride,
                size: stride,
                count,
            });
        };

        let (field_offset, field_type) = self.resolve_field(symbol, field)?;

        Ok(RuleExtent {
            field_offset,
            stride,
            size: field_type.total_size(),
            count,
        })
    }

    /// Returns the extent of a rule that iterates an array member of its symbol.
    ///
    /// `field`, when given, selects the same field within every element of that array. Without it
    /// each entry covers a whole element.
    fn array_field_extent(
        &mut self,
        symbol: &Symbol,
        array_field: &str,
        field: Option<&str>,
    ) -> Result<RuleExtent> {
        // A single `index` cannot address two levels of array, so the symbol has to be the one
        // value that holds the array being iterated.
        if symbol.type_info.element_count() > 1 {
            return Err(anyhow!(
                "Invalid Rule Configuration: Symbol {}: `array.field` cannot be used because the symbol is itself an array.",
                symbol.name()
            ));
        }

        let (array_offset, array_type) = self.resolve_field(symbol, array_field)?;

        if array_type.element_count() <= 1 {
            return Err(anyhow!(
                "Invalid Rule Configuration: Symbol {}: `array.field` [{}] is not an array.",
                symbol.name(),
                array_field
            ));
        }

        let extent = RuleExtent {
            field_offset: array_offset,
            stride: array_type.element_size(),
            size: array_type.element_size(),
            count: array_type.element_count(),
        };

        let Some(field) = field else {
            return Ok(extent);
        };

        // `TypeInfo` records an array as a repeat of its element type, so this is the type a field
        // named alongside `array.field` is resolved against.
        let element_type = array_type.type_id().ok_or_else(|| {
            anyhow!(
                "Array field [{}] of symbol [{}] has no element type information. Cannot resolve field [{}].",
                array_field,
                symbol.name(),
                field
            )
        })?;

        let info = self.pdb.type_information()?;
        let (offset, field_type) = Symbol::find_field(&info, &element_type, field, symbol.name())?;

        Ok(RuleExtent {
            field_offset: array_offset + offset,
            size: field_type.total_size(),
            ..extent
        })
    }

    fn validate_rule(&mut self, symbol: &Symbol, rule: &crate::config::Rule) -> Result<()> {
        let extent = self.rule_extent(symbol, rule)?;

        // If the rule is a content rule, make sure that the content size matches the symbol size.
        if let config::Validation::Content { content } = &rule.validation {
            let size = extent.size;

            if content.len() != size as usize {
                let name = if let Some(field) = &rule.field {
                    format!("{}.{}", symbol.name(), field)
                } else {
                    symbol.name().to_string()
                };
                return Err(anyhow::anyhow!(
                    "Invalid Rule Configuration: Symbol {}: Content size {} does not match symbol size {}.",
                    name,
                    content.len(),
                    size
                ));
            }
        }

        let element_count = extent.count;

        if element_count == 1 && rule.array.is_some() {
            return Err(anyhow!(
                "Symbol {} is not an array, but array configuration was provided.",
                symbol.name()
            ));
        }

        if let Some(array) = &rule.array {
            if array.index.is_some() && array.sentinel {
                return Err(
                    anyhow::anyhow!("Invalid Rule Configuration: Symbol {}: Array configuration `sentinel` and `index` cannot be combined.", symbol.name)
                );
            }

            if let Some(index) = &array.index {
                if index.end() >= &element_count {
                    return Err(
                        anyhow::anyhow!("Invalid Rule Configuration: Symbol {}: Array index {:#?} is out of bounds.", symbol.name, index)
                    );
                }
            }
        }

        Ok(())
    }

    fn build_validation_type(
        &self,
        validation: &crate::config::Validation,
    ) -> Result<file::ValidationType> {
        use config::Validation;
        use file::ValidationType;
        match validation {
            Validation::None => Ok(ValidationType::None),
            Validation::NonZero => Ok(ValidationType::NonZero),
            Validation::Content { content } => Ok(ValidationType::Content {
                content: content.clone(),
            }),
            Validation::MemAttr {
                memory_size,
                must_have,
                must_not_have,
            } => Ok(ValidationType::MemAttr {
                memory_size: *memory_size,
                must_have: *must_have,
                must_not_have: *must_not_have,
            }),
            Validation::Ref { reference } => Ok(ValidationType::Ref {
                address: self.find_symbol(reference).address,
            }),
            Validation::Pointer { in_mseg } => Ok(ValidationType::Pointer { in_mseg: *in_mseg }),
            Validation::Guid { guid } => Ok(ValidationType::Content {
                content: guid.as_bytes().to_vec(),
            }),
        }
    }

    /// Returns the symbol with the given name from the PDB file.
    fn find_symbol(&self, symbol: &str) -> &Symbol {
        self.sections
            .iter()
            .flat_map(|section| section.symbols.iter())
            .filter(|s| s.name == symbol)
            // We may find multiple symbols; typically the actual symbol and a label. This filters to return the
            // actual symbol if we happen to have found both.
            .max_by_key(|s| s.type_info.element_type.unwrap_or(TypeIndex(0)).0)
            .unwrap_or_else(|| panic!("Symbol {} not found in PDB file.", symbol))
    }

    /// Returns the sections in the PDB file in the custom format.
    fn get_sections(pdb: &mut PDB<'a, S>) -> Result<Vec<Section>> {
        let sections = pdb.sections()?.unwrap_or_default();
        let sections = sections
            .iter()
            .map(|section| {
                let range = section.virtual_address..section.virtual_address + section.virtual_size;

                Section {
                    name: section.name().to_string(),
                    range,
                    symbols: vec![],
                }
            })
            .collect::<Vec<_>>();

        Ok(sections)
    }

    /// Fills the sections with the symbols from the PDB file.
    fn fill_sections(&mut self) -> Result<()> {
        let address_map = self.pdb.address_map()?;
        let type_information = self.pdb.type_information()?;

        let symbol_table = self.pdb.global_symbols()?;
        let mut symbols = symbol_table.iter();

        let debug_information = self.pdb.debug_information()?;
        let mut modules = debug_information.modules()?;

        while let Some(module) = modules.next()? {
            let module_info = self.pdb.module_info(&module)?.unwrap();
            let mut symbols = module_info.symbols()?;
            while let Some(symbol) = symbols.next()? {
                if let Some(symbol) =
                    Symbol::from_pdb_symbol(symbol, &address_map, &type_information)?
                {
                    if let Some(section) = self
                        .sections
                        .iter_mut()
                        .find(|section| section.range.contains(&symbol.address))
                    {
                        section.symbols.push(symbol);
                    }
                }
            }
        }

        while let Some(symbol) = symbols.next()? {
            if let Some(symbol) = Symbol::from_pdb_symbol(symbol, &address_map, &type_information)?
            {
                if let Some(section) = self
                    .sections
                    .iter_mut()
                    .find(|section| section.range.contains(&symbol.address))
                {
                    section.symbols.push(symbol);
                }
            }
        }

        Ok(())
    }

    fn load_image(image: &[u8]) -> Result<Vec<u8>> {
        let pe = goblin::pe::PE::parse(image)?;
        let optional_header = pe
            .header
            .optional_header
            .ok_or(anyhow::anyhow!("No optional header found"))?;

        let size_of_image = optional_header.windows_fields.size_of_image;
        let size_of_headers = optional_header.windows_fields.size_of_headers as usize;

        // Copy the headers
        let mut loaded_image = vec![0; size_of_image as usize];
        let dst = loaded_image
            .get_mut(..size_of_headers)
            .ok_or(anyhow::anyhow!("Failed to get headers"))?;
        let src = image
            .get(..size_of_headers)
            .ok_or(anyhow::anyhow!("Failed to get headers"))?;
        dst.copy_from_slice(src);

        // Copy the sections.
        for section in pe.sections {
            let mut size = section.virtual_size;
            if size == 0 || size > section.size_of_raw_data {
                size = section.size_of_raw_data;
            }

            let dst = loaded_image
                .get_mut(
                    (section.virtual_address as usize)
                        ..(section.virtual_address.wrapping_add(size) as usize),
                )
                .ok_or(anyhow::anyhow!("Failed to get section"))?;
            let src = image
                .get(
                    (section.pointer_to_raw_data as usize)
                        ..(section.pointer_to_raw_data.wrapping_add(size) as usize),
                )
                .ok_or(anyhow::anyhow!("Failed to get section"))?;
            dst.copy_from_slice(src);
        }

        Ok(loaded_image)
    }

    fn build_symbol_padding_entries(
        &mut self,
        report: &report::Coverage,
    ) -> Result<Vec<(file::ImageValidationEntryHeader, Vec<u8>)>> {
        Ok(report
            .segments(|s| !s.covered() && s.symbol().is_empty())
            .iter()
            .map(|segment| {
                let content = vec![0; (segment.end() - segment.start()) as usize];
                let entry = file::ImageValidationEntryHeader {
                    offset: segment.start(),
                    size: segment.end() - segment.start(),
                    validation_type: file::ValidationType::Content {
                        content: content.clone(),
                    },
                    ..Default::default()
                };
                (entry, content)
            })
            .collect())
    }

    fn build_field_padding_entries(
        &mut self,
        report: &report::Coverage,
    ) -> Result<Vec<(file::ImageValidationEntryHeader, Vec<u8>)>> {
        let mut ret = Vec::new();
        let symbols = report.segments(|s| !s.covered() && !s.symbol().is_empty());

        // For each symbol that is not covered, if that symbol is a class and all fields are covered, then the missing
        // segment must be padding between fields, so we can add an entry for it.
        for uncovered in symbols {
            if let Some(fields) = self.symbol_fields(uncovered.symbol()) {
                // We must also consider that the symbol is an array where the elements are the underlying class. In
                // This case, we need to check all fields for the specific index are covered before we can properly add
                // any padding.
                let idx = self.symbol_idx(uncovered.symbol(), uncovered.start());
                let covered = fields.iter().all(|field| {
                    let expected = match idx {
                        Some(idx) => format!("{}[{}].{}", uncovered.symbol(), idx, field),
                        None => format!("{}.{}", uncovered.symbol(), field),
                    };
                    !report.segments(|s| s.symbol() == expected).is_empty()
                });

                if covered {
                    ret.push((
                        file::ImageValidationEntryHeader {
                            offset: uncovered.start(),
                            size: uncovered.end() - uncovered.start(),
                            validation_type: file::ValidationType::Content {
                                content: vec![0; (uncovered.end() - uncovered.start()) as usize],
                            },
                            ..Default::default()
                        },
                        vec![0; (uncovered.end() - uncovered.start()) as usize],
                    ));
                }
            }
        }

        Ok(ret)
    }
}

pub struct Section {
    pub name: String,
    range: Range<u32>,
    pub symbols: Vec<Symbol>,
}

/// What a rule iterates over, and how large each entry it produces is.
struct RuleExtent {
    /// Offset of the field within the symbol, or zero when the rule targets the symbol itself.
    field_offset: u32,
    /// Distance between consecutive entries.
    stride: u32,
    /// Size of each entry.
    size: u32,
    /// Number of entries the rule can produce.
    count: usize,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub address: u32,
    pub name: String,
    type_info: TypeInfo,
}

impl Symbol {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self, index: usize) -> u32 {
        self.address + (self.type_info.element_size() * index as u32)
    }

    fn from_pdb_symbol(
        symbol: pdb::Symbol<'_>,
        address_map: &AddressMap<'_>,
        type_information: &TypeInformation<'_>,
    ) -> Result<Option<Self>> {
        // let address_map = pdb.address_map()?;
        // let type_information = pdb.type_information()?;
        Ok(match symbol.parse() {
            Ok(pdb::SymbolData::Public(data)) if data.function => {
                Some(Self::from_public(data, address_map))
            }
            Ok(pdb::SymbolData::Data(data)) => {
                Some(Self::from_data(data, address_map, type_information)?)
            }
            Ok(pdb::SymbolData::Procedure(data)) => Some(Self::from_procedure(data, address_map)),
            Ok(pdb::SymbolData::Label(data)) => Some(Self::from_label(data, address_map)),
            _ => None,
        })
    }

    pub fn size(&self) -> u32 {
        self.type_info.total_size()
    }

    fn from_public(symbol: pdb::PublicSymbol<'_>, address_map: &AddressMap<'_>) -> Self {
        let address = symbol.offset.to_rva(address_map).unwrap_or_default().0;
        let type_info = TypeInfo::one(POINTER_LENGTH as u32, None);
        let name = symbol.name.to_string().to_string();

        Symbol {
            address,
            name,
            type_info,
        }
    }

    fn from_data(
        symbol: DataSymbol<'_>,
        address_map: &AddressMap<'_>,
        type_info: &TypeInformation,
    ) -> Result<Self> {
        let address = symbol.offset.to_rva(address_map).unwrap_or_default().0;
        let type_info = TypeInfo::from_type_index(type_info, symbol.type_index)?;
        let name = symbol.name.to_string().to_string();

        Ok(Symbol {
            address,
            name,
            type_info,
        })
    }

    fn from_procedure(symbol: pdb::ProcedureSymbol<'_>, address_map: &AddressMap<'_>) -> Self {
        let address = symbol.offset.to_rva(address_map).unwrap_or_default().0;
        let type_info = TypeInfo::one(POINTER_LENGTH as u32, Some(symbol.type_index));
        let name = symbol.name.to_string().to_string();

        Symbol {
            address,
            name,
            type_info,
        }
    }

    fn from_label(symbol: pdb::LabelSymbol<'_>, address_map: &AddressMap<'_>) -> Self {
        let address = symbol.offset.to_rva(address_map).unwrap_or_default().0;
        let type_info = TypeInfo::one(POINTER_LENGTH as u32, None);
        let name = symbol.name.to_string().to_string();

        Symbol {
            address,
            name,
            type_info,
        }
    }

    /// Returns the offset and size of a field in a class or union.
    fn find_field_offset_and_size(
        info: &TypeInformation,
        id: &TypeIndex,
        attribute: &str,
        symbol: &str,
    ) -> Result<(u32, u32)> {
        let (offset, type_info) = Self::find_field(info, id, attribute, symbol)?;
        Ok((offset, type_info.total_size()))
    }

    /// Returns the offset of a field within its symbol, along with the type of the field.
    ///
    /// The type is returned rather than just a size so that a rule can tell an array field from a
    /// single value and iterate its elements.
    fn find_field(
        info: &TypeInformation,
        id: &TypeIndex,
        attribute: &str,
        symbol: &str,
    ) -> Result<(u32, TypeInfo)> {
        Self::find_field_offset_and_size_at(info, id, attribute, symbol, 0)
    }

    /// Walks a dotted field path, transparently descending through wrapper types.
    ///
    /// `depth` counts only the wrapper layers that were skipped implicitly, and exists solely to
    /// stop a malformed PDB from producing an unbounded descent.
    fn find_field_offset_and_size_at(
        info: &TypeInformation,
        id: &TypeIndex,
        attribute: &str,
        symbol: &str,
        depth: u32,
    ) -> Result<(u32, TypeInfo)> {
        const MAX_WRAPPER_DEPTH: u32 = 32;

        let mut parts = attribute.splitn(2, '.');
        let name = parts.next().unwrap_or("");
        let remaining = parts.next().unwrap_or("");

        let aggregate =
            Aggregate::new(&TypeInfo::find_type(info, *id)?.parse()?).ok_or_else(|| {
                anyhow!(
                    "Symbol [{}] is not a class or union. Cannot get fields.",
                    symbol
                )
            })?;

        // Theoretically unreachable as you cannot have a struct defined without fields in C.
        let field_list = aggregate
            .fields
            .ok_or_else(|| anyhow!("Symbol [{}] is a class, but has no fields.", symbol))?;
        let parent_size = aggregate.size;

        let TypeData::FieldList(fields) = TypeInfo::find_type(info, field_list)?.parse()? else {
            // Theoretically unreachable, unless the pdb file is malformed or there is a bug in the
            // pdb crate code.
            return Err(anyhow::anyhow!(
                "UNEXPECTED: Symbol [{}] fields are not a field list.",
                symbol
            ));
        };

        let mut members = Vec::new();
        for field in fields.fields {
            if let TypeData::Member(member) = field {
                if member.name.to_string() == name {
                    if !remaining.is_empty() {
                        let (offset, size) = Self::find_field_offset_and_size_at(
                            info,
                            &member.field_type,
                            remaining,
                            symbol,
                            depth,
                        )?;
                        return Ok((member.offset as u32 + offset, size));
                    }
                    let size = TypeInfo::from_type_index(info, member.field_type)?;
                    return Ok((member.offset as u32, size));
                }
                members.push((
                    member.name.to_string().to_string(),
                    member.offset,
                    member.field_type,
                ));
            }
        }

        // Nothing matched at this level. A record whose single populated member starts at offset
        // 0 and spans the whole parent contributes a name and no storage, so descend through it
        // and retry; config paths then only name the fields a reader would recognize. Rust
        // produces this shape constantly via `UnsafeCell`, `ManuallyDrop`, `MaybeUninit` and
        // newtypes. Explicit paths still work, because this runs only after an exact match fails.
        if depth < MAX_WRAPPER_DEPTH {
            if let Some(inner) = Self::transparent_wrapper_member(info, &members, parent_size) {
                return Self::find_field_offset_and_size_at(
                    info,
                    &inner,
                    attribute,
                    symbol,
                    depth + 1,
                );
            }
        }

        Err(anyhow::anyhow!(
            "Field [{}] not found in symbol [{}]. Available fields at this level: [{}]",
            name,
            symbol,
            members
                .iter()
                .map(|(name, ..)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }

    /// Returns the type of the sole data-carrying member if `members` describes a transparent
    /// wrapper, meaning exactly one member that begins at offset 0 and covers the full
    /// `parent_size`. Members are only disregarded when they are provably zero sized, so a
    /// member that occupies storage can never be stepped over.
    ///
    /// Returns `None` whenever the shape is ambiguous or a member size cannot be resolved, so an
    /// unrecognized layout reports the original "field not found" error rather than guessing.
    fn transparent_wrapper_member(
        info: &TypeInformation,
        members: &[(String, u64, TypeIndex)],
        parent_size: u64,
    ) -> Option<TypeIndex> {
        if parent_size == 0 {
            return None;
        }

        let mut payload = None;
        for (_, offset, field_type) in members {
            if Self::is_provably_zero_sized(info, *field_type) {
                continue;
            }
            if payload.is_some() {
                return None;
            }
            // Any member that is not provably empty must account for the whole parent, otherwise
            // this is a real aggregate and stepping through it would skip storage.
            let size = TypeInfo::from_type_index(info, *field_type)
                .ok()?
                .total_size();
            if *offset != 0 || size as u64 != parent_size {
                return None;
            }
            payload = Some(*field_type);
        }
        payload
    }

    /// Returns whether `index` refers to a type that provably occupies no storage.
    ///
    /// Only a complete aggregate definition that records a size of zero qualifies. A computed
    /// size of zero is deliberately not accepted, because several type encodings yield zero when
    /// the size is merely unknown: `PrimitiveKind::NoType`, and arrays whose declared byte length
    /// is smaller than one element. Forward references are rejected as well, since their size is
    /// a placeholder rather than a statement about the real definition.
    fn is_provably_zero_sized(info: &TypeInformation, index: TypeIndex) -> bool {
        // Bound the walk so a malformed PDB cannot produce an unbounded modifier chain.
        const MAX_MODIFIER_DEPTH: u32 = 32;

        let mut index = index;
        for _ in 0..MAX_MODIFIER_DEPTH {
            let Ok(data) = TypeInfo::find_type(info, index).and_then(|item| Ok(item.parse()?))
            else {
                return false;
            };
            match data {
                // Qualifiers do not change the size of the underlying type.
                TypeData::Modifier(modifier) => index = modifier.underlying_type,
                data => {
                    return Aggregate::new(&data)
                        .is_some_and(|a| a.size == 0 && !a.forward_reference)
                }
            }
        }
        false
    }
}

#[derive(Default, Clone, Copy)]
/// A struct that represents the type information of a symbol.
pub struct TypeInfo {
    element_size: u32,
    element_type: Option<TypeIndex>,
    pub count: usize,
}

impl std::fmt::Debug for TypeInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(r#type) = self.element_type {
            write!(
                f,
                "TypeInfo {{ element_type: {:?}, element_size: 0x{:08X}, count: {} }}",
                r#type, self.element_size, self.count
            )
        } else {
            write!(
                f,
                "TypeInfo {{ element_size: 0x{:08X}, count: {} }}",
                self.element_size, self.count
            )
        }
    }
}

impl TypeInfo {
    /// Creates a new TypeInfo with the given size and type id.
    pub fn one(size: u32, type_id: Option<TypeIndex>) -> Self {
        Self {
            element_size: size,
            element_type: type_id,
            count: 1,
        }
    }

    /// Creates a new TypeInfo that is a array of the given size and type id.
    pub fn many(size: u32, count: usize, type_id: Option<TypeIndex>) -> Self {
        Self {
            element_size: size,
            element_type: type_id,
            count,
        }
    }

    /// Returns the total size of the type.
    pub fn total_size(&self) -> u32 {
        self.element_size * self.count as u32
    }

    /// Returns the size of the single element.
    pub fn element_size(&self) -> u32 {
        self.element_size
    }

    /// Returns the number of elements in the type.
    pub fn element_count(&self) -> usize {
        self.count
    }

    /// Returns the type id of the underlying type.
    pub fn type_id(&self) -> Option<TypeIndex> {
        self.element_type
    }

    /// Creates a new TypeInfo from the given type index.
    pub fn from_type_index(info: &TypeInformation, index: TypeIndex) -> Result<Self> {
        Self::from_type_data(info, Self::find_type(info, index)?.parse()?, index)
    }

    /// Creates a new TypeInfo from the given type data.
    pub fn from_type_data(
        info: &TypeInformation,
        data: TypeData,
        index: TypeIndex,
    ) -> Result<Self> {
        // A class and a union are both sized aggregates; only their member layout differs.
        if let Some(aggregate) = Aggregate::new(&data) {
            return Ok(TypeInfo::one(aggregate.size as u32, Some(index)));
        }

        Ok(match data {
            TypeData::Primitive(prim) => {
                if prim.indirection.is_some() {
                    TypeInfo::one(POINTER_LENGTH as u32, Some(index))
                } else {
                    TypeInfo::one(Self::get_size_from_primitive(prim.kind), Some(index))
                }
            }
            TypeData::VirtualFunctionTablePointer(_) => {
                TypeInfo::one(POINTER_LENGTH as u32, Some(index))
            }
            TypeData::Pointer(_) => TypeInfo::one(POINTER_LENGTH as u32, Some(index)),
            TypeData::Modifier(modifier) => {
                TypeInfo::from_type_index(info, modifier.underlying_type)?
            }
            pdb::TypeData::Enumeration(enm) => {
                TypeInfo::from_type_index(info, enm.underlying_type)?
            }
            TypeData::Array(arr) => {
                // The recursive nature of `TypeInfo::from_type_index` flattens n-dimensional arrays into a single
                // dimension. This is because for each dimension, `element.total_size()` is the size of the current
                // dimension. By using `element.element_size()` instead, we bubble up the size of the true element
                // type, which is ultimately divided by the total size of the symbol.
                let total_size = arr.dimensions[0] as usize;
                let element = TypeInfo::from_type_index(info, arr.element_type)?;
                let element_size = element.element_size();
                // Guard against a zero-sized element type.
                let count = if element_size == 0 {
                    1
                } else {
                    total_size / element_size as usize
                };
                TypeInfo::many(element_size, count, element.type_id())
            }
            // We don't have a good way to deal with bit-fields in this code, so we just return the size of the
            // underlying type. This is a limitation of the current implementation because the size we set is in bytes,
            // but the size of a particular bit-field is in bits. If we ever wish to make a rule for individual
            // bit-fields (similar to how we do for fields in a class) we will need to change this. Probably to make
            // the TypeInfo struct we return deal with sizes in bites instead of Bytes.
            pdb::TypeData::Bitfield(bf) => TypeInfo::from_type_index(info, bf.underlying_type)?,
            TypeData::FieldList(fl) => {
                let mut size = 0;
                for type_data in fl.fields {
                    size += TypeInfo::from_type_data(info, type_data, index)?.total_size();
                }
                if let Some(cont) = fl.continuation {
                    size += TypeInfo::from_type_index(info, cont)?.total_size();
                }
                TypeInfo::one(size, Some(index))
            }
            TypeData::ArgumentList(al) => {
                let mut size = 0;
                for item in al.arguments {
                    size += TypeInfo::from_type_index(info, item)?.total_size();
                }
                TypeInfo::one(size, Some(index))
            }
            data => {
                return Err(anyhow!("Unhandled TypeData for C Code: {:?}", data));
            }
        })
    }

    /// Returns a type using the type index. If the type is a class or union with size 0, it will
    /// check for a shadow definition with the real information, returning that instead.
    fn find_type<'a>(info: &'a TypeInformation, index: TypeIndex) -> Result<Item<'a, TypeIndex>> {
        let mut iter = info.iter();
        let mut finder = info.finder();

        while (iter.next()?).is_some() {
            finder.update(&iter)
        }

        let data = finder.find(index)?;
        let item = data.parse()?;

        // Anything that is not a zero-size forward reference is returned as-is. That includes a
        // size-0 complete definition, which is a genuine zero-sized type rather than a stand-in.
        let type_name = match Aggregate::new(&item) {
            Some(aggregate) if aggregate.size == 0 && aggregate.forward_reference => {
                aggregate.name.to_string().to_string()
            }
            _ => return Ok(data),
        };

        // The record was a size-0 forward reference, so it should have a shadow definition
        // carrying the real information.
        if let Some(item) = Self::find_aggregate(info, &type_name, |a| a.size != 0) {
            return Ok(item);
        }

        // The forward reference may describe a type whose real definition is genuinely zero
        // sized, such as an empty aggregate or Rust's `PhantomData`. No non-zero-sized definition
        // can exist for those, so accept a complete (non-forward-reference) definition instead. A
        // forward reference with no definition at all matches neither and falls through to the
        // error below, so a genuinely missing type is not masked.
        if let Some(item) = Self::find_aggregate(info, &type_name, |a| !a.forward_reference) {
            return Ok(item);
        }

        Err(anyhow!("Symbol {} was found, but size was 0", type_name))
    }

    /// Scans the type stream for a class or union named `name` that satisfies `accept`.
    fn find_aggregate<'a>(
        info: &'a TypeInformation,
        name: &str,
        accept: impl Fn(&Aggregate) -> bool,
    ) -> Option<Item<'a, TypeIndex>> {
        let mut iter = info.iter();
        iter.find(|item| {
            let data = item.parse()?;
            Ok(Aggregate::new(&data).is_some_and(|a| a.name.to_string() == name && accept(&a)))
        })
        .ok()
        .flatten()
    }

    /// Returns the size of a primitive type in bytes.
    fn get_size_from_primitive(primitive: pdb::PrimitiveKind) -> u32 {
        match primitive {
            PrimitiveKind::NoType => 0,
            PrimitiveKind::Void => POINTER_LENGTH as u32,
            PrimitiveKind::Char => 1,
            PrimitiveKind::UChar => 1,
            PrimitiveKind::WChar => 1,
            PrimitiveKind::RChar => 1,
            PrimitiveKind::RChar16 => 2,
            PrimitiveKind::RChar32 => 4,
            PrimitiveKind::I8 => 1,
            PrimitiveKind::U8 => 1,
            PrimitiveKind::Short => 2,
            PrimitiveKind::UShort => 2,
            PrimitiveKind::I16 => 2,
            PrimitiveKind::U16 => 2,
            PrimitiveKind::Long => 4,
            PrimitiveKind::ULong => 4,
            PrimitiveKind::I32 => 4,
            PrimitiveKind::U32 => 4,
            PrimitiveKind::Quad => 8,
            PrimitiveKind::UQuad => 8,
            PrimitiveKind::I64 => 8,
            PrimitiveKind::U64 => 8,
            PrimitiveKind::Octa => 16,
            PrimitiveKind::UOcta => 16,
            PrimitiveKind::I128 => 16,
            PrimitiveKind::U128 => 16,
            PrimitiveKind::F16 => 2,
            PrimitiveKind::F32 => 4,
            PrimitiveKind::F32PP => 4,
            PrimitiveKind::F48 => 6,
            PrimitiveKind::F64 => 8,
            PrimitiveKind::F80 => 10,
            PrimitiveKind::F128 => 16,
            PrimitiveKind::Complex32 => 8,
            PrimitiveKind::Complex64 => 16,
            PrimitiveKind::Complex80 => 20,
            PrimitiveKind::Complex128 => 32,
            PrimitiveKind::Bool8 => 1,
            PrimitiveKind::Bool16 => 2,
            PrimitiveKind::Bool32 => 4,
            PrimitiveKind::Bool64 => 8,
            _ => {
                println!("ERROR: Unhandled Primitive: {:?}", primitive);
                0
            }
        }
    }
}

#[cfg(test)]
mod test {
    use r_efi::efi::Guid;

    use super::*;

    use crate::{
        config::{Array, Key, Rule, Validation},
        file::AuxFile,
        report::Coverage,
    };

    use std::{fs::File, io::Write, path::PathBuf};

    fn build_metadata() -> PdbMetadata<'static, Cursor<&'static [u8]>> {
        let pdb = include_bytes!("../resources/test/example.pdb");
        let efi = include_bytes!("../resources/test/example.efi");
        PdbMetadata::<'static, Cursor<&'static [u8]>>::new(pdb, efi)
            .expect("Failed to build metadata")
    }

    #[test]
    fn test_metadata_new_with_good_files() {
        let mut pdb = tempfile::NamedTempFile::new().unwrap();
        pdb.write_all(include_bytes!("../resources/test/example.pdb"))
            .unwrap();
        let mut efi = tempfile::NamedTempFile::new().unwrap();
        efi.write_all(include_bytes!("../resources/test/example.efi"))
            .unwrap();
        assert!(
            PdbMetadata::<File>::new(pdb.path().to_path_buf(), efi.path().to_path_buf()).is_ok()
        );
    }

    #[test]
    fn test_metadata_new_with_good_buffers() {
        let pdb = include_bytes!("../resources/test/example.pdb");
        let efi = include_bytes!("../resources/test/example.efi");
        assert!(PdbMetadata::<Cursor<&[u8]>>::new(pdb, efi).is_ok());
    }

    #[test]
    fn test_new_with_bad_files() {
        let mut pdb = tempfile::NamedTempFile::new().unwrap();
        pdb.write_all(include_bytes!("../resources/test/example.pdb"))
            .unwrap();
        assert!(pdb.path().exists());

        let mut efi = tempfile::NamedTempFile::new().unwrap();
        efi.write_all(include_bytes!("../resources/test/example.efi"))
            .unwrap();
        assert!(efi.path().exists());

        // pdb path does not exist
        assert!(PdbMetadata::<File>::new(
            PathBuf::from("non_existent.pdb"),
            PathBuf::from("non_existent.bin")
        )
        .is_err());

        // pdb path exists, but file does not
        assert!(PdbMetadata::<File>::new(
            pdb.path().to_path_buf(),
            PathBuf::from("non_existent.bin")
        )
        .is_err());

        // pdb path exists, but is not a pdb file
        assert!(
            PdbMetadata::<File>::new(efi.path().to_path_buf(), efi.path().to_path_buf()).is_err()
        );
        // file exists, but is not a efi binary
        assert!(
            PdbMetadata::<File>::new(pdb.path().to_path_buf(), pdb.path().to_path_buf()).is_err()
        );
    }

    #[test]
    fn test_new_with_bad_buffers() {
        let pdb = include_bytes!("../resources/test/example.pdb");
        let efi = include_bytes!("../resources/test/example.efi");

        // pdb buffer is not a pdb file
        assert!(PdbMetadata::<Cursor<&[u8]>>::new(efi, efi).is_err());

        // efi buffer is not a efi binary
        assert!(PdbMetadata::<Cursor<&[u8]>>::new(pdb, pdb).is_err());
    }

    #[test]
    fn test_build_entries_with_elements() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mMmSupvPoolLists".to_string(),
            array: Some(Array {
                field: None,
                sentinel: false,
                index: Some(1usize..=2usize),
            }),
            validation: config::Validation::None,
            ..Default::default()
        };

        let entries = metadata
            .build_entries(&rule)
            .unwrap_or_else(|e| panic!("Failed to build entries: [{}]", e));

        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_build_entries_with_field() {
        let mut metadata = build_metadata();

        let rule1 = Rule {
            symbol: "mMmSupvPoolLists".to_string(),
            field: Some("ForwardLink".to_string()),
            validation: config::Validation::None,
            ..Default::default()
        };

        let rule2 = Rule {
            symbol: "mMmSupvPoolLists".to_string(),
            validation: config::Validation::None,
            ..Default::default()
        };

        let entries1 = metadata
            .build_entries(&rule1)
            .unwrap_or_else(|e| panic!("Failed to build entries: [{}]", e));
        assert_eq!(entries1.len(), 12); // Did not specify a range, so it created this rule for all list elements.
        let entries2 = metadata
            .build_entries(&rule2)
            .unwrap_or_else(|e| panic!("Failed to build entries: [{}]", e));
        assert_eq!(entries2.len(), 12); // Did not specify a field, so it created this rule for the entire symbol.

        for (entry1, entry2) in entries1.iter().zip(entries2.iter()) {
            // entry1 is for the first field in the symbol while entry2 is for the entire symbol
            // Due to this, the offset should be the same but the size should be different.)
            assert_eq!(entry1.0.offset, entry2.0.offset);
            assert!(entry1.0.size < entry2.0.size);
        }
    }

    #[test]
    fn test_build_entries_with_elements_and_sentinel() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mMmSupvPoolLists".to_string(),
            validation: config::Validation::None,
            array: Some(Array {
                field: None,
                sentinel: true,
                index: None,
            }),
            ..Default::default()
        };

        let entries = metadata
            .build_entries(&rule)
            .unwrap_or_else(|e| panic!("Failed to build entries: [{}]", e));
        assert_eq!(entries.len(), 12);

        // All but the last entry should have a validation type of None.
        for entry in entries.iter().rev().skip(1) {
            assert_eq!(entry.0.validation_type, file::ValidationType::None);
        }

        // The last entry should have a validation type of Content with a sentinel value.
        if let Some(file::ValidationType::Content { content }) =
            entries.last().map(|e| &e.0.validation_type)
        {
            // mmSupvPoolLists is a list of structs that have 2 pointers. So the size is 2 pointers.
            assert_eq!(
                content.as_slice(),
                vec![0x00; (POINTER_LENGTH * 2) as usize].as_slice()
            );
        } else {
            panic!("Last entry should have a sentinel value.");
        };
    }

    #[test]
    #[should_panic(expected = "Symbol ABCDEFG not found in PDB file.")]
    fn test_build_key_symbol_missing_symbol() {
        let mut metadata = build_metadata();

        let key = Key {
            symbol: "ABCDEFG".to_string(),
            signature: ['L', 'O', 'O', 'L'],
            field: None,
        };

        // This will panic
        let _ = metadata.build_key_symbol(&key);
    }
    #[test]
    fn test_build_key_symbol_without_field_uses_symbol_address() {
        let mut metadata = build_metadata();
        let expected_address = metadata.find_symbol("mMmSupvPoolLists").address;

        let key = Key {
            symbol: "mMmSupvPoolLists".to_string(),
            signature: ['P', 'O', 'O', 'L'],
            field: None,
        };

        let key_symbol = metadata
            .build_key_symbol(&key)
            .unwrap_or_else(|e| panic!("Failed to build key symbol: [{}]", e));
        assert_eq!(key_symbol.signature, 0x4c_4f_4f_50); // 'POOL'
        assert_eq!(key_symbol.offset, expected_address);
    }

    #[test]
    fn test_build_key_symbol_with_field_adds_field_offset() {
        let mut metadata = build_metadata();
        let symbol_address = metadata.find_symbol("mRootMmiEntry").address;
        let key = Key {
            symbol: "mRootMmiEntry".to_string(),
            signature: ['L', 'I', 'S', 'T'],
            field: Some("AllEntries".to_string()),
        };

        let key_symbol = metadata
            .build_key_symbol(&key)
            .unwrap_or_else(|e| panic!("Failed to build key symbol: [{}]", e));

        assert_eq!(key_symbol.signature, 0x54_53_49_4c); // 'LIST'
        assert_eq!(key_symbol.offset, symbol_address + 0x8);
    }

    #[test]
    fn test_build_key_symbol_with_invalid_field_fails() {
        let mut metadata = build_metadata();
        let key = Key {
            symbol: "mRootMmiEntry".to_string(),
            signature: ['L', 'I', 'S', 'T'],
            field: Some("NonExistentField".to_string()),
        };

        let error = metadata
            .build_key_symbol(&key)
            .expect_err("an invalid key field should fail");

        assert!(error
            .to_string()
            .contains("Field [NonExistentField] not found in symbol [mRootMmiEntry]"));
    }

    #[test]
    fn test_build_symbol_padding_entries() {
        let mut metadata = build_metadata();
        let aux = AuxFile::default();

        let coverage = Coverage::build(&aux, &mut metadata)
            .unwrap_or_else(|e| panic!("Failed to build coverage: [{}]", e));
        let entries = metadata
            .build_symbol_padding_entries(&coverage)
            .unwrap_or_else(|e| panic!("Failed to build symbol padding entries: [{}]", e));

        // In this exact binary, we have 39 areas of padding between symbols in a R/W section, for alignment purposes.
        // If we start detecting more or less, then the new change is wrong, or we were wrong.
        // Not the best way to write tests, but this will at least prevent regressions.
        assert_eq!(entries.len(), 39);
    }

    #[test]
    fn test_build_field_padding_entries() {
        // mImagePropertiesPrivateData has padding between symbols. Adding a rule for each individual field
        // should make it such that we can detect the padding between fields, and generate entries with
        // build_field_padding_entries.
        let rules = {
            let mut rules = Vec::new();
            for field in [
                "Signature",
                "ImageRecordCount",
                "CodeSegmentCountMax",
                "ImageRecordList",
            ] {
                rules.push(Rule {
                    symbol: "mImagePropertiesPrivateData".to_string(),
                    field: Some(field.to_string()),
                    validation: config::Validation::None,
                    ..Default::default()
                })
            }
            rules
        };

        let mut metadata = build_metadata();
        let mut entries = {
            let mut entries = Vec::new();
            for rule in rules {
                entries.extend(
                    metadata
                        .build_entries(&rule)
                        .unwrap_or_else(|e| panic!("Failed to build entries: [{}]", e)),
                );
            }
            entries
        };

        let mut aux = AuxFile::default();

        for entry in entries.drain(..) {
            aux.add_entry(entry.0, &entry.1);
        }

        let coverage = Coverage::build(&aux, &mut metadata)
            .unwrap_or_else(|e| panic!("Failed to build coverage: [{}]", e));
        let entries = metadata
            .build_field_padding_entries(&coverage)
            .unwrap_or_else(|e| panic!("Failed to build field padding entries: [{}]", e));

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.offset, 0x0000_3766C); // Hardcoded for this specific binary.
        assert_eq!(entries[0].0.size, 0x0000_0004); // Hardcoded for this specific binary.

        // The 1 field padding we created, plus the 39 symbol padding entries, should give us a total of 40 entries.
        assert_eq!(
            metadata.create_padding_entries(&coverage).unwrap().len(),
            40
        );
    }

    #[test]
    fn test_validate_rule_content() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mSmmCpuService".to_string(),
            validation: config::Validation::Content {
                content: vec![0x0; 48],
            },
            ..Default::default()
        };

        let symbol = metadata.find_symbol("mSmmCpuService").clone();

        metadata
            .validate_rule(&symbol, &rule)
            .unwrap_or_else(|e| panic!("Failed to validate rule: [{}]", e));
    }

    #[test]
    fn test_validate_rule_content_bad_size() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mSmmCpuService".to_string(),
            validation: config::Validation::Content {
                content: vec![0x0; 32],
            },
            ..Default::default()
        };

        let symbol = metadata.find_symbol("mSmmCpuService").clone();

        match metadata.validate_rule(&symbol, &rule) {
            Ok(_) => panic!("Expected validation to fail"),
            Err(e) => {
                assert!(e.to_string().contains("does not match symbol size"));
            }
        }
    }

    #[test]
    fn test_validate_rule_content_and_field() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mUnblockedMemoryList".to_string(),
            field: Some("ForwardLink".to_string()),
            validation: config::Validation::Content {
                content: vec![0x0; 8],
            },
            ..Default::default()
        };

        let symbol = metadata.find_symbol("mUnblockedMemoryList").clone();

        metadata
            .validate_rule(&symbol, &rule)
            .unwrap_or_else(|e| panic!("Failed to validate rule: [{}]", e));
    }

    #[test]
    fn test_validate_rule_content_and_field_bad_size() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mUnblockedMemoryList".to_string(),
            field: Some("ForwardLink".to_string()),
            validation: config::Validation::Content {
                content: vec![0x0; 4],
            },
            ..Default::default()
        };

        let symbol = metadata.find_symbol("mUnblockedMemoryList").clone();

        assert!(metadata.validate_rule(&symbol, &rule).is_err());
    }

    #[test]
    fn test_validate_rule_when_array_config_but_symbol_not_array() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mUnblockedMemoryList".to_string(),
            array: Some(Array {
                field: None,
                sentinel: false,
                index: Some(1..=2),
            }),
            validation: config::Validation::Content {
                content: vec![0x0; 16],
            },
            ..Default::default()
        };

        let symbol = metadata.find_symbol("mUnblockedMemoryList").clone();

        match metadata.validate_rule(&symbol, &rule) {
            Ok(_) => panic!("Expected validation to fail"),
            Err(e) => {
                assert!(e.to_string().contains("is not an array"));
            }
        }
    }

    #[test]
    fn test_validate_rule_when_array_index_and_array_sentinel_is_set() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mReservedVectorsData".to_string(),
            array: Some(Array {
                field: None,
                sentinel: true,
                index: Some(1..=2),
            }),
            validation: config::Validation::Content {
                content: vec![0x0; 96],
            },
            ..Default::default()
        };

        let symbol = metadata.find_symbol("mReservedVectorsData").clone();

        match metadata.validate_rule(&symbol, &rule) {
            Ok(_) => panic!("Expected validation to fail"),
            Err(e) => {
                assert!(e.to_string().contains("cannot be combined"));
            }
        }
    }

    #[test]
    fn test_validate_rule_index_out_of_bounds() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mMmSupvPoolLists".to_string(),
            array: Some(Array {
                field: None,
                sentinel: false,
                index: Some(99..=99),
            }),
            validation: config::Validation::Content {
                content: vec![0x0; 16],
            },
            ..Default::default()
        };

        let symbol = metadata.find_symbol("mMmSupvPoolLists").clone();

        match metadata.validate_rule(&symbol, &rule) {
            Ok(_) => panic!("Expected validation to fail"),
            Err(e) => {
                assert!(e.to_string().contains("is out of bounds"));
            }
        }
    }

    #[test]
    fn test_build_validation_type() {
        let metadata = build_metadata();

        let v = metadata
            .build_validation_type(&Validation::None)
            .unwrap_or_else(|e| panic!("Failed to build validation type: [{}]", e));
        assert_eq!(v, file::ValidationType::None);

        let v = metadata
            .build_validation_type(&Validation::Content {
                content: vec![0x0; 8],
            })
            .unwrap_or_else(|e| panic!("Failed to build validation type: [{}]", e));
        assert_eq!(
            v,
            file::ValidationType::Content {
                content: vec![0x0; 8]
            }
        );

        let v = metadata
            .build_validation_type(&Validation::NonZero)
            .unwrap_or_else(|e| panic!("Failed to build validation type: [{}]", e));
        assert_eq!(v, file::ValidationType::NonZero);

        let v = metadata
            .build_validation_type(&Validation::Guid {
                guid: Guid::from_fields(0xffffffff, 0, 0, 0, 0, &[0, 0, 0, 0, 0, 0]),
            })
            .unwrap_or_else(|e| panic!("Failed to build validation type: [{}]", e));
        assert_eq!(
            v,
            file::ValidationType::Content {
                content: vec![
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00
                ]
            }
        );

        let v = metadata
            .build_validation_type(&Validation::MemAttr {
                memory_size: 0x1,
                must_have: 0x2,
                must_not_have: 0x3,
            })
            .unwrap_or_else(|e| panic!("Failed to build validation type: [{}]", e));
        assert_eq!(
            v,
            file::ValidationType::MemAttr {
                memory_size: 0x1,
                must_have: 0x2,
                must_not_have: 0x3
            }
        );

        let v = metadata
            .build_validation_type(&Validation::Pointer { in_mseg: true })
            .unwrap_or_else(|e| panic!("Failed to build validation type: [{}]", e));
        assert_eq!(v, file::ValidationType::Pointer { in_mseg: true });

        let v = metadata
            .build_validation_type(&Validation::Ref {
                reference: "mUnblockedMemoryList".to_string(),
            })
            .unwrap_or_else(|e| panic!("Failed to build validation type: [{}]", e));
        assert_eq!(
            v,
            file::ValidationType::Ref {
                address: 0x0003_76D8
            }
        );
    }

    #[test]
    fn test_type_info_primitive_size_values() {
        // This test is purely to acknowledge that adjusting the primitive size values is dangerous and probably wrong.
        assert_eq!(0, TypeInfo::get_size_from_primitive(PrimitiveKind::NoType));
        assert_eq!(
            POINTER_LENGTH as u32,
            TypeInfo::get_size_from_primitive(PrimitiveKind::Void)
        );
        assert_eq!(1, TypeInfo::get_size_from_primitive(PrimitiveKind::Char));
        assert_eq!(1, TypeInfo::get_size_from_primitive(PrimitiveKind::UChar));
        assert_eq!(1, TypeInfo::get_size_from_primitive(PrimitiveKind::WChar));
        assert_eq!(1, TypeInfo::get_size_from_primitive(PrimitiveKind::RChar));
        assert_eq!(2, TypeInfo::get_size_from_primitive(PrimitiveKind::RChar16));
        assert_eq!(4, TypeInfo::get_size_from_primitive(PrimitiveKind::RChar32));
        assert_eq!(1, TypeInfo::get_size_from_primitive(PrimitiveKind::I8));
        assert_eq!(1, TypeInfo::get_size_from_primitive(PrimitiveKind::U8));
        assert_eq!(2, TypeInfo::get_size_from_primitive(PrimitiveKind::Short));
        assert_eq!(2, TypeInfo::get_size_from_primitive(PrimitiveKind::UShort));
        assert_eq!(2, TypeInfo::get_size_from_primitive(PrimitiveKind::I16));
        assert_eq!(2, TypeInfo::get_size_from_primitive(PrimitiveKind::U16));
        assert_eq!(4, TypeInfo::get_size_from_primitive(PrimitiveKind::Long));
        assert_eq!(4, TypeInfo::get_size_from_primitive(PrimitiveKind::ULong));
        assert_eq!(4, TypeInfo::get_size_from_primitive(PrimitiveKind::I32));
        assert_eq!(4, TypeInfo::get_size_from_primitive(PrimitiveKind::U32));
        assert_eq!(8, TypeInfo::get_size_from_primitive(PrimitiveKind::Quad));
        assert_eq!(8, TypeInfo::get_size_from_primitive(PrimitiveKind::UQuad));
        assert_eq!(8, TypeInfo::get_size_from_primitive(PrimitiveKind::I64));
        assert_eq!(8, TypeInfo::get_size_from_primitive(PrimitiveKind::U64));
        assert_eq!(16, TypeInfo::get_size_from_primitive(PrimitiveKind::Octa));
        assert_eq!(16, TypeInfo::get_size_from_primitive(PrimitiveKind::UOcta));
        assert_eq!(16, TypeInfo::get_size_from_primitive(PrimitiveKind::I128));
        assert_eq!(16, TypeInfo::get_size_from_primitive(PrimitiveKind::U128));
        assert_eq!(2, TypeInfo::get_size_from_primitive(PrimitiveKind::F16));
        assert_eq!(4, TypeInfo::get_size_from_primitive(PrimitiveKind::F32));
        assert_eq!(4, TypeInfo::get_size_from_primitive(PrimitiveKind::F32PP));
        assert_eq!(6, TypeInfo::get_size_from_primitive(PrimitiveKind::F48));
        assert_eq!(8, TypeInfo::get_size_from_primitive(PrimitiveKind::F64));
        assert_eq!(10, TypeInfo::get_size_from_primitive(PrimitiveKind::F80));
        assert_eq!(16, TypeInfo::get_size_from_primitive(PrimitiveKind::F128));
        assert_eq!(
            8,
            TypeInfo::get_size_from_primitive(PrimitiveKind::Complex32)
        );
        assert_eq!(
            16,
            TypeInfo::get_size_from_primitive(PrimitiveKind::Complex64)
        );
        assert_eq!(
            20,
            TypeInfo::get_size_from_primitive(PrimitiveKind::Complex80)
        );
        assert_eq!(
            32,
            TypeInfo::get_size_from_primitive(PrimitiveKind::Complex128)
        );
        assert_eq!(1, TypeInfo::get_size_from_primitive(PrimitiveKind::Bool8));
        assert_eq!(2, TypeInfo::get_size_from_primitive(PrimitiveKind::Bool16));
        assert_eq!(4, TypeInfo::get_size_from_primitive(PrimitiveKind::Bool32));
        assert_eq!(8, TypeInfo::get_size_from_primitive(PrimitiveKind::Bool64));
        assert_eq!(0, TypeInfo::get_size_from_primitive(PrimitiveKind::HRESULT));
    }

    #[test]
    fn test_type_info_from_type_data_primitives() {
        // Test the TypeInfo::from_type_data method with basic primitive types
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();
        let index = TypeIndex(1);

        // Test with a primitive type (I32)
        let primitive_data = TypeData::Primitive(pdb::PrimitiveType {
            kind: PrimitiveKind::I32,
            indirection: None,
        });
        let result = TypeInfo::from_type_data(type_info, primitive_data, index).unwrap();
        assert_eq!(result.element_size(), 4);
        assert_eq!(result.element_count(), 1);
        assert_eq!(result.total_size(), 4);
        assert_eq!(result.type_id(), Some(index));

        // Test with various primitive types and their expected sizes
        let test_primitives = vec![
            (PrimitiveKind::I8, 1),
            (PrimitiveKind::U8, 1),
            (PrimitiveKind::I16, 2),
            (PrimitiveKind::U16, 2),
            (PrimitiveKind::I32, 4),
            (PrimitiveKind::U32, 4),
            (PrimitiveKind::I64, 8),
            (PrimitiveKind::U64, 8),
            (PrimitiveKind::F32, 4),
            (PrimitiveKind::F64, 8),
            (PrimitiveKind::Bool8, 1),
            (PrimitiveKind::Bool32, 4),
            (PrimitiveKind::Char, 1),
            (PrimitiveKind::UChar, 1),
            (PrimitiveKind::Short, 2),
            (PrimitiveKind::UShort, 2),
            (PrimitiveKind::Long, 4),
            (PrimitiveKind::ULong, 4),
            (PrimitiveKind::Void, POINTER_LENGTH as u32),
        ];

        for (primitive_kind, expected_size) in test_primitives {
            let primitive_data = TypeData::Primitive(pdb::PrimitiveType {
                kind: primitive_kind,
                indirection: None,
            });
            let result = TypeInfo::from_type_data(type_info, primitive_data, index).unwrap();
            assert_eq!(
                result.element_size(),
                expected_size,
                "Failed for primitive kind: {:?}",
                primitive_kind
            );
            assert_eq!(result.element_count(), 1);
            assert_eq!(result.total_size(), expected_size);
            assert_eq!(result.type_id(), Some(index));
        }

        // Test with a pointer type (by using a primitive with indirection)
        let mut primitive_ptr = pdb::PrimitiveType {
            kind: PrimitiveKind::I32,
            indirection: None,
        };
        primitive_ptr.indirection = Some(pdb::Indirection::Near16);
        let pointer_data = TypeData::Primitive(primitive_ptr);
        let result = TypeInfo::from_type_data(type_info, pointer_data, index).unwrap();
        assert_eq!(result.element_size(), POINTER_LENGTH as u32);
        assert_eq!(result.element_count(), 1);
        assert_eq!(result.total_size(), POINTER_LENGTH as u32);
        assert_eq!(result.type_id(), Some(index));
    }

    #[test]
    fn test_type_info_from_type_data_bitfield() {
        // Test the TypeInfo::from_type_data method with a class type
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        // Grab an idx we know exists, that we can use later.
        let idx = type_info.finder().max_index();
        let size = TypeInfo::from_type_index(type_info, idx)
            .unwrap()
            .total_size();

        let bitfield = TypeData::Bitfield(pdb::BitfieldType {
            underlying_type: idx,
            length: 5,
            position: 0,
        });
        let result = TypeInfo::from_type_data(type_info, bitfield, idx).unwrap();
        // Right now, we just return the total size of the struct, not the individual bitfield. This test will fail when
        // we change that.
        assert_eq!(result.total_size(), size);
    }

    #[test]
    fn test_type_info_from_type_data_fieldlist() {
        // Test the TypeInfo::from_type_data method with a field list type
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        // Grab an idx we know exists, that we can use later.
        let idx = type_info.finder().max_index();
        let size = TypeInfo::from_type_index(type_info, idx)
            .unwrap()
            .total_size();

        let field_list = TypeData::FieldList(pdb::FieldList {
            fields: vec![
                TypeData::Primitive(pdb::PrimitiveType {
                    kind: PrimitiveKind::I32,
                    indirection: None,
                }),
                TypeData::Primitive(pdb::PrimitiveType {
                    kind: PrimitiveKind::U32,
                    indirection: None,
                }),
            ],
            continuation: Some(idx),
        });
        let result = TypeInfo::from_type_data(type_info, field_list, idx).unwrap();

        // 4 bytes for I32 and 4 bytes for U32 + the size of the continuation type.
        assert_eq!(result.total_size(), 8 + size);
    }

    #[test]
    fn test_type_info_from_type_data_argument_list() {
        // Test the TypeInfo::from_type_data method with an argument list type
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        // Grab an idx we know exists, that we can use later.
        let idx = type_info.finder().max_index();
        let size = TypeInfo::from_type_index(type_info, idx)
            .unwrap()
            .total_size();

        let argument_list = TypeData::ArgumentList(pdb::ArgumentList {
            arguments: vec![idx; 10],
        });
        let result = TypeInfo::from_type_data(type_info, argument_list, idx).unwrap();

        // 4 bytes for I32 and 4 bytes for U32 + the size of the continuation type.
        assert_eq!(result.total_size(), size * 10);
    }

    #[test]
    fn test_type_info_from_unsupported_type_data() {
        let index = TypeIndex(1);
        let data = TypeData::OverloadedMethod(pdb::OverloadedMethodType {
            count: 0,
            method_list: index,
            name: "".into(),
        });
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        let result = TypeInfo::from_type_data(type_info, data, index);
        assert!(result.is_err_and(|err| err
            .to_string()
            .contains("Unhandled TypeData for C Code: OverloadedMethod")));
    }

    #[test]
    fn test_type_info_formatter() {
        let mut ti = TypeInfo::many(0x1, 4, Some(TypeIndex(0x1)));
        let formatted = format!("{:?}", ti);
        assert_eq!(
            formatted,
            "TypeInfo { element_type: TypeIndex(0x1), element_size: 0x00000001, count: 4 }"
        );

        ti.element_type = None;
        let formatted = format!("{:?}", ti);
        assert_eq!(formatted, "TypeInfo { element_size: 0x00000001, count: 4 }");
    }

    #[test]
    fn test_symbol_find_field_offset_and_size_simple() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        let symbol = "mRootMmiEntry";
        let field = "AllEntries";
        let type_index = metadata
            .find_symbol("mRootMmiEntry")
            .type_info
            .type_id()
            .unwrap();

        let result = Symbol::find_field_offset_and_size(type_info, &type_index, field, symbol);
        let Ok((offset, size)) = result else {
            panic!(
                "Failed to find field offset and size for {}.{}",
                symbol, field
            );
        };

        assert_eq!(offset, 0x8); // AllEntries follows a UINTN, which is 8 bytes in size.
        assert_eq!(size, 0x10); // AllEntries is a LIST_ENTRY, which is a struct with 2 pointers, so 8 bytes each.
    }

    #[test]
    fn test_symbol_find_field_offset_and_size_recurse() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        let symbol = "mRootMmiEntry";
        let field = "AllEntries.BackLink";
        let type_index = metadata
            .find_symbol("mRootMmiEntry")
            .type_info
            .type_id()
            .unwrap();

        let result = Symbol::find_field_offset_and_size(type_info, &type_index, field, symbol);
        let Ok((offset, size)) = result else {
            panic!(
                "Failed to find field offset and size for {}.{}",
                symbol, field
            );
        };

        // ForwardLink follows a UINTN, which is 8 bytes in size. BackLink is the second field in LIST_ENTRY, where the
        // first is ForwardLink, a pointer (8 bytes). Due to this, the offset should be 16 bytes.
        assert_eq!(offset, 0x10);
        assert_eq!(size, 0x8); // BackLink is a pointer, so 8 bytes in size.
    }

    #[test]
    fn test_symbol_find_field_offset_and_size_not_attribute() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        let symbol = "mRootMmiEntry";
        let field = "NonExistentField";
        let type_index = metadata
            .find_symbol("mRootMmiEntry")
            .type_info
            .type_id()
            .unwrap();

        let result = Symbol::find_field_offset_and_size(type_info, &type_index, field, symbol);
        assert!(result.is_err_and(|err| err
            .to_string()
            .contains("Field [NonExistentField] not found in symbol [mRootMmiEntry]")));
    }

    /// `gMmMps.HeapGuardPolicy` is a C union of a raw byte and a bitfield struct, both at offset
    /// 0 within the union, which itself sits at offset 0x2 of the symbol.
    #[test]
    fn test_symbol_find_field_offset_and_size_through_union() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();
        let type_index = metadata.find_symbol("gMmMps").type_info.type_id().unwrap();

        let (offset, size) = Symbol::find_field_offset_and_size(
            type_info,
            &type_index,
            "HeapGuardPolicy.Data",
            "gMmMps",
        )
        .expect("a field behind a union should resolve");

        assert_eq!(offset, 0x2);
        assert_eq!(size, 0x1);
    }

    /// Union members overlap, so two members of the same union report the same offset while
    /// keeping their own sizes.
    #[test]
    fn test_symbol_find_field_offset_and_size_union_members_overlap() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();
        let type_index = metadata.find_symbol("gMmMps").type_info.type_id().unwrap();

        let data = Symbol::find_field_offset_and_size(
            type_info,
            &type_index,
            "HeapGuardPoolType.Data",
            "gMmMps",
        )
        .expect("union member should resolve");
        let fields = Symbol::find_field_offset_and_size(
            type_info,
            &type_index,
            "HeapGuardPoolType.Fields",
            "gMmMps",
        )
        .expect("union member should resolve");

        assert_eq!(data.0, 0x4);
        assert_eq!(fields.0, data.0);
        assert_ne!(fields.1, data.1);
    }

    /// A path may continue into a struct that lives behind a union.
    #[test]
    fn test_symbol_find_field_offset_and_size_through_union_into_struct() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();
        let type_index = metadata.find_symbol("gMmMps").type_info.type_id().unwrap();

        let (offset, _) = Symbol::find_field_offset_and_size(
            type_info,
            &type_index,
            "HeapGuardPolicy.Fields.MmPageGuard",
            "gMmMps",
        )
        .expect("a field of a struct behind a union should resolve");

        // The union sits at 0x2, and both the struct and its first bitfield start at 0.
        assert_eq!(offset, 0x2);
    }

    #[test]
    fn test_symbol_find_field_offset_and_size_not_class() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        let symbol = "mMapDepth";
        let field = "AllEntries";
        let type_index = metadata
            .find_symbol("mMapDepth")
            .type_info
            .type_id()
            .unwrap();

        let result = Symbol::find_field_offset_and_size(type_info, &type_index, field, symbol);
        assert!(result.is_err_and(|err| err
            .to_string()
            .contains("Symbol [mMapDepth] is not a class or union. Cannot get fields.")));
    }

    /// The descent only fires for a record that is unambiguously a pass-through: one payload, at
    /// offset 0, covering the whole parent.
    #[test]
    fn test_transparent_wrapper_member_accepts_a_sole_full_width_payload() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        let payload = metadata
            .find_symbol("mMapDepth")
            .type_info
            .type_id()
            .unwrap();
        let width = TypeInfo::from_type_index(type_info, payload)
            .unwrap()
            .total_size() as u64;

        let members = vec![("value".to_string(), 0u64, payload)];
        assert_eq!(
            Symbol::transparent_wrapper_member(type_info, &members, width),
            Some(payload)
        );
    }

    /// Anything that is not provably a pass-through is refused, so a descent can never move a
    /// path onto storage the author did not name.
    #[test]
    fn test_transparent_wrapper_member_refuses_anything_ambiguous() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        let payload = metadata
            .find_symbol("mMapDepth")
            .type_info
            .type_id()
            .unwrap();
        let width = TypeInfo::from_type_index(type_info, payload)
            .unwrap()
            .total_size() as u64;

        // Two members that both carry data: which one to follow is a guess, so neither is taken.
        let two = vec![
            ("a".to_string(), 0u64, payload),
            ("b".to_string(), 0u64, payload),
        ];
        assert_eq!(
            Symbol::transparent_wrapper_member(type_info, &two, width),
            None
        );

        // Sole member, but it does not start the parent, so bytes precede it.
        let offset = vec![("value".to_string(), 1u64, payload)];
        assert_eq!(
            Symbol::transparent_wrapper_member(type_info, &offset, width),
            None
        );

        // Sole member at offset 0, but it does not span the parent, so bytes follow it.
        let short = vec![("value".to_string(), 0u64, payload)];
        assert_eq!(
            Symbol::transparent_wrapper_member(type_info, &short, width + 1),
            None
        );

        // A parent of unknown size proves nothing about its members.
        assert_eq!(
            Symbol::transparent_wrapper_member(type_info, &short, 0),
            None
        );
    }

    /// A C bitfield union has two full width members, so the descent cannot choose between them.
    /// The failure names what was available rather than silently landing on one of them.
    #[test]
    fn test_symbol_find_field_refuses_to_guess_through_an_ambiguous_union() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();
        let type_index = metadata.find_symbol("gMmMps").type_info.type_id().unwrap();

        // `MmPageGuard` lives under `HeapGuardPolicy.Fields`, and skipping `Fields` is a guess.
        let error = Symbol::find_field_offset_and_size(
            type_info,
            &type_index,
            "HeapGuardPolicy.MmPageGuard",
            "gMmMps",
        )
        .expect_err("an ambiguous union must not be descended through");

        let error = error.to_string();
        assert!(error.contains("Field [MmPageGuard] not found"));
        assert!(error.contains("Data"), "{}", error);
        assert!(error.contains("Fields"), "{}", error);
    }

    #[test]
    fn test_symbol_is_provably_zero_sized_rejects_types_that_occupy_storage() {
        let mut metadata = build_metadata();
        let type_info = &metadata.pdb.type_information().unwrap();

        // An aggregate that holds data is never treated as empty, so the transparent wrapper
        // descent can never step over it.
        let class_index = metadata
            .find_symbol("mRootMmiEntry")
            .type_info
            .type_id()
            .unwrap();
        assert!(!Symbol::is_provably_zero_sized(type_info, class_index));

        // Non-aggregates are rejected as well. Several encodings report a computed size of zero
        // when the size is merely unknown, so only an explicit zero-sized aggregate definition
        // counts as proof.
        let scalar_index = metadata
            .find_symbol("mMapDepth")
            .type_info
            .type_id()
            .unwrap();
        assert!(!Symbol::is_provably_zero_sized(type_info, scalar_index));
    }
}

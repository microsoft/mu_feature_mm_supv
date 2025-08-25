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

        let mut ret = Vec::new();

        let type_information = &mut self.pdb.type_information()?;
        let element_count = symbol.type_info.element_count();

        for i in 0..element_count {
            if !rule
                .array
                .as_ref()
                .and_then(|arr| arr.index.clone())
                .unwrap_or(i..=i)
                .contains(&i)
            {
                continue;
            }

            let mut offset = 0;
            let mut size = symbol.type_info.element_size();

            if let Some(field) = &rule.field {
                let (field_offset, total_size) = Symbol::find_field_offset_and_size(
                    type_information,
                    &symbol.type_info.type_id().unwrap(),
                    field,
                    symbol.name(),
                )?;
                offset += field_offset;
                size = total_size;
            }

            let validation_type = if rule
                .array
                .as_ref()
                .is_some_and(|a| a.sentinel && i == element_count - 1)
            {
                file::ValidationType::Content {
                    content: vec![0; size as usize],
                }
            } else {
                self.build_validation_type(&rule.validation)?
            };

            let entry = file::ImageValidationEntryHeader {
                offset: symbol.address(i) + offset,
                size,
                validation_type,
                ..Default::default()
            };

            let default = self.loaded_image
                [entry.offset as usize..(entry.offset + entry.size) as usize]
                .to_vec();

            let mut name = rule.symbol.clone();
            if element_count > 1 {
                name += format!("[{}]", i).as_str();
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
        Ok(file::KeySymbol::new(key.signature, symbol.address))
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

    fn validate_rule(&mut self, symbol: &Symbol, rule: &crate::config::Rule) -> Result<()> {
        // If the rule is a content rule, make sure that the content size matches the symbol size.
        if let config::Validation::Content { content } = &rule.validation {
            let size = match &rule.field {
                Some(field) => {
                    let (_, size) = Symbol::find_field_offset_and_size(
                        &self.pdb.type_information()?,
                        &symbol.type_info.type_id().unwrap(),
                        field,
                        symbol.name(),
                    )?;
                    size
                }
                None => symbol.type_info.element_size(),
            };

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

        let element_count = symbol.type_info.element_count();

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

    /// Returns the offset and size of a field in a class.
    fn find_field_offset_and_size(
        info: &TypeInformation,
        id: &TypeIndex,
        attribute: &str,
        symbol: &str,
    ) -> Result<(u32, u32)> {
        let mut parts = attribute.splitn(2, '.');
        let attribute = parts.next().unwrap_or("");
        let remaining = parts.next().unwrap_or("");
        match TypeInfo::find_type(info, *id)?.parse()? {
            TypeData::Class(class) => {
                if let Some(fields) = class.fields {
                    if let pdb::TypeData::FieldList(fields) =
                        TypeInfo::find_type(info, fields)?.parse()?
                    {
                        for field in fields.fields {
                            if let TypeData::Member(member) = field {
                                if member.name.to_string() == attribute {
                                    let size = TypeInfo::from_type_index(info, member.field_type)?
                                        .total_size();
                                    if !remaining.is_empty() {
                                        let (offset, size) = Self::find_field_offset_and_size(
                                            info,
                                            &member.field_type,
                                            remaining,
                                            symbol,
                                        )?;
                                        return Ok((member.offset as u32 + offset, size));
                                    }
                                    return Ok((member.offset as u32, size));
                                }
                            }
                        }
                        return Err(anyhow::anyhow!(
                            "Field [{}] not found in symbol [{}]",
                            attribute,
                            symbol
                        ));
                    }
                    // Theoretically unreachable, unless the pdb file is malformed or there is a bug in the pdb crate
                    // code.
                    return Err(anyhow::anyhow!(
                        "UNEXPECTED: Symbol [{}] fields are not a field list.",
                        symbol
                    ));
                }
                // Theoretically unreachable as you cannot have a struct defined without fields in C.
                Err(anyhow::anyhow!(
                    "Symbol [{}] is a class, but has no fields.",
                    symbol
                ))
            }
            _ => Err(anyhow::anyhow!(
                "Symbol [{}] is not a class. Cannot get class fields.",
                symbol
            )),
        }
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
        Ok(match data {
            TypeData::Primitive(prim) => {
                if prim.indirection.is_some() {
                    TypeInfo::one(POINTER_LENGTH as u32, Some(index))
                } else {
                    TypeInfo::one(Self::get_size_from_primitive(prim.kind), Some(index))
                }
            }
            TypeData::Class(class) => TypeInfo::one(class.size as u32, Some(index)),
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
                TypeInfo::many(
                    element.element_size(),
                    total_size / element.element_size() as usize,
                    element.type_id(),
                )
            }
            pdb::TypeData::Union(union) => TypeInfo::one(union.size as u32, Some(index)),
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

    /// Returns a type using the type index. If the type is a class with size 0, it will
    /// check for a shadow class with the real information, returning that instead.
    fn find_type<'a>(info: &'a TypeInformation, index: TypeIndex) -> Result<Item<'a, TypeIndex>> {
        let mut iter = info.iter();
        let mut finder = info.finder();

        while (iter.next()?).is_some() {
            finder.update(&iter)
        }

        let data = finder.find(index)?;
        let item = data.parse()?;

        // Return the item if it is anything other than class, and only
        // if the class size is not zero.
        let class_name;
        if let TypeData::Class(d) = item {
            if d.size != 0 {
                return Ok(data);
            }
            class_name = d.name.to_string().to_string();
        } else {
            return Ok(data);
        }

        // The type was a class and size 0, so it should have a shadow class
        // with the real information.
        let mut iter = info.iter();
        let item = iter.find(|item| {
            let item = item.parse()?;
            if let Some(name) = item.name() {
                if name.to_string() == class_name {
                    if let TypeData::Class(data) = item {
                        if data.size != 0 {
                            return Ok(true);
                        }
                    }
                }
            }
            Ok(false)
        });
        if let Ok(Some(item)) = item {
            return Ok(item);
        }
        Err(anyhow!("Symbol {} was found, but size was 0", class_name))
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
        };

        // This will panic
        let _ = metadata.build_key_symbol(&key);
    }
    #[test]
    fn test_build_key_symbol() {
        let mut metadata = build_metadata();

        let key = Key {
            symbol: "mMmSupvPoolLists".to_string(),
            signature: ['P', 'O', 'O', 'L'],
        };

        let key_symbol = metadata
            .build_key_symbol(&key)
            .unwrap_or_else(|e| panic!("Failed to build key symbol: [{}]", e));
        assert_eq!(key_symbol.signature, 0x4c_4f_4f_50); // 'POOL'
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
    fn test_validate_rule_when_array_field_but_symbol_not_array() {
        let mut metadata = build_metadata();

        let rule = Rule {
            symbol: "mUnblockedMemoryList".to_string(),
            array: Some(Array {
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
            .contains("Symbol [mMapDepth] is not a class. Cannot get class fields.")));
    }
}

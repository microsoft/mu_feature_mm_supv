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
use std::{collections::HashMap, fmt::Formatter, fs::File, ops::Range, path::PathBuf};

use anyhow::{anyhow, Result};
use pdb::{
    AddressMap, DataSymbol, FallibleIterator, Item, PrimitiveKind, TypeData, TypeIndex,
    TypeInformation, PDB,
};

use crate::{config, file, report};

const POINTER_LENGTH: u64 = 8;

/// A struct containing all metadata from the PDB necessary to generate the auxiliary file.
pub struct PdbMetadata<'a> {
    pdb: PDB<'a, File>,
    sections: Vec<Section>,
    addr_to_name: HashMap<u32, String>,
    unloaded_image: Vec<u8>,
    loaded_image: Vec<u8>,
}

impl PdbMetadata<'_> {
    /// Creates a new instance of the PdbMetadata struct by parsing the PDB file and loading the image.
    pub fn new(pdb_path: PathBuf, efi_path: PathBuf) -> Result<Self> {
        let file = File::open(pdb_path)?;
        let mut pdb = PDB::open(file)?;

        let sections = Self::get_sections(&mut pdb)?;
        let unloaded_image = std::fs::read(efi_path)?;
        let loaded_image = Self::load_image(&unloaded_image)?;
        let addr_to_name = HashMap::new();

        let mut metadata = PdbMetadata {
            pdb,
            sections,
            addr_to_name,
            unloaded_image,
            loaded_image,
        };

        metadata.fill_sections()?;

        Ok(metadata)
    }

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
                .map_or(false, |a| a.sentinel && i == element_count - 1)
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
            self.addr_to_name.insert(entry.offset, name);

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

    /// Gives the specific symbol instance for the given address including it's index and field.
    pub fn name_from_address(&self, address: &u32) -> Option<String> {
        self.addr_to_name.get(address).cloned()
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
                    println!("{}", element_count);
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
    fn get_sections(pdb: &mut PDB<'_, File>) -> Result<Vec<Section>> {
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
                            "Attribute [{}] not found for symbol [{}]",
                            attribute,
                            symbol
                        ));
                    }
                    return Err(anyhow::anyhow!(
                        "UNEXPECTED: Symbol [{}] fields are not a field list.",
                        symbol
                    ));
                }

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
                "{{ element_type: {:?}, element_size: {:08X}, count: {} }}",
                r#type, self.element_size, self.count
            )
        } else {
            write!(
                f,
                "{{ element_size: {:08X}, count: {} }}",
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
            TypeData::Member(_) => {
                log::error!("Member type unexpected in global data.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::MemberFunction(_) => {
                log::error!("Member function unexpected in global data.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::OverloadedMethod(_) => {
                log::error!("Overloaded method unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::Method(_) => {
                log::error!("Method unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::StaticMember(_) => {
                log::error!("Static method unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::Nested(_) => {
                log::error!("Nested unexpected in global data.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::BaseClass(_) => {
                log::error!("BaseClass unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::VirtualBaseClass(_) => {
                log::error!("VirtualBaseClass unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::VirtualFunctionTablePointer(_) => {
                TypeInfo::one(POINTER_LENGTH as u32, Some(index))
            }
            TypeData::Procedure(_) => {
                log::error!("Procedure unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::Pointer(_) => TypeInfo::one(POINTER_LENGTH as u32, Some(index)),
            TypeData::Modifier(modifier) => {
                TypeInfo::from_type_index(info, modifier.underlying_type)?
            }
            pdb::TypeData::Enumeration(enm) => {
                TypeInfo::from_type_index(info, enm.underlying_type)?
            }
            TypeData::Enumerate(_) => {
                log::error!("Unknown Type Enumerate");
                TypeInfo::one(0, Some(index))
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
            pdb::TypeData::Bitfield(bf) => {
                let type_info = TypeInfo::from_type_index(info, bf.underlying_type)?;
                let size = type_info.total_size() * bf.length as u32;
                TypeInfo::one(size, Some(index))
            }
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
            TypeData::MethodList(_) => {
                log::error!("MethodList unexpected in C.");
                TypeInfo::one(0, None)
            }
            _ => {
                log::error!("Unknown Type");
                TypeInfo::one(0, None)
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

//! A module that contains the C-equivalent structs and final functions to
//! generate the aux file.
//! 
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//! 
use std::{fmt, io::Write, mem::size_of};
use pdb::{SectionCharacteristics, TypeInformation};
use scroll::{self, ctx, Endian, Pread, Pwrite, LE};
use crate::{report::CoverageReport, type_info::TypeInfo, ConfigFile, KeySymbol, ValidationRule, ValidationType};

/// The type of symbol in the PDB file.
#[derive(Default, Clone, PartialEq, Debug)]
pub enum SymbolType {
    #[default]
    None,
    Public,
    Data,
    Procedure,
    Label,
}

/// A struct representing a symbol in the PDB file.
#[derive(Default, Clone)]
pub struct Symbol {
    /// The human readable name of the symbol
    pub name: String,
    /// The address of the symbol in the loaded image.
    pub address: u32,
    /// Information about this symbol's type
    pub type_info: TypeInfo,
    // The type of the symbol
    pub symbol_type: SymbolType,
    // The characteristics of the section that the symbol is in.
    pub section_characteristics: SectionCharacteristics,
}

impl std::fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Symbol {{ address: 0x{:08X}, name: {}, type_info: {:?} }}", self.address, self.name, self.type_info)
    }
}

impl Symbol {
    /// Returns true if the symbol is in a section that is read-only (READ, !WRITE, !EXECUTE)
    pub fn in_read_write_section(&self) -> bool {
        let characteristics = self.section_characteristics;
        characteristics.read() && characteristics.write()
    }

    /// Returns the address of the symbol at the given index.
    pub fn address(&self, index: u64) -> i64 {
        self.address as i64 + (self.type_info.element_size() * index) as i64
    }
}

/// A struct representing the header of the aux file.
#[derive(Debug, Pwrite)]
pub struct ImageValidationDataHeader {
    /// The signature of the header. Must be 0x444C4156
    signature: u32,
    /// The size of the entire aux file in bytes.
    size: u32,
    /// The number of entries in the aux file.
    entry_count: u32,
    /// The offset to the first entry in the aux file.
    /// This is the size of the IMAGE_VALIDATION_DATA_HEADER.
    offset_to_first_entry: u32,
    /// The offset to the first default value in the aux file.
    offset_to_first_default: u32,
    /// The number of key symbols in the aux file.
    key_symbol_count: u32,
    /// The offset to the first key_sybol in the aux file.
    offset_to_first_key_symbol: u32,
}

impl Default for ImageValidationDataHeader {
    fn default() -> Self {
        ImageValidationDataHeader {
            signature: 0x444C4156,
            size: 28,
            entry_count: 0,
            offset_to_first_entry: 0,
            offset_to_first_default: 0,
            key_symbol_count: 0,
            offset_to_first_key_symbol: 0,
        }
    }
}

/// A struct representing the header of an entry in the aux file.
/// Typically a IMAGE_VALIDATION_ENTRY_HEADER, but may be casted to a different
/// type depending on the validation_type field. The other possible header
/// types are:
/// 
/// - validation_type = 0x2: IMAGE_VALIDATION_CONTENT
/// - validation_type = 0x3: IMAGE_VALIDATION_MEM_ATTR
/// - validation_type = 0x4: IMAGE_VALIDATION_SELF_REF
/// 
#[derive(Clone)]
pub struct ImageValidationEntryHeader {
    pub signature: u32,
    /// Offset of the value in the original image.
    pub offset: u32,
    /// Size of the value in bytes.
    pub size: u32,
    /// The type of validation to perform on the symbol. Contains the data
    /// necessary to perform the validation.
    pub validation_type: ValidationType,
    /// Offset of the default value in the aux file.
    pub offset_to_default: u32,
    /// The symbol name that this entry is for. This is not written to the aux
    /// file, but exists for debugging purposes.
    pub symbol: String,
}

impl Default for ImageValidationEntryHeader {
    fn default() -> Self {
        ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0,
            size: 0,
            validation_type: ValidationType::default(),
            offset_to_default: 0,
            symbol: String::new(),
        }
    }
}

impl std::fmt::Debug for ImageValidationEntryHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImageValidationEntryHeader {{ signature: 0x{:08X}, offset: 0x{:08X}, size: 0x{:08X}, validation_type: {:?}, offset_to_default: 0x{:08X} }}", self.signature, self.offset, self.size, self.validation_type, self.offset_to_default)
    }
}

impl <'a> ctx::TryIntoCtx<Endian> for &ImageValidationEntryHeader {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], le: Endian) -> Result<usize, Self::Error> {
        let mut offset = 0;
        this.gwrite_with(self.signature, &mut offset, le)?;
        this.gwrite_with(self.offset, &mut offset, le)?;
        this.gwrite_with(self.size, &mut offset, le)?;
        this.gwrite_with(&self.validation_type, &mut offset, le)?;
        this.gwrite_with(self.offset_to_default, &mut offset, le)?;
        
        match &self.validation_type {
            ValidationType::None => {},
            ValidationType::NonZero => {},
            ValidationType::Content{content} => {
                this.gwrite_with(&content[..], &mut offset, ())?;
            },
            ValidationType::MemAttr {memory_size, must_have, must_not_have} => {
                this.gwrite_with(memory_size, &mut offset, le)?;
                this.gwrite_with(must_have, &mut offset, le)?;
                this.gwrite_with(must_not_have, &mut offset, le)?;
            },
            ValidationType::Ref{address, ..} => {
                if let Some(address) = address {
                    this.gwrite_with(address, &mut offset, le)?;
                } else {
                    return Err(scroll::Error::Custom("SELF validation type must have an address".to_string()))
                }
            },
            ValidationType::Pointer{in_mseg} => {
                this.gwrite(*in_mseg as u32, &mut offset)?;
            },
        }
        Ok(offset)
    }
}

impl ImageValidationEntryHeader {
    /// Generates one or more ImageValidationEntryHeaders from a ValidationRule and a Symbol.
    ///
    /// Multiple headers are generated if the top level symbol is an array of an underlying type.
    /// In this scenario, the same rule is applied to each element in the array rather than the
    /// array as a whole.
    fn from_rule(rule: &ValidationRule) -> anyhow::Result<Vec<Self>> {
        let mut ret = Vec::new();
        let Some(symbol) = rule.symbol_info.as_ref() else {
            return Err(anyhow::anyhow!("Invalid Rule: [{:?}] symbol_info is None", rule));
        };
        let element_count = symbol.type_info.element_count();
        let symbol_is_arr = element_count > 1;

        if !symbol_is_arr && (rule.array.sentinel || rule.array.index.is_some()) {
            return Err(anyhow::anyhow!("Invalid Rule Configuration: Symbol {} is not an array, but the rule specifies configuration for an array.", symbol.name));
        }

        if rule.array.sentinel && rule.array.index.is_some() {
            return Err(anyhow::anyhow!("Invalid Rule Configuration: Symbol {}: Array configuration `sentinel` and `index` cannot be combined.", symbol.name));
        }

        if let Some(index) = rule.array.index {
            if index >= element_count {
                return Err(
                    anyhow::anyhow!("Invalid Rule Configuration: [{:?}] index[{}] is larger than array size[{}]", rule, index, element_count
                ));
            }
        }

        for i in 0..element_count {
            // Skip the entry if the config specifies a specific index to apply the rule to
            if rule.array.index.unwrap_or(i) != i {
                continue;
            }

            let mut entry = ImageValidationEntryHeader::default();
            entry.offset = (symbol.address(i) + rule.offset.unwrap_or_default()) as u32;
            entry.size = rule.size.unwrap_or(symbol.type_info.element_size() as u32);
            
            // If the last value in the array is a sentinel, then the data should be all zeros to signify
            // the end of the array.
            if rule.array.sentinel && i == element_count - 1 {
                entry.validation_type = ValidationType::Content { content: vec![0; entry.size as usize] };
            } else {
                entry.validation_type = rule.validation.clone();
            }

            // Set the symbol name for debugging purposes and the final json report.
            entry.symbol = symbol.name.clone();
            if symbol_is_arr {
                entry.symbol += &format!("[{}]", i);
            }
            if let Some(ref field) = rule.field {
                entry.symbol += &format!(".{}", field);
            }
            ret.push(entry);
        }
        Ok(ret)
    }

    /// Returns the size of ImageValidationEntryHeader in bytes. While the C
    /// struct IMAGE_VALIDATION_ENTRY_HEADER is 20 bytes, The actual header in
    /// the aux file can be larger as may be casted to a different type
    /// depending on the validation_type field. That is to say, if the
    /// validation_type is ValidationType::Content, the header header written
    /// to the aux file will  actually be IMAGE_VALIDATION_CONTENT.
    fn header_size(&self) -> u32 {
        20 + match &self.validation_type {
            ValidationType::None => 0,
            ValidationType::NonZero => 0,
            ValidationType::Content{content} => content.len() as u32,
            ValidationType::MemAttr {..} => 24,
            ValidationType::Ref{..} => 4,
            ValidationType::Pointer{..} => 4,
        }
    }
}

/// A builder pattern struct for generating the aux file. 
#[derive(Default, Debug)]
pub struct AuxBuilder {
    /// The loaded image to generate the aux file for
    loaded_image: Vec<u8>,
    /// A list of symbols to generate rules for
    symbols: Vec<Symbol>,
    /// A list of key symbols to be added to the auxiliary file header.
    key_symbols: Vec<KeySymbol>,
    // A list of rules that apply to a certain symbol
    rules: Vec<ValidationRule>,
    // Auto Generate rules for symbols that don't have any
    auto_generate: bool,
    // Exit if a symbol is missing a rule in the config file
    exit_on_missing_rules: bool,
    // Symbols filtered out of the aux file
    excluded_symbols: Vec<String>,
}

impl AuxBuilder {
    /// Registers the loaded image that is used to generate the aux file.
    /// Mocks a UEFI load_image call to ensure data is in the correct format
    /// for copying symbol values into the aux file.
    pub fn with_image(mut self, image: &[u8]) -> anyhow::Result<Self> {
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
                .get_mut((section.virtual_address as usize)..(section.virtual_address.wrapping_add(size) as usize))
                .ok_or(anyhow::anyhow!("Failed to get section"))?;
            let src = image
                .get((section.pointer_to_raw_data as usize)..(section.pointer_to_raw_data.wrapping_add(size) as usize))
                .ok_or(anyhow::anyhow!("Failed to get section"))?;
            dst.copy_from_slice(src);
        }

        self.loaded_image = loaded_image;

        Ok(self)
    }
    
    /// Registers the config file used to generate the entries in the aux file.
    pub fn with_config(mut self, path: Option<std::path::PathBuf>) -> anyhow::Result<Self> {
        if let Some(path) = path {
            let data = std::fs::read_to_string(path)?;
            let file = toml::from_str::<ConfigFile>(&data)?;
            
            if file.config.auto_gen && file.config.no_missing_rules {
                return Err(anyhow::anyhow!("auto_gen and no_missing_symbols cannot be true at the same time."));
            }
            
            self.exit_on_missing_rules = file.config.no_missing_rules;
            self.auto_generate = file.config.auto_gen;
            self.excluded_symbols = file.config.excluded_symbols;
            self.rules = file.rules;
            self.key_symbols = file.key_symbols;
        }
        Ok(self)
    }

    /// Registers the symbols parsed from the PDB files. These symbols are used
    /// to generate the rules for the aux file.
    pub fn with_symbols(mut self, symbols: Vec<Symbol>) -> Self {
        self.symbols = symbols;
        self
    }

    /// Generates rules for any symbols that do not have a rule in the config file. Ignores any symbols in the
    /// `excluded_symbols` list in the configuration file (that filter is done before calling this function).
    pub fn add_missing_rules(symbols: &Vec<Symbol>, rules: &mut Vec<ValidationRule>) {
        for symbol in symbols {
            if !rules.iter().any(|rule| rule.symbol == symbol.name) {
                rules.push(ValidationRule::new(symbol.name.clone()));
            }
        }
    }

    /// Finds symbols that do not have a rule in the configuration file. Ignores symbols of type `Procedure` or `Label` and
    /// any symbols in the `excluded_symbols` list in the configuration file (that filter is done before calling this function).
    pub fn find_symbols_with_no_rule(symbols: &Vec::<Symbol>, rules: &Vec<ValidationRule>) -> Vec<Symbol> {
        const IGNORE_SYMBOL_TYPES: [SymbolType;2] = [SymbolType::Procedure, SymbolType::Label];

        let mut missing = Vec::new();
        for symbol in symbols {
            
            if !rules.iter().any(|rule| {
                rule.symbol == symbol.name
                    || IGNORE_SYMBOL_TYPES.contains(&symbol.symbol_type)
                    || !symbol.in_read_write_section()
                }) {
                missing.push(symbol.clone());
            }
        }

        // Apply extra static filters for junk symbols
        missing
            .into_iter()
            .filter(|symbol| symbol.name != "")
            .filter(|symbol| symbol.address != 0)
            .collect()
    }

    /// Returns the validation entry headers for the given configuration.
    pub fn get_validation_entry_headers(&self, scopes: Vec<String>, type_info: &TypeInformation) -> anyhow::Result<Vec<ImageValidationEntryHeader>> {
        let mut headers = Vec::new();

        for rule in &self.get_rules(scopes, type_info)? {
            let entry_headers = ImageValidationEntryHeader::from_rule(rule)?;
            headers.extend(entry_headers);
        }

        Ok(headers)
    }

    /// Returns the rules that apply to the given configuration.
    /// 
    /// ## Errors
    /// 
    /// Returns an error if `exit_on_missing_rules` is enabled and there are symbols that do not have rules.
    fn get_rules(&self, scopes: Vec<String>, type_info: &TypeInformation) -> anyhow::Result<Vec<ValidationRule>> {
        let symbols = self.get_symbols()?;

        let (mut rules, filtered): (Vec<_>, Vec<_>) = self
            .rules
            .iter()
            .cloned()
            .partition(|rule| rule.is_in_scope(&scopes));
        
        for rule in filtered {
            println!("Rule: {:?} Skipped... Does not apply to scopes: {:?}", rule, scopes);
        }

        if self.auto_generate {
            Self::add_missing_rules(&symbols, &mut rules);
        }

        if self.exit_on_missing_rules {
            let symbols_with_no_rule = Self::find_symbols_with_no_rule(&self.get_symbols()?, &rules);
            if !symbols_with_no_rule.is_empty() {
                println!("ERROR: Rules missing for the following symbols in the configuration file.");
                for symbol in symbols_with_no_rule {
                    println!(" 0x{:08X} - {:?}", symbol.address, symbol.name);
                }
                let e = "`exit_on_missing_rule` is enabled in the configuration file and the symbols above do not have rules.";
                return Err(anyhow::anyhow!(e))
            }
        }

        for rule in &mut rules {
            rule.resolve(&symbols, type_info)?;
        }
        Ok(rules)
    }

    /// Returns the symbols that are not excluded by the given configuration.
    fn get_symbols(&self) -> anyhow::Result<Vec<Symbol>> {
        let (symbols, filtered): (Vec<_>, Vec<_>) = self
            .symbols
            .iter()
            .cloned()
            .partition(|symbol| !self.excluded_symbols.contains(&symbol.name));

        for symbol in filtered {
            println!("Symbol: {:?} Skipped... Excluded via `excluded_symbols` in config file", symbol);
        }

        Ok(symbols)
    }

    /// Resolves and returns the key symbols that are not excluded by the given configuration.
    fn get_key_symbols(&self) -> anyhow::Result<Vec<KeySymbol>> {
        let symbols = self.get_symbols()?;
        let mut key_symbols = self.key_symbols.clone();

        for symbol in &mut key_symbols {
            symbol.resolve(&symbols)?;
        }
        Ok(key_symbols)
    }

    /// Auto generates additional Content rules for padding that is present in the image.
    fn auto_generate_rules(&self, report: CoverageReport) -> anyhow::Result<Vec<ImageValidationEntryHeader>> {
        let mut entry_headers = Vec::new();

        let rules: Vec<ValidationRule> = report.segments()
            .iter()
            .filter(|segment| !segment.covered() && segment.symbol().is_empty())
            .map(|segment| {
                let mut rule = ValidationRule::new(String::from(""));
                let size = segment.end() - segment.start();
                rule.validation = ValidationType::Content { content: vec![0; size as usize] };

                let name = if segment.reason() == "Padding" {
                    String::from("Section Padding")
                } else {
                    String::from("Symbol Padding")
                };

                rule.symbol_info = Some(Symbol {
                    name,
                    address: segment.start() as u32,
                    type_info: TypeInfo::one(size as u64, None),
                    symbol_type: SymbolType::None,
                });
                rule
            })
            .collect();

        for rule in rules {
            entry_headers.extend(
                ImageValidationEntryHeader::from_rule(&rule)?
            );
        }

        Ok(entry_headers)
    }

    // Generates the aux file from the given entry headers and key symbols.
    fn _generate(&self, entry_headers: Vec<ImageValidationEntryHeader>, key_symbols: Vec<KeySymbol>) -> anyhow::Result<AuxFile> {
        let mut aux = AuxFile::default();
        aux.header.offset_to_first_entry = size_of::<ImageValidationDataHeader>() as u32;
        
        for key_symbol in key_symbols {
            aux.key_symbols.push(key_symbol);
            aux.header.key_symbol_count += 1;
            aux.header.size += 8;
            aux.header.offset_to_first_entry += 8;
        }

        if aux.key_symbols.len() > 0 {
            aux.header.offset_to_first_key_symbol = size_of::<ImageValidationDataHeader>() as u32;
        }

        let mut offset_in_default = 0;

        for mut entry in entry_headers {
            entry.offset_to_default = offset_in_default;
            
            offset_in_default += entry.size;
            
            aux.header.size += entry.size + entry.header_size();
            aux.raw_data.extend_from_slice(
                &self.loaded_image[(entry.offset as usize)..(entry.offset + entry.size) as usize]
            );
            aux.entries.push(entry);
            aux.header.entry_count += 1;
        }

        // Now that all entries have been added, we can calculate the offset to
        // the raw data, and update the offset_to_default field in each entry.
        let offset_to_default_start = size_of::<ImageValidationDataHeader>() as u32
            + aux.entries.iter().fold(0, |acc, entry| { acc + entry.header_size()})
            + aux.key_symbols.len() as u32 * 8;

        aux.header.offset_to_first_default = offset_to_default_start;
        for entry_header in &mut aux.entries {
            entry_header.offset_to_default += offset_to_default_start;
        }

        Ok(aux)
    }

    /// Generates the aux final file.
    /// 
    /// By default, only rules specified in the config file have entries in the aux file. If `autogen=true` is
    /// specified in the configuration file, a rule (with no validation) will be generated, so that all symbols are
    /// reverted to their original value.
    /// 
    /// This command ultimately builds the aux file twice. The first time is is used to see if there are any additional
    /// rules that need to be automatically generated. This is typically to auto generate rules for padding that is
    /// present in the image.
    pub fn generate(self, type_info: &TypeInformation, scopes: Vec<String>) -> anyhow::Result<AuxFile> {
        let mut entry_headers = self.get_validation_entry_headers(scopes, type_info)?;
        let key_symbols = self.get_key_symbols()?;

        let aux = self._generate(entry_headers.clone(), key_symbols.clone())?;

        let report = CoverageReport::build(
            &self.loaded_image,
            &aux,
            &self.get_symbols()?
        )?;

        entry_headers.extend(self.auto_generate_rules(report)?);

        let aux = self._generate(entry_headers, key_symbols)?;
        
        aux.verify(self.loaded_image)?;
        Ok(aux)
    }
}

/// A struct representing the auxiliary file that is generated from the PDB
#[derive(Debug, Default)]
pub struct AuxFile {
    /// The IMAGE_VALIDATION_DATA_HEADER that is written to the aux file.
    pub header: ImageValidationDataHeader,
    /// a list of KEY_SYMBOL C structs to be written to the aux file.
    pub key_symbols: Vec<KeySymbol>,
    /// A list of IMAGE_VALIDATION_ENTRY_HEADER's or derivations of it based on
    /// the validation_type field.
    pub entries: Vec<ImageValidationEntryHeader>,
    /// The raw data containing the default values of symbols that have rules.
    pub raw_data: Vec<u8>,
}

impl <'a> ctx::TryIntoCtx<Endian> for &AuxFile {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], le: Endian) -> Result<usize, Self::Error> {
        let mut offset = 0;
        this.gwrite_with(&self.header, &mut offset, le)?;
        for symbol in &self.key_symbols {
            this.gwrite_with(symbol.signature(), &mut offset, le)?;
            this.gwrite_with(symbol.offset.expect("Symbol offset should be resolved"), &mut offset, le)?;
        }
        for entry in &self.entries {
            this.gwrite_with(entry, &mut offset, le)?;
        }
        this.gwrite_with(&self.raw_data[..], &mut offset, ())?;
        Ok(offset)
    }
}

impl AuxFile {
    /// Verify that values and offsets in the aux file match what is expected.
    /// Checks that the size of the aux file matches the size in the header, and
    /// that all values are equal, by using the offsets to compare values in the
    /// original image and the raw data in the aux file.
    fn verify(&self, image_buffer: Vec<u8>) -> anyhow::Result<()> {
        let aux_buffer =  self.to_vec()?;

        if aux_buffer.len() != self.header.size as usize {
            return Err(anyhow::anyhow!("Aux buffer size mismatch."))
        }

        for (i, symbol) in self.key_symbols.iter().enumerate() {
            let start = self.header.offset_to_first_key_symbol as usize + (i * 8);
            let aux_value = aux_buffer.get(
                start .. start + 8
            ).ok_or(anyhow::anyhow!("Failed to get Aux Value"))?;
            
            let sig: u32 = aux_value.gread(&mut 0)?;
            let offset: u32 = aux_value.gread(&mut 4)?;

            if sig != symbol.signature() || offset != symbol.offset.unwrap_or_default() {
                return Err(anyhow::anyhow!("Aux / Image mismatch."))
            }
        }

        for entry in &self.entries {
            let aux_value = aux_buffer.get(
                entry.offset_to_default as usize..(entry.offset_to_default + entry.size) as usize
            ).ok_or(anyhow::anyhow!("Failed to get Aux Value"))?;
            let image_value = image_buffer.get(
                entry.offset as usize..(entry.offset + entry.size) as usize
            ).ok_or(anyhow::anyhow!("Failed to get image Value"))?;
            if aux_value != image_value {
                return Err(anyhow::anyhow!("Aux / Image mismatch."))
            }
        }
        Ok(())
    }

    /// Converts the AuxFile to a `Vec<u8>` buffer.
    pub fn to_vec(&self) -> anyhow::Result<Vec<u8>> {
        let mut buffer = vec![0; self.header.size as usize];
        buffer.gwrite_with(self, &mut 0, LE)?;
        Ok(buffer)
    }

    /// Writes the AuxFile to a file at the specified path.
    pub fn to_file(&self, path: std::path::PathBuf) -> anyhow::Result<()> {
        let mut file = std::fs::File::create(path)?;
        let buffer = self.to_vec()?;
        file.write_all(&buffer)?;
        Ok(())
    }
}

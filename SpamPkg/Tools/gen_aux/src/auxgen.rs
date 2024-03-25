//! A module that contains the C-equivalent structs and final functions to
//! generate the aux file.
use std::{fmt, io::Write, mem::size_of};
use pdb::{TypeIndex, TypeInformation};
use scroll::{self, ctx, Endian, Pread, Pwrite, LE};
use crate::{Config, ValidationRule, ValidationType, KeySymbol};

/// A struct representing a symbol in the PDB file.
#[derive(Default, Clone)]
pub struct Symbol {
    /// The human readable name of the symbol
    pub name: String,
    /// The address of the symbol in the loaded image.
    pub address: u32,
    /// The size of the symbol
    pub size: u32,
    // The type index of the symbol
    pub type_index: Option<TypeIndex>,
}

impl std::fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Symbol {{ address: 0x{:08X}, size: 0x{:08X}, name: {}, type_index: {:?} }}", self.address, self.size, self.name, self.type_index)
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
/// - IMAGE_VALIDATION_CONTENT
/// - IMAGE_VALIDATION_MEM_ATTR
/// - IMAGE_VALIDATION_SELF_REF
/// 
#[derive(Clone)]
pub struct ImageValidationEntryHeader {
    signature: u32,
    /// Offset of the value in the original image.
    offset: u32,
    /// Size of the value in bytes.
    size: u32,
    /// The type of validation to perform on the symbol. Contains the data
    /// necessary to perform the validation.
    validation_type: ValidationType,
    /// Offset of the default value in the raw data
    offset_to_default: u32
}

impl Default for ImageValidationEntryHeader {
    fn default() -> Self {
        ImageValidationEntryHeader {
            signature: 0x52544E45,
            offset: 0,
            size: 0,
            validation_type: ValidationType::default(),
            offset_to_default: 0
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
            }
        }
        Ok(offset)
    }
}

impl ImageValidationEntryHeader {
    /// Generates an ImageValidationEntryHeader from a ValidationRule and a Symbol.
    fn from_rule(rule: &ValidationRule, symbol: &Symbol) -> Self {
        let mut entry = ImageValidationEntryHeader::default();
        entry.offset = ((symbol.address as i64) + rule.offset.unwrap_or_default()) as u32;
        entry.size = rule.size.unwrap_or(symbol.size);
        entry.validation_type = rule.validation.clone();
        entry
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
            ValidationType::Ref{..} => 4
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
    /// A list of key symbols to be added to the auxillary file header.
    key_symbols: Vec<KeySymbol>,
    // A list of rules that apply to a certain symbol
    rules: Vec<ValidationRule>,
    // Auto Generate rules for symbols that don't have any
    auto_generate: bool,
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
            let config = toml::from_str::<Config>(&data)?;
            self.auto_generate = config.auto_gen;
            self.rules = config.rules;
            self.key_symbols = config.key_symbols;
        }
        Ok(self)
    }

    /// Registers the symbols parsed from the PDB files. These symbols are used
    /// to generate the rules for the aux file.
    pub fn with_symbols(mut self, symbols: Vec<Symbol>) -> Self {
        self.symbols = symbols;
        self
    }

    /// Generates the aux file. By default, only rules specified in the
    /// config file have entries in the aux file. If `autogen=true` is
    /// specified in the configuration file, a rule (with no validation) will
    /// be generated, so that all symbols are reverted to their original value.
    pub fn generate(mut self, info: &TypeInformation) -> anyhow::Result<AuxFile> {
        let mut aux = AuxFile::default();
        aux.header.offset_to_first_entry = size_of::<ImageValidationDataHeader>() as u32;
        
        for mut symbol in self.key_symbols {
            symbol.resolve(&self.symbols)?;
            aux.key_symbols.push(symbol);
            aux.header.key_symbol_count += 1;
            aux.header.size += 8;
            aux.header.offset_to_first_entry += 8;
        }

        if aux.key_symbols.len() > 0 {
            aux.header.offset_to_first_key_symbol = size_of::<ImageValidationDataHeader>() as u32;
        }

        let mut offset_in_default = 0;

        if self.auto_generate{
            for symbol in &self.symbols {
                let rule = self.rules.iter().find(|&entry| &entry.symbol == &symbol.name);
                if rule.is_none() {
                    self.rules.push(ValidationRule {
                        symbol: symbol.name.clone(),
                        field: None,
                        validation: ValidationType::None,
                        offset: None,
                        size: None,
                    })
                }
            }
        }

        for rule in self.rules.iter_mut() {
            let symbol = self.symbols
                .iter()
                .find(|&entry| &entry.name == &rule.symbol)
                .ok_or(
                    anyhow::anyhow!(
                        "The symbol [{}] does not exist in the PDB, but a rule is present in the configuration file.",
                        rule.symbol
                ))?;
            rule.resolve(symbol, &self.symbols, info)?;
            
            let mut entry = ImageValidationEntryHeader::from_rule(rule, &symbol);
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
            this.gwrite_with(symbol.signature, &mut offset, le)?;
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

            if sig != symbol.signature || offset != symbol.offset.unwrap_or_default() {
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

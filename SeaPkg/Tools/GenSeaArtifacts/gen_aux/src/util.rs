//! A module containing utility functions for extracting information from the PDB file.
//! 
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//! 
use std::collections::HashMap;

use pdb::{FallibleIterator, Item, PrimitiveKind, TypeData, TypeIndex, TypeInformation};
use anyhow::{anyhow, Result};

use crate::{type_info::TypeInfo, POINTER_LENGTH};

/// Returns a type using the type index. If the type is a class with size 0, it will
/// check for a shadow class with the real information, returning that instead.
pub fn find_type<'a>(info: &'a TypeInformation, index: TypeIndex)->Result<Item<'a, TypeIndex>> {
    let mut iter = info.iter();
    let mut finder = info.finder();

    while let Some(_) = iter.next()? {
        finder.update(&iter)
    }

    let data = finder.find(index)?;
    let item = data.parse()?;

    // Return the item if it is anything other than class, and only
    // if the class size is not zero.
    let class_name;
    if let TypeData::Class(d) = item {
        if d.size != 0 { return Ok(data) }
        class_name = d.name.to_string().to_string();
    } else { return Ok(data)}

    // The type was a class and size 0, so it should have a shadow class
    // with the real information.
    let mut iter = info.iter();
    let item = iter.find(|item| {
        let item = item.parse()?;
        if let Some(name) = item.name() {
            if name.to_string() == class_name {
                if let TypeData::Class(data) = item {
                    if data.size != 0 {
                        return Ok(true)
                    }
                }
            }
        }
        Ok(false)
    });
    if let Ok(Some(item)) = item {
        return Ok(item)
    }
    Err(anyhow!("Symbol {} was found, but size was 0", class_name))
}

/// Parses and adds the symbol to `map` if it is a symbol we care about.
pub fn add_symbol(map: &mut HashMap<String, crate::Symbol>, symbol: pdb::Symbol<'_>, address_map: &pdb::AddressMap, info: &TypeInformation) -> Result<()> {
    match symbol.parse() {
        Ok(pdb::SymbolData::Public(data)) if data.function => {
            let address = data.offset.to_rva(&address_map).unwrap_or_default().0;
            let type_info = TypeInfo::one(POINTER_LENGTH, None);
            let name = data.name.to_string().to_string();
            let symbol_type = crate::SymbolType::Public;
            map.entry(name.clone()).or_insert(crate::Symbol {
                address,
                name,
                type_info,
                symbol_type,
            });
        }
        Ok(pdb::SymbolData::Data(data)) => {
            let address = data.offset.to_rva(&address_map).unwrap_or_default().0;
            let type_info = TypeInfo::from_type_index(&info, data.type_index)?;
            let name = data.name.to_string().to_string();
            let symbol_type = crate::SymbolType::Data;
            
            // A data symbol should always take precedence over an existing
            // symbol on a collision (typically label). If there is a collision
            // and both are data symbols, take the custom type (one whose type
            // index is greater than 0x1000).
            if map.contains_key(&name) && data.type_index.0 < 0x1000 {
                return Ok(())
            }

            map.insert(name.clone(), crate::Symbol {
                address,
                name,
                type_info,
                symbol_type,
            });
        }
        Ok(pdb::SymbolData::Procedure(data)) => {
            let address = data.offset.to_rva(&address_map).unwrap_or_default().0;
            let type_info = TypeInfo::one(POINTER_LENGTH, Some(data.type_index));
            let name = data.name.to_string().to_string();
            let symbol_type = crate::SymbolType::Procedure;
            map.entry(name.clone()).or_insert(crate::Symbol {
                address,
                name,
                type_info,
                symbol_type,
            });
        }
        Ok(pdb::SymbolData::Label(data)) => {
            let address = data.offset.to_rva(&address_map).unwrap_or_default().0;
            let type_info = TypeInfo::one(POINTER_LENGTH, None);
            let name = data.name.to_string().to_string();
            let symbol_type = crate::SymbolType::Label;
            map.entry(name.clone()).or_insert(crate::Symbol {
                address,
                name,
                type_info,
                symbol_type,
            });
        }
        _ => {}
    }

    Ok(())
}

/// Returns the size of a primitive type in bytes.
pub fn get_size_from_primitive(primitive: pdb::PrimitiveKind) -> u64 {
    match primitive {
        PrimitiveKind::NoType => 0,
        PrimitiveKind::Void => POINTER_LENGTH,
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
        },
    }
}

/// Returns the offset and size of a field in a class.
pub fn find_field_offset_and_size(info: &TypeInformation, id: &TypeIndex, attribute: &str, symbol: &str) -> Result<(u64, u64)> {
    let mut parts = attribute.splitn(2, '.');
    let attribute = parts.next().unwrap_or("");
    let remaining = parts.next().unwrap_or("");
    match find_type(info, *id)?.parse()? {
        TypeData::Class(class) => {
            if let Some(fields) = class.fields {
                if let pdb::TypeData::FieldList(fields) = find_type(info, fields)?.parse()? {
                    for field in fields.fields {
                        match field {
                            TypeData::Member(member) => {
                                if member.name.to_string().to_string() == attribute {
                                    let size = TypeInfo::from_type_index(&info, member.field_type)?.total_size();
                                    if !remaining.is_empty() {
                                        let (offset, size) = find_field_offset_and_size(info, &member.field_type, remaining, symbol)?;
                                        return Ok((member.offset + offset, size))
                                    }
                                    return Ok((member.offset, size))
                                }
                            }
                            _ => {} // TODO: Handle recursion if the field is another class.
                        }
                    }
                    return Err(anyhow::anyhow!("Attribute [{}] not found for symbol [{}]", attribute, symbol));
                }
                return Err(anyhow::anyhow!("UNEXPECTED: Symbol [{}] fields are not a field list.", symbol));
            }

            Err(anyhow::anyhow!("Symbol [{}] is a class, but has no fields.", symbol))
        }
        _ => Err(anyhow::anyhow!("Symbol [{}] is not a class. Cannot get class fields.", symbol))
    }
}

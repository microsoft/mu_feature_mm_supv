//! A module containing utility functions for extracting information from the PDB file.
use std::collections::HashMap;

use pdb::{FallibleIterator, Item, PrimitiveKind, TypeData, TypeIndex, TypeInformation};
use anyhow::{anyhow, Result};

use crate::POINTER_LENGTH;

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
            let size = POINTER_LENGTH as u32;
            let name = data.name.to_string().to_string();
            let type_index = None;
            map.insert(name.clone(), crate::Symbol {
                address,
                size,
                name,
                type_index,
            });
        }
        Ok(pdb::SymbolData::Data(data)) => {
            let address = data.offset.to_rva(&address_map).unwrap_or_default().0;
            let size = get_size_from_index(&info, data.type_index)? as u32;
            let name = data.name.to_string().to_string();
            let type_index = Some(data.type_index);
            map.insert(name.clone(), crate::Symbol {
                address,
                size,
                name,
                type_index,
            });
        }
        Ok(pdb::SymbolData::Procedure(data)) => {
            let address = data.offset.to_rva(&address_map).unwrap_or_default().0;
            let size = POINTER_LENGTH as u32;
            let name = data.name.to_string().to_string();
            let type_index = Some(data.type_index);
            map.insert(name.clone(), crate::Symbol {
                address,
                size,
                name,
                type_index,
            });
        }
        Ok(pdb::SymbolData::Label(data)) => {
            let address = data.offset.to_rva(&address_map).unwrap_or_default().0;
            let size = POINTER_LENGTH as u32;
            let name = data.name.to_string().to_string();
            let type_index = None;
            map.insert(name.clone(), crate::Symbol {
                address,
                size,
                name,
                type_index,
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

/// Returns the size of a type via it's type index in the type information stream
pub fn get_size_from_index(info: &TypeInformation, index: TypeIndex) -> Result<u64> {
    Ok(get_size_from_type(info, find_type(info, index)?.parse()?)?)
}

/// Returns the size of a data type in bytes.
pub fn get_size_from_type(info: &TypeInformation, data: TypeData) -> Result<u64> {
    let x = match data {
        TypeData::Primitive(prim) => {
            if prim.indirection.is_some() {
                POINTER_LENGTH
            } else {
                get_size_from_primitive(prim.kind)
            }
        }
        TypeData::Class(class) => {
            class.size
        }
        TypeData::Member(_) => {
            println!("ERROR: Member type unexpected in global data.");
            0
        }
        TypeData::MemberFunction(_) => {
            println!("ERROR: Member function unexpected in global data.");
            0
        }
        TypeData::OverloadedMethod(_) => {
            println!("ERROR: Overloaded method unexpected in C.");
            0
        }
        TypeData::Method(_) => {
            println!("ERROR: Method unexpected in C.");
            0
        }
        TypeData::StaticMember(_) => {
            println!("ERROR: Static method unexpected in C.");
            0
        }
        TypeData::Nested(_) => {
            println!("ERROR: Nested unexpected in global data.");
            0
        }
        TypeData::BaseClass(_) => {
            println!("ERROR: BaseClass unexpected in C.");
            0
        }
        TypeData::VirtualBaseClass(_) => {
            println!("ERROR: VirtualBaseClass unexpected in C.");
            0
        }
        TypeData::VirtualFunctionTablePointer(_) => {
            POINTER_LENGTH
        }
        TypeData::Procedure(_) => {
            println!("ERROR: Procedure unexpected in C.");
            0
        }
        TypeData::Pointer(_) => {
            POINTER_LENGTH
        }
        TypeData::Modifier(modifier) => {
            get_size_from_index(info, modifier.underlying_type)?
        }
        pdb::TypeData::Enumeration(enm) => {
            get_size_from_index(info, enm.underlying_type)?
        }
        TypeData::Enumerate(_) => {
            println!("ERROR: Unknown Type Enumerate"); // TODO: Figure out what this is if needed.
            0
        }
        TypeData::Array(arr) => {
            arr.dimensions[0] as u64
        }
        pdb::TypeData::Union(union) => {
            union.size
        }
        pdb::TypeData::Bitfield(bf) => {
            let r#type = get_size_from_index(info, bf.underlying_type)?;
            let size = r#type * bf.length as u64;
            size
        }
        TypeData::FieldList(fl) => {
            let mut size = 0;
            for r#type in fl.fields {
                size += get_size_from_type(info, r#type)?;
            }
            if let Some(cont) = fl.continuation {
                size += get_size_from_index(info, cont)?;
            }
            size
        }
        TypeData::ArgumentList(al) => {
            let mut size = 0;
            for item in al.arguments {
                size += get_size_from_index(info, item)?;
            }
            size
        }
        TypeData::MethodList(_) => {
            println!("ERROR: MethodList unexpected in C.");
            0
        }
        _ => {
            println!("ERROR: Unknown Type");
            0
        }
    };
    Ok(x)
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
                                    let size = get_size_from_index(&info, member.field_type)?;
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

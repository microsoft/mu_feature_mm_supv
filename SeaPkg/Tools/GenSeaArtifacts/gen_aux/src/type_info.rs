use std::fmt::Formatter;

use anyhow::Result;
use pdb::{TypeData, TypeIndex, TypeInformation};

use crate::{util::{find_type, get_size_from_primitive}, POINTER_LENGTH};

#[derive(Default, Clone)]
/// A struct that represents the type information of a symbol.
pub struct TypeInfo {
    element_size: u64,
    element_type: Option<TypeIndex>,
    pub count: u64,
}

impl std::fmt::Debug for TypeInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(r#type) = self.element_type {
            write!(f, "{{ element_type: {:?}, element_size: {:08X}, count: {} }}", r#type, self.element_size, self.count)
        } else {
            write!(f, "{{ element_size: {:08X}, count: {} }}", self.element_size, self.count)
        }
    }
}

impl TypeInfo {
    /// Creates a new TypeInfo with the given size and type id.
    pub fn one(size: u64, type_id: Option<TypeIndex>) -> Self {
        Self {
            element_size: size,
            element_type: type_id,
            count: 1,
        }
    }

    /// Creates a new TypeInfo that is a array of the given size and type id.
    pub fn many(size: u64, count: u64, type_id: Option<TypeIndex>) -> Self {
        Self {
            element_size: size,
            element_type: type_id,
            count,
        }
    }

    /// Returns the total size of the type.
    pub fn total_size(&self) -> u64 {
        self.element_size * self.count
    }

    /// Returns the size of the single element.
    pub fn element_size(&self) -> u64 {
        self.element_size
    }

    /// Returns the number of elements in the type.
    pub fn element_count(&self) -> u64 {
        self.count
    }

    /// Returns the type id of the underlying type.
    pub fn type_id(&self) -> Option<TypeIndex> {
        self.element_type
    }

    /// Creates a new TypeInfo from the given type index.
    pub fn from_type_index(info: &TypeInformation, index: TypeIndex) -> Result<Self> {
        Self::from_type_data(info, find_type(info, index)?.parse()?, index)
    }

    /// Creates a new TypeInfo from the given type data.
    pub fn from_type_data(info: &TypeInformation, data: TypeData, index: TypeIndex) -> Result<Self> {
        Ok(match data {
            TypeData::Primitive(prim) => {
                if prim.indirection.is_some() {
                    TypeInfo::one(POINTER_LENGTH, Some(index))
                } else {
                    TypeInfo::one(get_size_from_primitive(prim.kind), Some(index))
                }
            }
            TypeData::Class(class) => {
                TypeInfo::one(class.size, Some(index))
            }
            TypeData::Member(_) => {
                println!("ERROR: Member type unexpected in global data.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::MemberFunction(_) => {
                println!("ERROR: Member function unexpected in global data.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::OverloadedMethod(_) => {
                println!("ERROR: Overloaded method unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::Method(_) => {
                println!("ERROR: Method unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::StaticMember(_) => {
                println!("ERROR: Static method unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::Nested(_) => {
                println!("ERROR: Nested unexpected in global data.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::BaseClass(_) => {
                println!("ERROR: BaseClass unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::VirtualBaseClass(_) => {
                println!("ERROR: VirtualBaseClass unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::VirtualFunctionTablePointer(_) => {
                TypeInfo::one(POINTER_LENGTH, Some(index))
            }
            TypeData::Procedure(_) => {
                println!("ERROR: Procedure unexpected in C.");
                TypeInfo::one(0, Some(index))
            }
            TypeData::Pointer(_) => {
                TypeInfo::one(POINTER_LENGTH, Some(index))
            }
            TypeData::Modifier(modifier) => {
                TypeInfo::from_type_index(info, modifier.underlying_type)?
            }
            pdb::TypeData::Enumeration(enm) => {
                TypeInfo::from_type_index(info, enm.underlying_type)?
            }
            TypeData::Enumerate(_) => {
                println!("ERROR: Unknown Type Enumerate"); // TODO: Figure out what this is if needed.
                TypeInfo::one(0, Some(index))
            }
            TypeData::Array(arr) => {
                let total_size = arr.dimensions[0] as u64;
                let element = TypeInfo::from_type_index(info, arr.element_type)?;
                TypeInfo::many(element.total_size(), total_size / element.total_size(), element.type_id())
            }
            pdb::TypeData::Union(union) => {
                TypeInfo::one(union.size, Some(index))
            }
            pdb::TypeData::Bitfield(bf) => {
                let type_info = TypeInfo::from_type_index(info, bf.underlying_type)?;
                let size = type_info.total_size() * bf.length as u64;
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
                println!("ERROR: MethodList unexpected in C.");
                TypeInfo::one(0, None)
            }
            _ => {
                println!("ERROR: Unknown Type");
                TypeInfo::one(0, None)
            }
        })
    }
}

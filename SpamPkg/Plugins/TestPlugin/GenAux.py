from pathlib import Path
import ctypes
import sys
from pefile import PE
import yaml

VALIDATION_TYPES = {
    "NONE": 0,
    "NON_ZERO": 1,
    "CONTENT": 2,
    "MEM_ATTR": 3,
    "SELF": 4,
}


class Map:
    def __init__(self):
        self.sections = {}
        self.symbols = []
    
    def from_lines(file: Path):
        map_file = Map()
        in_section_table = False
        in_symbols_table = False

        for line in file.open("r").readlines():
            line = line.strip()
            if line == "":
                continue

            if line.split() == ["Start", "Length", "Name", "Class"]:
                in_section_table = True

            if line.split() == ["Address", "Publics", "by", "Value", "Rva+Base", "Lib:Object"]:
                in_section_table = False
                in_symbols_table = True

            
            if in_section_table:
                if ":" not in line.split()[0]:
                    continue
                section = Section.from_line(line)
                map_file.sections.setdefault(section.index, []).append(section)

            if in_symbols_table:
                if ":" not in line.split()[0]:
                    continue
                symbol = Symbol.from_line(line)
                map_file.symbols.append(symbol)

        # Sort the symbols by address
        map_file.symbols.sort(key=lambda x: x.rva_and_base)
        return map_file


class Section:
    def __init__(self):
        self.index = 0
        self.length = 0
        self.name = ""
        self.class_name = ""

    @staticmethod
    def from_line(line: str):
        entry = Section()
        parts = line.strip().split()
        (index, start) = parts[0].split(":")
        entry.index = int(index, 16)
        entry.start = int(start, 16)
        if not parts[1].endswith("H"):
            raise RuntimeError("Unexpected encoding for length")
        entry.length = int(parts[1][:-1], 16)
        entry.name = parts[2]
        entry.class_name = parts[3]
        return entry


class Symbol:

    def __init__(self):
        self.section = ""
        self.address = ""
        self.name = ""
        self.is_function = False
        self.rva_and_base = ""

    @staticmethod
    def from_line(line: str):
        entry = Symbol()
        parts = line.strip().split()

        (section, address) = parts[0].split(":")
        entry.section = int(section, 16)
        entry.address = int(address, 16)
        entry.name = parts[1]
        entry.rva_and_base = int(parts[2], 16)
        if len(parts[3]) == 1:
            entry.is_function = True
        return entry


class ImageValidationDataHeader(ctypes.Structure):
    """Class representing the C structure IMAGE_VALIDATION_HEADER."""
    _fields_ = [
        ('header_signature', ctypes.c_uint32),
        ('size', ctypes.c_uint32),
        ('entry_count', ctypes.c_uint32),
        ('offset_to_first_entry', ctypes.c_uint32),
        ('offset_to_first_default', ctypes.c_uint32),
    ]
    def __init__(self):
        self.header_signature = 0x444C4156
        self.size = 20
        self.entry_count = 0
        self.offset_to_first_entry = 0
        self.offset_to_first_default = 0


class ImageValidationEntryHeader(ctypes.Structure):
    """Class representing the C structure IMAGE_VALIDATION_ENTRY_HEADER."""
    _fields_ = [
        ('entry_signature', ctypes.c_uint32),
        ('offset', ctypes.c_uint32),
        ('size', ctypes.c_uint32),
        ('validation_type', ctypes.c_uint32),
        ('offset_to_default', ctypes.c_uint32),
    ]
    def __init__(self):
        self.entry_signature = 0x52544E45
        self.offset = 0
        self.size = 0
        self.validation_type = 0
        self.offset_to_default = 0


class ImageValidationDataTest:
    """Class representing the C structure IMAGE_VALIDATION_DATA_TEST."""

    def __init__(self):
        self.header = ImageValidationDataHeader()
        self.entries = []
        self.raw_data = bytearray()

    @staticmethod
    def from_map(map: Map, image: bytearray, config: dict):
        aux = ImageValidationDataTest()
        aux.header = ImageValidationDataHeader()

        # Filter out the unwind symbols.
        symbols = list(filter(lambda x: not x.name.startswith("$unwind"), map.symbols))

        # Ignore the last entry - cannot calculate size
        offset = 20 + (20 * len(symbols)) - 20
        aux.header.offset_to_first_default = offset
        aux.header.offset_to_first_entry = 20
        for i, symbol in enumerate(map.symbols):
            # Ignore the last entry - cannot calculate size
            if i == len(symbols) - 1:
                break

            entry = ImageValidationEntryHeader()
            entry.offset = symbol.rva_and_base
            entry.offset_to_default = offset
            entry.validation_type = VALIDATION_TYPES[config.get(symbol.name, "NONE")]
            entry.size = calculate_size(symbols, i)
            
            aux.header.entry_count +=1
            aux.header.size += entry.size + 20
            aux.entries.append(entry)
            raw_data = image[symbol.rva_and_base:symbol.rva_and_base + entry.size]
            aux.raw_data.extend(bytearray(raw_data))

            offset += entry.size

        return aux
    
    def __bytes__(self):
        b = bytearray(self.header)
        for entry in self.entries:
            b.extend(bytearray(entry))
        b.extend(self.raw_data)

        return bytes(b)


def calculate_size(symbols: dict, cur_index: int):
    """Calculates the size of the current symbol."""
    if symbols[cur_index].is_function:
        return 8

    if cur_index == len(symbols) - 1:
        print("Error: We should be skipping the last symbol.")
        sys.exit(1)
    else:
        return symbols[cur_index + 1].rva_and_base - symbols[cur_index].rva_and_base


def generate_image_validation_binary(input: Path, efi: Path, output: Path, config: Path):
    """Generate an aux file.

    Args:
        input (Path): The input file to parse
        output (Path): The output file to write to
    
    Raises:
        FileNotFoundError: If the input file does not exist
        ValueError: If the input file is not a supported file type
    """
    if not input.exists():
        raise FileNotFoundError(str(input))
    
    if not efi.exists():
        raise FileNotFoundError(str(efi))
    
    if input.suffix != ".map":
        raise ValueError(str(input))
    
    if config is not None and config.suffix not in [".json", ".yaml", ".yml", ".cfg"]:
        raise ValueError(str(config))
    
    loaded_image = pe32_load_image(efi)
    map_file = Map.from_lines(input)
    config = yaml.safe_load(config.open("r").read()) or {} if config else {}
    data_test = ImageValidationDataTest.from_map(map_file, loaded_image, config)

    aux_data = bytearray(bytes(data_test))
    
    verify_aux_data(aux_data, loaded_image, data_test)
    output.write_bytes(aux_data)


def verify_aux_data(aux_data: bytearray, loaded_image: bytearray, data_test: ImageValidationDataTest):
    """Verify the values in the aux data match the values in the loaded image.
    
    This is to verify that the aux data was generated correctly at the correct addresses.

    Will exit the program if a test fails.
    """
    header = ImageValidationDataHeader.from_buffer(aux_data, 0)

    if header.entry_count != data_test.header.entry_count:
        print("Error: Entry count does not match.")
        sys.exit(1)
    
    offset_to_entry = header.offset_to_first_entry
    offset_to_default = header.offset_to_first_default

    for _ in range(header.entry_count):
        entry = ImageValidationEntryHeader.from_buffer(aux_data, offset_to_entry)
        
        aux_value = aux_data[entry.offset_to_default:(entry.offset_to_default + entry.size)]
        image_value = loaded_image[entry.offset:(entry.offset + entry.size)]

        if aux_value != image_value:
            print(f"Error: {entry.offset} - {entry.offset + entry.size} does not match.")
            print("  aux_value:", aux_value)
            print("  image_value:", image_value)
            sys.exit(1)

        offset_to_entry += 20  # Size of each entry header
        offset_to_default += entry.size


def pe32_load_image(image: Path) -> bytearray:
    """Load a PE32 image into a buffer."""
    pe = PE(image)
    image = bytearray(image.read_bytes())

    # Create the loaded image buffer, zero'd out
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    loaded_image = bytearray(int(size_of_image))

    # Copy the headers into the loaded image
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    loaded_image[:size_of_headers] = image[:size_of_headers]

    # copy the sections into the loaded image
    for section in pe.sections:
        size = section.Misc_VirtualSize
        if size == 0 or size > section.SizeOfRawData:
            size = section.SizeOfRawData
        
        loaded_image[section.VirtualAddress:section.VirtualAddress + size] = image[section.PointerToRawData:section.PointerToRawData + size]
    return loaded_image


def go():
    """Main entry point for the executable."""
    parser = ArgumentParser(description="Test Plugin")
    parser.add_argument("-e", "--efi", help="Path to the EFI image.")
    parser.add_argument("-m", "--map", help="Path to the EFI image's MAP file.")
    parser.add_argument("-c", "--config", help="Path to the configuration file.")
    parser.add_argument("-o", "--output", help="Path to write the Aux file to.", default="Aux.bin")

    args = parser.parse_args()

    map_file = Path(args.map)
    efi_image = Path(args.efi)
    config = Path(args.config) if args.config else None
    output_file = Path(args.output)

    try:
        generate_image_validation_binary(map_file, efi_image, output_file, config)
    except FileNotFoundError as e:
        print(f"Error: {e} does not exist.")
        return 1
    except ValueError as e:
        print(e)
        print(f"Error: {e} is not a supported file type. ")
        return 1
    
    return 0


if __name__ == "__main__":
    from argparse import ArgumentParser
    sys.exit(go())
    

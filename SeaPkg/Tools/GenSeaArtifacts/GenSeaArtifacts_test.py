
# @file
# unit tests for GenSeaArtifacts
#
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from GenSeaArtifacts import HASH_ALGORITHM, calculate_loadable_image_hash

# The byte lld-link leaves in the file-alignment tail of an executable section.
INT3 = 0xCC


def build_pe(sections, pe_offset=0x80, optional_header_size=0xF0):
    """Builds a minimal PE/COFF image.

    Only the fields calculate_loadable_image_hash reads are populated; the rest is left zero.

    Args:
        sections: a list of (virtual_size, raw_bytes) pairs, laid out in order.

    Returns:
        The image bytes.
    """
    section_table = pe_offset + 24 + optional_header_size
    raw_start = section_table + 40 * len(sections)

    image = bytearray(raw_start)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset:pe_offset + 4] = b"PE\0\0"
    struct.pack_into("<H", image, pe_offset + 6, len(sections))
    struct.pack_into("<H", image, pe_offset + 20, optional_header_size)

    offset = raw_start
    for index, (virtual_size, raw) in enumerate(sections):
        header = section_table + index * 40
        image[header:header + 8] = f".s{index}".ljust(8, "\0").encode()
        struct.pack_into("<IIII", image, header + 8, virtual_size, 0x1000 * (index + 1), len(raw), offset)
        image.extend(raw)
        offset += len(raw)

    return bytes(image)


class TestCalculateLoadableImageHash(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def write(self, name, data):
        path = Path(self.directory.name) / name
        path.write_bytes(data)
        return path

    def digest(self, data):
        return hashlib.new(HASH_ALGORITHM, data).hexdigest()

    def test_fill_byte_in_section_padding_does_not_change_the_hash(self):
        """Two linkers disagreeing on the fill byte must still produce the same reference."""
        payload = b"\x01" * 0x10
        zeroed = build_pe([(len(payload), payload + b"\x00" * 0x30)])
        filled = build_pe([(len(payload), payload + bytes([INT3]) * 0x30)])

        self.assertNotEqual(zeroed, filled)
        self.assertEqual(
            calculate_loadable_image_hash(self.write("zeroed.efi", zeroed)),
            calculate_loadable_image_hash(self.write("filled.efi", filled)),
        )

    def test_hash_is_taken_over_the_zeroed_image(self):
        """The reference is the image a loader can reproduce, which has zeros in the padding."""
        payload = b"\x02" * 0x20
        zeroed = build_pe([(len(payload), payload + b"\x00" * 0x20)])
        filled = build_pe([(len(payload), payload + bytes([INT3]) * 0x20)])

        self.assertEqual(
            calculate_loadable_image_hash(self.write("filled.efi", filled)),
            self.digest(zeroed),
        )

    def test_bytes_within_virtual_size_are_never_zeroed(self):
        """Only the tail past VirtualSize is padding; the loader copies everything before it."""
        payload = bytes([INT3]) * 0x40
        image = build_pe([(len(payload), payload)])

        self.assertEqual(
            calculate_loadable_image_hash(self.write("exact.efi", image)),
            self.digest(image),
        )

    def test_section_larger_in_memory_than_on_disk_is_untouched(self):
        """A .bss style section has no raw bytes to canonicalize."""
        image = build_pe([(0x1000, bytes([INT3]) * 0x10)])

        self.assertEqual(
            calculate_loadable_image_hash(self.write("bss.efi", image)),
            self.digest(image),
        )

    def test_section_without_virtual_size_is_untouched(self):
        """A zero VirtualSize says nothing about how much of the section is real."""
        image = build_pe([(0, bytes([INT3]) * 0x10)])

        self.assertEqual(
            calculate_loadable_image_hash(self.write("novsize.efi", image)),
            self.digest(image),
        )

    def test_every_section_is_canonicalized(self):
        """Padding is per section, so a later section must not be skipped."""
        first = b"\x03" * 0x10
        second = b"\x04" * 0x10
        zeroed = build_pe([(len(first), first + b"\x00" * 0x10), (len(second), second + b"\x00" * 0x10)])
        filled = build_pe(
            [(len(first), first + bytes([INT3]) * 0x10), (len(second), second + bytes([INT3]) * 0x10)]
        )

        self.assertEqual(
            calculate_loadable_image_hash(self.write("multi.efi", filled)),
            self.digest(zeroed),
        )

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            calculate_loadable_image_hash(Path(self.directory.name) / "absent.efi")

    def test_missing_dos_header_raises(self):
        path = self.write("nodos.efi", b"XX" + build_pe([(0x10, b"\x00" * 0x10)])[2:])

        with self.assertRaises(ValueError):
            calculate_loadable_image_hash(path)

    def test_missing_pe_signature_raises(self):
        image = bytearray(build_pe([(0x10, b"\x00" * 0x10)]))
        pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
        image[pe_offset:pe_offset + 4] = b"NOPE"

        with self.assertRaises(ValueError):
            calculate_loadable_image_hash(self.write("nosig.efi", bytes(image)))

    def test_section_past_end_of_file_raises(self):
        """A truncated image must be rejected rather than silently hashed short."""
        image = build_pe([(0x10, b"\x05" * 0x40)])

        with self.assertRaises(ValueError):
            calculate_loadable_image_hash(self.write("short.efi", image[:-0x20]))


if __name__ == "__main__":
    unittest.main()

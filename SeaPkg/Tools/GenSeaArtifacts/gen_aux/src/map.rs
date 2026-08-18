//! Parsing of MSVC style linker map files, used to recover symbols the PDB file does not name.
//!
//! The compiler does not emit debug information for every static. A `&dyn Trait` static, for
//! example, is split by the optimizer into one global per pointer, and a single debug entry cannot
//! describe a variable spread across several globals, so the entry is dropped. The linker still
//! names each piece, so a map file recovers what the PDB file lost. Producing a map does not change
//! the image; it is an additional linker output.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent

/// A symbol recovered from a linker map file.
#[derive(Debug, Clone)]
pub struct MapSymbol {
    /// The one based index of the section containing the symbol.
    pub section: usize,
    /// The offset of the symbol from the start of its section.
    pub offset: u32,
    /// The demangled name of the symbol.
    pub name: String,
    /// The size of the symbol in bytes.
    pub size: u32,
    /// The `(offset, size)` of each piece the symbol was split into, relative to its start.
    ///
    /// A map names every piece the optimizer produced but records no field names, so these are
    /// the only structure a recovered symbol has. A symbol the optimizer did not split has a
    /// single piece covering the whole symbol.
    pub pieces: Vec<(u32, u32)>,
}

/// Parses the symbols out of the contents of a linker map file.
///
/// A map file records neither types nor sizes, so each symbol is sized by the distance to the next
/// symbol in the same section. Trailing symbols, whose size cannot be established that way, are
/// discarded rather than guessed at.
pub fn parse(contents: &str) -> Vec<MapSymbol> {
    let mut raw = Vec::new();

    for line in contents.lines() {
        if let Some(entry) = parse_line(line) {
            raw.push(entry);
        }
    }

    raw.sort_by_key(|(section, offset, _)| (*section, *offset));

    coalesce(raw)
}

/// Parses a single `SSSS:OOOOOOOO <symbol> <address> <object>` line.
fn parse_line(line: &str) -> Option<(usize, u32, String)> {
    let mut parts = line.split_whitespace();

    let (section, offset) = parts.next()?.split_once(':')?;
    let section = usize::from_str_radix(section, 16).ok()?;
    let offset = u32::from_str_radix(offset, 16).ok()?;

    // A section index of zero is used for absolute symbols, which have no storage.
    if section == 0 {
        return None;
    }

    let name = parts.next()?;

    // The address column confirms this is a symbol line rather than prose that happens to start
    // with something colon separated.
    let address = parts.next()?;
    if address.len() < 8 || u64::from_str_radix(address, 16).is_err() {
        return None;
    }

    Some((section, offset, name.to_string()))
}

/// Groups the pieces of split symbols back together and assigns each symbol a size.
///
/// The optimizer names the pieces of a split global `<symbol>.0`, `<symbol>.1` and so on. Adjacent
/// pieces sharing a base name describe one variable, so they are merged back into a single symbol
/// spanning all of them.
///
/// A map file records no sizes, so a symbol is measured by the distance to whatever follows it.
/// That distance also covers any alignment padding, which would overstate the symbol. Every piece
/// but the last is bounded by the next piece of the same symbol and so is exact; the last piece is
/// therefore assumed to match the piece before it, which keeps padding out of the result for the
/// split globals this exists to recover. A symbol of a single piece has nothing to calibrate
/// against and is still measured by the distance to the next symbol, so it may absorb padding.
fn coalesce(raw: Vec<(usize, u32, String)>) -> Vec<MapSymbol> {
    let mut named = raw
        .into_iter()
        .map(|(section, offset, mangled)| {
            let (base, _) = split_piece_suffix(&mangled);
            (section, offset, demangle(base))
        })
        .collect::<Vec<_>>();

    // Aliases of the same address collapse to one entry once the piece suffix and mangling are
    // gone, and a repeated address would otherwise be read as a zero sized piece.
    named.dedup();

    // Collect the runs of consecutive pieces that describe the same variable.
    let mut groups: Vec<Vec<(usize, u32, String)>> = Vec::new();
    for entry in named {
        match groups.last_mut() {
            Some(group) if group[0].0 == entry.0 && group[0].2 == entry.2 => group.push(entry),
            _ => groups.push(vec![entry]),
        }
    }

    let mut ret = Vec::new();
    for (index, group) in groups.iter().enumerate() {
        let (section, start, name) = (group[0].0, group[0].1, group[0].2.clone());
        let last_offset = group[group.len() - 1].1;

        let last_size = if group.len() > 1 {
            // The preceding piece is bounded by this one, so its size is exact.
            last_offset - group[group.len() - 2].1
        } else {
            // Nothing to calibrate against; fall back to the distance to the next symbol.
            match groups.get(index + 1) {
                Some(next) if next[0].0 == section => next[0].1 - last_offset,
                // The extent cannot be established, so the symbol is not reported.
                _ => continue,
            }
        };

        // Every piece except the last is exactly bounded by the piece that follows it.
        let pieces = group
            .iter()
            .enumerate()
            .map(|(piece, (_, offset, _))| {
                let size = match group.get(piece + 1) {
                    Some((_, next, _)) => next - offset,
                    None => last_size,
                };
                (offset - start, size)
            })
            .collect::<Vec<_>>();

        ret.push(MapSymbol {
            section,
            offset: start,
            name,
            size: (last_offset - start) + last_size,
            pieces,
        });
    }

    ret
}

/// Splits a `<symbol>.<n>` piece suffix off of a mangled name.
fn split_piece_suffix(mangled: &str) -> (&str, Option<u32>) {
    match mangled.rsplit_once('.') {
        Some((base, suffix)) => match suffix.parse::<u32>() {
            Ok(piece) => (base, Some(piece)),
            Err(_) => (mangled, None),
        },
        None => (mangled, None),
    }
}

/// Demangles a Rust symbol name, leaving other names untouched.
fn demangle(mangled: &str) -> String {
    // The alternate form omits the trailing hash of the legacy mangling, matching the names the
    // PDB file uses.
    format!("{:#}", rustc_demangle::demangle(mangled))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_map_parse_line_accepts_a_symbol_line() {
        let line =
            " 0003:00000320       _RNvCs2NSaCUTa2Sz_3log6LOGGER.0 0000000140034320     some.o";
        let (section, offset, name) = parse_line(line).expect("line should parse");
        assert_eq!(section, 3);
        assert_eq!(offset, 0x320);
        assert_eq!(name, "_RNvCs2NSaCUTa2Sz_3log6LOGGER.0");
    }

    #[test]
    fn test_map_parse_line_rejects_prose() {
        assert!(parse_line(" Address         Publics by Value              Rva+Base").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line("Timestamp is 68b0f0e1 (Sun Aug 03 00:00:00 2026)").is_none());
    }

    #[test]
    fn test_map_parse_reads_symbols_out_of_a_map() {
        let contents = "\
 Address         Publics by Value              Rva+Base               Lib:Object

 0003:00000330       _RNvCs2NSaCUTa2Sz_3log5STATE 0000000140034330     some.o
 0003:00000320       _RNvCs2NSaCUTa2Sz_3log6LOGGER.0 0000000140034320     some.o
 0003:00000328       _RNvCs2NSaCUTa2Sz_3log6LOGGER.1 0000000140034328     some.o
 0000:00000000       __ImageBase                  0000000140000000     <linker-defined>
";

        let symbols = parse(contents);

        // Lines arrive out of order and the trailing symbol has no successor to size it against.
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "log::LOGGER");
        assert_eq!(symbols[0].section, 3);
        assert_eq!(symbols[0].offset, 0x320);
        assert_eq!(symbols[0].size, 0x10);
    }

    #[test]
    fn test_map_parse_accepts_an_empty_map() {
        assert!(parse("").is_empty());
    }

    #[test]
    fn test_map_split_piece_suffix() {
        assert_eq!(split_piece_suffix("sym.0"), ("sym", Some(0)));
        assert_eq!(split_piece_suffix("sym.12"), ("sym", Some(12)));
        // A dot that does not introduce a piece index is part of the name.
        assert_eq!(split_piece_suffix("sym.llvm"), ("sym.llvm", None));
        assert_eq!(split_piece_suffix("sym"), ("sym", None));
    }

    #[test]
    fn test_map_coalesce_merges_split_pieces() {
        let raw = vec![
            (3, 0x320, "_RNvCs2NSaCUTa2Sz_3log6LOGGER.0".to_string()),
            (3, 0x328, "_RNvCs2NSaCUTa2Sz_3log6LOGGER.1".to_string()),
            (3, 0x330, "_RNvCs2NSaCUTa2Sz_3log5STATE".to_string()),
            (3, 0x338, "_RNvCs2NSaCUTa2Sz_3log5OTHER".to_string()),
        ];

        let symbols = coalesce(raw);

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "log::LOGGER");
        assert_eq!(symbols[0].offset, 0x320);
        // Both eight byte pieces are merged into one sixteen byte symbol.
        assert_eq!(symbols[0].size, 0x10);
        // The pieces stay individually addressable, because they are the only structure a
        // recovered symbol has.
        assert_eq!(symbols[0].pieces, vec![(0x0, 0x8), (0x8, 0x8)]);
        assert_eq!(symbols[1].name, "log::STATE");
        assert_eq!(symbols[1].size, 0x8);
        assert_eq!(symbols[1].pieces, vec![(0x0, 0x8)]);
    }

    #[test]
    fn test_map_coalesce_drops_symbols_of_unknown_extent() {
        // The final symbol has nothing after it to bound its size, so it is not reported.
        let raw = vec![
            (3, 0x100, "_RNvCs2NSaCUTa2Sz_3log5FIRST".to_string()),
            (3, 0x108, "_RNvCs2NSaCUTa2Sz_3log6SECOND".to_string()),
        ];

        let symbols = coalesce(raw);

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "log::FIRST");
    }

    #[test]
    fn test_map_coalesce_keeps_padding_out_of_a_split_symbol() {
        // Alignment padding separates the split symbol from what follows it. Sizing the last piece
        // by the distance to the next symbol would swallow that padding, so the piece before it is
        // used as the measure instead.
        let raw = vec![
            (3, 0x320, "_RNvCs2NSaCUTa2Sz_3log6LOGGER.0".to_string()),
            (3, 0x328, "_RNvCs2NSaCUTa2Sz_3log6LOGGER.1".to_string()),
            (3, 0x400, "_RNvCs2NSaCUTa2Sz_3log5OTHER".to_string()),
            (3, 0x408, "_RNvCs2NSaCUTa2Sz_3log4LAST".to_string()),
        ];

        let symbols = coalesce(raw);

        assert_eq!(symbols[0].name, "log::LOGGER");
        assert_eq!(symbols[0].offset, 0x320);
        // Sixteen bytes, not the 0xE0 that reaches all the way to the next symbol.
        assert_eq!(symbols[0].size, 0x10);
    }

    #[test]
    fn test_map_coalesce_sizes_a_single_piece_symbol_by_its_successor() {
        let raw = vec![
            (3, 0x100, "_RNvCs2NSaCUTa2Sz_3log5STATE".to_string()),
            (3, 0x108, "_RNvCs2NSaCUTa2Sz_3log5OTHER".to_string()),
            (3, 0x110, "_RNvCs2NSaCUTa2Sz_3log4LAST".to_string()),
        ];

        let symbols = coalesce(raw);

        assert_eq!(symbols[0].name, "log::STATE");
        assert_eq!(symbols[0].size, 0x8);
    }
}

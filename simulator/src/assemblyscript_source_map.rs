// Copyright 2026 Erst Users
// SPDX-License-Identifier: Apache-2.0

//! AssemblyScript Source Map Support
//!
//! Parses standard Source Map V3 format embedded in WASM custom sections
//! (`sourceMappingURL` or `sourceMap`) and maps WASM byte offsets back to
//! original AssemblyScript source file locations.
//!
//! The Source Map V3 spec uses Base64 VLQ-encoded segments in a `mappings`
//! string to represent generated-to-original position correspondences.

use crate::source_mapper::SourceLocation;
use base64::Engine as _;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Parsed Source Map V3 JSON structure.
#[derive(Debug, Deserialize)]
struct SourceMapV3 {
    version: u32,
    sources: Vec<String>,
    #[serde(default)]
    names: Vec<String>,
    mappings: String,
    #[serde(default, rename = "sourceRoot")]
    source_root: Option<String>,
}

/// A single decoded mapping segment from the source map.
#[derive(Debug, Clone)]
struct MappingSegment {
    generated_column: u32,
    source_index: Option<u32>,
    original_line: Option<u32>,
    original_column: Option<u32>,
    name_index: Option<u32>,
}

/// Resolved source location from an AssemblyScript source map.
#[derive(Debug, Clone)]
pub struct AsMappingEntry {
    pub wasm_offset: u64,
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}

/// Decode a single Base64 VLQ value from the mappings string.
///
/// Returns the decoded value and the number of characters consumed.
fn decode_vlq(chars: &[u8], start: usize) -> Option<(i32, usize)> {
    const VLQ_BASE_SHIFT: u32 = 5;
    const VLQ_BASE: u32 = 1 << VLQ_BASE_SHIFT; // 32
    const VLQ_CONTINUATION_BIT: u32 = VLQ_BASE; // 32

    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut pos = start;

    loop {
        if pos >= chars.len() {
            return None;
        }

        let digit = base64_char_to_value(chars[pos])?;
        pos += 1;

        let has_continuation = (digit & VLQ_CONTINUATION_BIT) != 0;
        let value_part = digit & (VLQ_BASE - 1);
        result += value_part << shift;
        shift += VLQ_BASE_SHIFT;

        if !has_continuation {
            // Lowest bit is sign
            let is_negative = (result & 1) == 1;
            let magnitude = result >> 1;
            let signed = if is_negative {
                -(magnitude as i32)
            } else {
                magnitude as i32
            };
            return Some((signed, pos - start));
        }
    }
}

/// Convert a Base64 character to its 6-bit value.
fn base64_char_to_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Parse a Source Map V3 mappings string into decoded segments grouped by
/// generated line.
fn parse_mappings(mappings: &str) -> Vec<Vec<MappingSegment>> {
    let bytes = mappings.as_bytes();
    let mut lines: Vec<Vec<MappingSegment>> = Vec::new();
    let mut current_line: Vec<MappingSegment> = Vec::new();

    // Running state across the entire mappings string (values are relative)
    let mut gen_col: i32 = 0;
    let mut src_idx: i32 = 0;
    let mut orig_line: i32 = 0;
    let mut orig_col: i32 = 0;
    let mut name_idx: i32 = 0;

    let mut pos = 0;

    while pos < bytes.len() {
        match bytes[pos] {
            b';' => {
                // New generated line
                lines.push(std::mem::take(&mut current_line));
                gen_col = 0;
                pos += 1;
            }
            b',' => {
                // Next segment on the same line
                pos += 1;
            }
            _ => {
                // Decode segment fields (1, 4, or 5 VLQ values)
                let mut fields: Vec<i32> = Vec::with_capacity(5);

                while pos < bytes.len() && bytes[pos] != b',' && bytes[pos] != b';' {
                    if let Some((value, consumed)) = decode_vlq(bytes, pos) {
                        fields.push(value);
                        pos += consumed;
                    } else {
                        // Skip invalid character
                        pos += 1;
                        break;
                    }
                }

                if fields.is_empty() {
                    continue;
                }

                gen_col += fields[0];

                let (source_index, original_line, original_column, name_index) =
                    if fields.len() >= 4 {
                        src_idx += fields[1];
                        orig_line += fields[2];
                        orig_col += fields[3];
                        let ni = if fields.len() >= 5 {
                            name_idx += fields[4];
                            Some(name_idx as u32)
                        } else {
                            None
                        };
                        (
                            Some(src_idx as u32),
                            Some(orig_line as u32),
                            Some(orig_col as u32),
                            ni,
                        )
                    } else {
                        (None, None, None, None)
                    };

                current_line.push(MappingSegment {
                    generated_column: gen_col as u32,
                    source_index,
                    original_line,
                    original_column,
                    name_index,
                });
            }
        }
    }

    // Push final line
    if !current_line.is_empty() {
        lines.push(current_line);
    }

    lines
}

/// Extract a source map JSON string from WASM custom sections.
///
/// Looks for custom sections named `sourceMappingURL` (containing the
/// inline source map data as a data URI) or `sourceMap` (containing the
/// raw JSON directly).
pub fn extract_source_map_from_wasm(wasm_bytes: &[u8]) -> Option<String> {
    let parser = wasmparser::Parser::new(0);

    for payload in parser.parse_all(wasm_bytes) {
        if let Ok(wasmparser::Payload::CustomSection(section)) = payload {
            match section.name() {
                "sourceMap" => {
                    // Raw JSON source map embedded directly
                    if let Ok(json_str) = std::str::from_utf8(section.data()) {
                        return Some(json_str.to_string());
                    }
                }
                "sourceMappingURL" => {
                    if let Ok(url_str) = std::str::from_utf8(section.data()) {
                        // Check for data URI with inline JSON
                        if let Some(json) = url_str
                            .strip_prefix("data:application/json;base64,")
                            .or_else(|| {
                                url_str.strip_prefix("data:application/json;charset=utf-8;base64,")
                            })
                        {
                            if let Ok(decoded) =
                                base64::engine::general_purpose::STANDARD.decode(json.trim())
                            {
                                if let Ok(s) = String::from_utf8(decoded) {
                                    return Some(s);
                                }
                            }
                        }
                        // Plain URL reference — not supported for embedded resolution,
                        // but return the URL so callers can attempt external loading
                        return Some(url_str.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    None
}

/// Parse a Source Map V3 JSON string and build a sorted mapping table
/// from WASM byte offsets to original source locations.
///
/// The generated line numbers in the source map correspond to WASM function
/// indices or code section offsets. Each segment's generated column maps to a
/// byte offset within that generated line.
pub fn parse_source_map(json_str: &str) -> Option<Vec<AsMappingEntry>> {
    let source_map: SourceMapV3 = serde_json::from_str(json_str).ok()?;

    if source_map.version != 3 {
        return None;
    }

    let source_root = source_map.source_root.unwrap_or_default();
    let lines = parse_mappings(&source_map.mappings);
    let mut entries: Vec<AsMappingEntry> = Vec::new();

    for (gen_line_idx, segments) in lines.iter().enumerate() {
        for segment in segments {
            let Some(src_idx) = segment.source_index else {
                continue;
            };
            let Some(orig_line) = segment.original_line else {
                continue;
            };

            let source_file = source_map.sources.get(src_idx as usize)?;
            let file_path = if source_root.is_empty() {
                source_file.clone()
            } else {
                format!("{}/{}", source_root.trim_end_matches('/'), source_file)
            };

            // In WASM source maps, the generated line typically represents
            // a function or section, and the column is the byte offset.
            // Use a combined offset: line * large_stride + column
            // to produce unique wasm_offset values for lookups.
            let wasm_offset = (gen_line_idx as u64) * 65536 + segment.generated_column as u64;

            entries.push(AsMappingEntry {
                wasm_offset,
                file: file_path,
                // Source map lines are 0-based; SourceLocation lines are 1-based
                line: orig_line + 1,
                column: segment.original_column,
            });
        }
    }

    entries.sort_by_key(|e| e.wasm_offset);
    Some(entries)
}

/// Convert parsed AssemblyScript mapping entries into `SourceLocation`
/// objects suitable for the existing source mapper pipeline.
pub fn as_entries_to_source_locations(entries: &[AsMappingEntry]) -> BTreeMap<u64, SourceLocation> {
    let mut map = BTreeMap::new();
    for entry in entries {
        map.insert(
            entry.wasm_offset,
            SourceLocation {
                file: entry.file.clone(),
                line: entry.line,
                column: entry.column,
                column_end: None,
                github_link: None,
            },
        );
    }
    map
}

/// Attempt to build a source-location cache from an AssemblyScript source map
/// embedded in the given WASM bytes.
///
/// Returns `Some` with sorted mapping entries on success, `None` if no
/// AssemblyScript source map is found or it cannot be parsed.
pub fn try_build_as_line_cache(wasm_bytes: &[u8]) -> Option<Vec<AsMappingEntry>> {
    let json_str = extract_source_map_from_wasm(wasm_bytes)?;

    // Skip if the extracted string looks like a URL rather than JSON
    if !json_str.trim_start().starts_with('{') {
        return None;
    }

    parse_source_map(&json_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    // ---- VLQ decoding tests ----

    #[test]
    fn test_decode_vlq_zero() {
        let (val, consumed) = decode_vlq(b"A", 0).unwrap();
        assert_eq!(val, 0);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_vlq_positive() {
        // 'C' = 2 in base64 = binary 000010, VLQ: continuation=0, value=00001, sign=0 → +1
        let (val, consumed) = decode_vlq(b"C", 0).unwrap();
        assert_eq!(val, 1);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_vlq_negative() {
        // 'D' = 3 in base64 = binary 000011, VLQ: continuation=0, value=00001, sign=1 → -1
        let (val, consumed) = decode_vlq(b"D", 0).unwrap();
        assert_eq!(val, -1);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_vlq_multi_byte() {
        // Encode larger values that require continuation bits
        // 'g' = 32, continuation bit set → needs second char
        // 'B' = 1, no continuation → value = (1 << 5) | 0 = 32 >> 1 = 16
        let (val, consumed) = decode_vlq(b"gB", 0).unwrap();
        assert_eq!(val, 16);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_decode_vlq_invalid() {
        assert!(decode_vlq(b"", 0).is_none());
        assert!(decode_vlq(b"!", 0).is_none());
    }

    // ---- Base64 char conversion tests ----

    #[test]
    fn test_base64_char_to_value() {
        assert_eq!(base64_char_to_value(b'A'), Some(0));
        assert_eq!(base64_char_to_value(b'Z'), Some(25));
        assert_eq!(base64_char_to_value(b'a'), Some(26));
        assert_eq!(base64_char_to_value(b'z'), Some(51));
        assert_eq!(base64_char_to_value(b'0'), Some(52));
        assert_eq!(base64_char_to_value(b'9'), Some(61));
        assert_eq!(base64_char_to_value(b'+'), Some(62));
        assert_eq!(base64_char_to_value(b'/'), Some(63));
        assert_eq!(base64_char_to_value(b'!'), None);
    }

    // ---- Mappings parser tests ----

    #[test]
    fn test_parse_mappings_empty() {
        let lines = parse_mappings("");
        assert!(lines.is_empty());
    }

    #[test]
    fn test_parse_mappings_single_segment() {
        // "AAAA" = four zeros: genCol=0, srcIdx=0, origLine=0, origCol=0
        let lines = parse_mappings("AAAA");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), 1);
        assert_eq!(lines[0][0].generated_column, 0);
        assert_eq!(lines[0][0].source_index, Some(0));
        assert_eq!(lines[0][0].original_line, Some(0));
        assert_eq!(lines[0][0].original_column, Some(0));
    }

    #[test]
    fn test_parse_mappings_multiple_lines() {
        // Two lines separated by semicolon
        let lines = parse_mappings("AAAA;AACA");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].len(), 1);
        assert_eq!(lines[1].len(), 1);
        // Second line: genCol resets to 0, srcIdx stays 0, origLine increments by 1
        assert_eq!(lines[1][0].generated_column, 0);
        assert_eq!(lines[1][0].original_line, Some(1));
    }

    #[test]
    fn test_parse_mappings_multiple_segments() {
        // Two segments on one line separated by comma
        let lines = parse_mappings("AAAA,EAEC");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].len(), 2);
        // Second segment: genCol += 2, srcIdx += 0, origLine += 1, origCol += -1
        assert_eq!(lines[0][1].generated_column, 2);
        assert_eq!(lines[0][1].original_line, Some(1));
    }

    #[test]
    fn test_parse_mappings_empty_lines() {
        // Semicolons with no segments produce empty lines
        let lines = parse_mappings("AAAA;;;AACA");
        // "AAAA" → line 0, ";" → empty line 1, ";" → empty line 2, "AACA" → line 3
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].len(), 1);
        assert!(lines[1].is_empty());
        assert!(lines[2].is_empty());
        assert_eq!(lines[3].len(), 1);
    }

    // ---- Source map parsing tests ----

    #[test]
    fn test_parse_source_map_valid() {
        let json = r#"{
            "version": 3,
            "sources": ["assembly/index.ts"],
            "names": [],
            "mappings": "AAAA;AACA"
        }"#;

        let entries = parse_source_map(json).unwrap();
        assert!(!entries.is_empty());
        assert_eq!(entries[0].file, "assembly/index.ts");
        assert_eq!(entries[0].line, 1); // 0-based → 1-based
    }

    #[test]
    fn test_parse_source_map_with_source_root() {
        let json = r#"{
            "version": 3,
            "sources": ["index.ts"],
            "names": [],
            "mappings": "AAAA",
            "sourceRoot": "assembly/"
        }"#;

        let entries = parse_source_map(json).unwrap();
        assert_eq!(entries[0].file, "assembly/index.ts");
    }

    #[test]
    fn test_parse_source_map_wrong_version() {
        let json = r#"{
            "version": 2,
            "sources": ["test.ts"],
            "names": [],
            "mappings": "AAAA"
        }"#;

        assert!(parse_source_map(json).is_none());
    }

    #[test]
    fn test_parse_source_map_invalid_json() {
        assert!(parse_source_map("not json").is_none());
    }

    #[test]
    fn test_parse_source_map_entries_sorted() {
        let json = r#"{
            "version": 3,
            "sources": ["a.ts", "b.ts"],
            "names": [],
            "mappings": "AAAA,EACA;AACA"
        }"#;

        let entries = parse_source_map(json).unwrap();
        for window in entries.windows(2) {
            assert!(window[0].wasm_offset <= window[1].wasm_offset);
        }
    }

    // ---- Conversion to SourceLocation tests ----

    #[test]
    fn test_as_entries_to_source_locations() {
        let entries = vec![
            AsMappingEntry {
                wasm_offset: 100,
                file: "index.ts".to_string(),
                line: 10,
                column: Some(5),
            },
            AsMappingEntry {
                wasm_offset: 200,
                file: "lib.ts".to_string(),
                line: 20,
                column: None,
            },
        ];

        let locations = as_entries_to_source_locations(&entries);
        assert_eq!(locations.len(), 2);

        let loc = locations.get(&100).unwrap();
        assert_eq!(loc.file, "index.ts");
        assert_eq!(loc.line, 10);
        assert_eq!(loc.column, Some(5));
        assert!(loc.github_link.is_none());
    }

    // ---- WASM custom section extraction tests ----

    #[test]
    fn test_extract_source_map_from_minimal_wasm() {
        // Build a minimal WASM module with a "sourceMap" custom section
        let source_map_json = r#"{"version":3,"sources":["test.ts"],"names":[],"mappings":"AAAA"}"#;
        let wasm = build_wasm_with_custom_section("sourceMap", source_map_json.as_bytes());

        let result = extract_source_map_from_wasm(&wasm);
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert!(extracted.contains("\"version\":3"));
    }

    #[test]
    fn test_extract_source_map_data_uri() {
        let source_map_json = r#"{"version":3,"sources":["test.ts"],"names":[],"mappings":"AAAA"}"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(source_map_json);
        let data_uri = format!("data:application/json;base64,{}", encoded);

        let wasm = build_wasm_with_custom_section("sourceMappingURL", data_uri.as_bytes());

        let result = extract_source_map_from_wasm(&wasm);
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert!(extracted.contains("\"version\":3"));
    }

    #[test]
    fn test_extract_source_map_no_custom_section() {
        // Minimal valid WASM module with no custom sections
        let wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
        ];

        assert!(extract_source_map_from_wasm(&wasm).is_none());
    }

    #[test]
    fn test_try_build_as_line_cache_no_source_map() {
        let wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
        ];

        assert!(try_build_as_line_cache(&wasm).is_none());
    }

    #[test]
    fn test_try_build_as_line_cache_with_source_map() {
        let json =
            r#"{"version":3,"sources":["assembly/index.ts"],"names":[],"mappings":"AAAA;AACA"}"#;
        let wasm = build_wasm_with_custom_section("sourceMap", json.as_bytes());

        let entries = try_build_as_line_cache(&wasm);
        assert!(entries.is_some());
        let entries = entries.unwrap();
        assert!(!entries.is_empty());
        assert_eq!(entries[0].file, "assembly/index.ts");
    }

    #[test]
    fn test_try_build_as_line_cache_url_not_data_uri() {
        // A plain URL in sourceMappingURL should be skipped (not JSON)
        let wasm =
            build_wasm_with_custom_section("sourceMappingURL", b"https://example.com/source.map");

        assert!(try_build_as_line_cache(&wasm).is_none());
    }

    // ---- Test helpers ----

    /// Build a minimal valid WASM module with a single custom section.
    fn build_wasm_with_custom_section(name: &str, data: &[u8]) -> Vec<u8> {
        let mut wasm = vec![
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version
        ];

        // Custom section (id = 0)
        let name_bytes = name.as_bytes();
        let section_size = leb128_size(name_bytes.len() as u32) + name_bytes.len() + data.len();

        wasm.push(0x00); // section id: custom
        write_leb128(&mut wasm, section_size as u32);
        write_leb128(&mut wasm, name_bytes.len() as u32);
        wasm.extend_from_slice(name_bytes);
        wasm.extend_from_slice(data);

        wasm
    }

    fn leb128_size(mut value: u32) -> usize {
        let mut size = 0;
        loop {
            size += 1;
            value >>= 7;
            if value == 0 {
                break;
            }
        }
        size
    }

    fn write_leb128(buf: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }
}

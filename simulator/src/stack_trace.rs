// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

//! Enhanced WASM stack trace generation.
//!
//! Exposes the Wasmi internal call stack directly on traps,
//! bypassing Soroban Host abstractions for low-level debugging.

use serde::Serialize;

/// A single frame in a WASM call stack.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StackFrame {
    /// Index within the call stack (0 = innermost/trap site).
    pub index: usize,
    /// Function index in the WASM module, if known.
    pub func_index: Option<u32>,
    /// Demangled or raw function name, if available.
    pub func_name: Option<String>,
    /// Byte offset within the WASM module where the trap occurred.
    pub wasm_offset: Option<u64>,
    /// Module name, if the WASM has an embedded name section.
    pub module: Option<String>,
}

/// Categorised trap reason extracted from a raw error string.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum TrapKind {
    OutOfBoundsMemoryAccess,
    OutOfBoundsTableAccess,
    IntegerOverflow,
    IntegerDivisionByZero,
    InvalidConversionToInt,
    Unreachable,
    StackOverflow,
    IndirectCallTypeMismatch,
    UndefinedElement,
    HostError(String),
    Unknown(String),
}

/// Structured stack trace emitted on a WASM trap.
#[derive(Debug, Clone, Serialize)]
pub struct WasmStackTrace {
    /// Categorised trap reason.
    pub trap_kind: TrapKind,
    /// Raw error message from the host/runtime.
    pub raw_message: String,
    /// Ordered call stack frames (index 0 = trap site).
    pub frames: Vec<StackFrame>,
    /// Whether the Host error was unwound through Soroban abstractions.
    pub soroban_wrapped: bool,
}

impl WasmStackTrace {
    /// Build a stack trace by parsing a raw HostError debug representation.
    ///
    /// This extracts trap kind, function names, and offsets from the
    /// stringified error that Wasmi/Soroban produces.
    pub fn from_host_error(error_debug: &str) -> Self {
        let trap_kind = classify_trap(error_debug);
        let frames = extract_frames(error_debug);
        let soroban_wrapped = error_debug.contains("HostError")
            || error_debug.contains("ScError")
            || error_debug.contains("Error(WasmVm");

        WasmStackTrace {
            trap_kind,
            raw_message: error_debug.to_string(),
            frames,
            soroban_wrapped,
        }
    }

    /// Build a trace from a panic payload.
    pub fn from_panic(message: &str) -> Self {
        WasmStackTrace {
            trap_kind: TrapKind::Unknown(message.to_string()),
            raw_message: message.to_string(),
            frames: vec![],
            soroban_wrapped: false,
        }
    }

    /// Format the trace as a human-readable string.
    pub fn display(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("Trap: {}\n", self.trap_kind_label()));

        if self.soroban_wrapped {
            out.push_str("  (error passed through Soroban Host layer)\n");
        }

        if self.frames.is_empty() {
            out.push_str("  <no frames captured>\n");
        } else {
            out.push_str("  Call stack (most recent call last):\n");
            for frame in &self.frames {
                out.push_str(&format!("    #{}: ", frame.index));
                if let Some(ref name) = frame.func_name {
                    out.push_str(name);
                } else if let Some(idx) = frame.func_index {
                    out.push_str(&format!("func[{}]", idx));
                } else {
                    out.push_str("<unknown>");
                }
                if let Some(offset) = frame.wasm_offset {
                    out.push_str(&format!(" @ 0x{:x}", offset));
                }
                if let Some(ref module) = frame.module {
                    out.push_str(&format!(" in {}", module));
                }
                out.push('\n');
            }
        }
        out
    }

    fn trap_kind_label(&self) -> &str {
        match &self.trap_kind {
            TrapKind::OutOfBoundsMemoryAccess => "out of bounds memory access",
            TrapKind::OutOfBoundsTableAccess => "out of bounds table access",
            TrapKind::IntegerOverflow => "integer overflow",
            TrapKind::IntegerDivisionByZero => "integer division by zero",
            TrapKind::InvalidConversionToInt => "invalid conversion to integer",
            TrapKind::Unreachable => "unreachable instruction executed",
            TrapKind::StackOverflow => "stack overflow",
            TrapKind::IndirectCallTypeMismatch => "indirect call type mismatch",
            TrapKind::UndefinedElement => "undefined table element",
            TrapKind::HostError(_) => "host error",
            TrapKind::Unknown(_) => "unknown trap",
        }
    }
}

/// Classify a raw error string into a known trap kind.
fn classify_trap(msg: &str) -> TrapKind {
    let lower = msg.to_lowercase();

    if lower.contains("out of bounds memory") {
        TrapKind::OutOfBoundsMemoryAccess
    } else if lower.contains("out of bounds table") {
        TrapKind::OutOfBoundsTableAccess
    } else if lower.contains("integer overflow") {
        TrapKind::IntegerOverflow
    } else if lower.contains("integer division by zero") || lower.contains("division by zero") {
        TrapKind::IntegerDivisionByZero
    } else if lower.contains("invalid conversion to int") {
        TrapKind::InvalidConversionToInt
    } else if lower.contains("unreachable") {
        TrapKind::Unreachable
    } else if lower.contains("call stack exhausted") || lower.contains("stack overflow") {
        TrapKind::StackOverflow
    } else if lower.contains("indirect call type mismatch") {
        TrapKind::IndirectCallTypeMismatch
    } else if lower.contains("undefined element") || lower.contains("uninitialized element") {
        TrapKind::UndefinedElement
    } else if lower.contains("hosterror") || lower.contains("host error") {
        TrapKind::HostError(msg.to_string())
    } else {
        TrapKind::Unknown(msg.to_string())
    }
}

/// Extract call stack frames from the stringified Wasmi/HostError output.
///
/// Wasmi and Soroban format trap backtraces as lines like:
///   `  0: func[42] @ 0xa3c`
///   `  1: <module_name>::function_name @ 0xb20`
///
/// We parse these into structured `StackFrame` values.
fn extract_frames(error_debug: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();

    for line in error_debug.lines() {
        let trimmed = line.trim();

        // Match patterns like "0: func[42] @ 0xa3c" or "#0 func_name"
        if let Some(frame) = try_parse_numbered_frame(trimmed) {
            frames.push(frame);
            continue;
        }

        // Match Wasmi-style "wasm backtrace:" header followed by frames
        if trimmed.starts_with("func[") || trimmed.starts_with("<") {
            if let Some(frame) = try_parse_bare_frame(trimmed, frames.len()) {
                frames.push(frame);
            }
        }
    }

    frames
}

/// Attempt to parse a frame line with a leading index like "0: func[42] @ 0xa3c".
fn try_parse_numbered_frame(line: &str) -> Option<StackFrame> {
    // Try "N: <rest>" pattern
    let (index_str, rest) = line.split_once(':')?;
    let index: usize = index_str.trim().trim_start_matches('#').parse().ok()?;
    let rest = rest.trim();

    let (func_name, func_index, wasm_offset) = parse_frame_body(rest);

    Some(StackFrame {
        index,
        func_index,
        func_name,
        wasm_offset,
        module: None,
    })
}

/// Attempt to parse a bare frame without a leading index.
fn try_parse_bare_frame(line: &str, index: usize) -> Option<StackFrame> {
    let (func_name, func_index, wasm_offset) = parse_frame_body(line);

    if func_name.is_some() || func_index.is_some() {
        Some(StackFrame {
            index,
            func_index,
            func_name,
            wasm_offset,
            module: None,
        })
    } else {
        None
    }
}

/// Parse the body of a frame line, extracting function name/index and offset.
///
/// Recognised patterns:
///   - `func[42]`
///   - `func[42] @ 0xa3c`
///   - `some_function_name @ 0xb20`
///   - `<module>::path::function`
fn parse_frame_body(body: &str) -> (Option<String>, Option<u32>, Option<u64>) {
    let mut func_name: Option<String> = None;
    let mut func_index: Option<u32> = None;
    let mut wasm_offset: Option<u64> = None;

    // Split on " @ " to separate name from offset
    let (name_part, offset_part) = if let Some(idx) = body.find(" @ ") {
        (&body[..idx], Some(&body[idx + 3..]))
    } else {
        (body, None)
    };

    // Parse offset
    if let Some(off) = offset_part {
        let off = off.trim();
        if let Some(hex) = off.strip_prefix("0x") {
            wasm_offset = u64::from_str_radix(hex, 16).ok();
        } else {
            wasm_offset = off.parse().ok();
        }
    }

    // Parse function name/index
    let name_trimmed = name_part.trim();
    if name_trimmed.starts_with("func[") {
        // func[42]
        if let Some(inner) = name_trimmed.strip_prefix("func[") {
            if let Some(idx_str) = inner.strip_suffix(']') {
                func_index = idx_str.parse().ok();
            }
        }
    } else if !name_trimmed.is_empty() {
        func_name = Some(name_trimmed.to_string());
    }

    (func_name, func_index, wasm_offset)
}

/// Hardcoded lookup for common Soroban SDK panic codes so we can return a
/// human-readable explanation even when DWARF/source maps are unavailable.
const SOROBAN_PANIC_LOOKUP: &[(&str, &str)] = &[
    (
        "Error(WasmVm, MissingValue)",
        "Contract tried to read a ledger/storage entry that does not exist.",
    ),
    (
        "Error(Storage, MissingValue)",
        "Contract tried to read a ledger/storage entry that does not exist.",
    ),
    (
        "Error(WasmVm, ExceededLimit)",
        "Execution exceeded the Soroban VM resource limits (CPU or memory budget).",
    ),
    (
        "Error(Context, InvalidInput)",
        "Invalid input was provided to a host function or SDK call.",
    ),
    (
        "Error(Auth, InvalidAction)",
        "Authorization failed or an auth entry was missing/invalid for this action.",
    ),
    (
        "Error(Auth, InvalidAuth)",
        "Authorization failed or an auth entry was missing/invalid for this action.",
    ),
    (
        "Error(WasmVm, InvalidAction)",
        "A contract call attempted an invalid or disallowed action.",
    ),
];

fn map_soroban_sdk_error(msg: &str) -> Option<&'static str> {
    SOROBAN_PANIC_LOOKUP
        .iter()
        .find(|(needle, _)| msg.contains(needle))
        .map(|(_, expl)| *expl)
}

/// Public helper: decode a raw error string into a human-readable description
/// that includes the trap kind. Used by `main.rs` for backward compatibility.
pub fn decode_error(msg: &str) -> String {
    if let Some(mapped) = map_soroban_sdk_error(msg) {
        return format!("Soroban SDK panic: {}", mapped);
    }

    let trace = WasmStackTrace::from_host_error(msg);
    let label = trace.trap_kind_label();

    if label != "unknown trap" {
        format!("VM Trap: {} -- {}", capitalise_first(label), msg)
    } else {
        format!("Error: {}", msg)
    }
}

fn capitalise_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_oob_memory() {
        let kind = classify_trap("Error: Wasm Trap: out of bounds memory access");
        assert_eq!(kind, TrapKind::OutOfBoundsMemoryAccess);
    }

    #[test]
    fn test_classify_unreachable() {
        let kind = classify_trap("wasm trap: unreachable");
        assert_eq!(kind, TrapKind::Unreachable);
    }

    #[test]
    fn test_classify_stack_overflow() {
        let kind = classify_trap("call stack exhausted");
        assert_eq!(kind, TrapKind::StackOverflow);
    }

    #[test]
    fn test_classify_division_by_zero() {
        let kind = classify_trap("integer division by zero");
        assert_eq!(kind, TrapKind::IntegerDivisionByZero);
    }

    #[test]
    fn test_classify_host_error() {
        let kind = classify_trap("HostError: contract call failed");
        assert!(matches!(kind, TrapKind::HostError(_)));
    }

    #[test]
    fn test_decode_error_known_trap() {
        let msg = decode_error("Error: Wasm Trap: out of bounds memory access");
        assert!(msg.contains("VM Trap: Out of bounds memory access"));
    }

    #[test]
    fn test_decode_error_unknown() {
        let msg = decode_error("some random error");
        assert_eq!(msg, "Error: some random error");
    }

    #[test]
    fn test_extract_frames() {
        let err = "wasm trap: unreachable\n  0: func[0] @ 0x3\n  1: func[1] @ 0x4";
        let frames = extract_frames(err);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].func_index, Some(0));
        assert_eq!(frames[1].func_index, Some(1));
    }

    #[test]
    fn test_soroban_panic_lookup_missing_value() {
        let msg = "HostError: Error(WasmVm, MissingValue)";
        let decoded = decode_error(msg);
        assert!(decoded.contains("Soroban SDK panic"));
        assert!(decoded.contains("storage entry"));
    }

    #[test]
    fn test_soroban_panic_lookup_invalid_input() {
        let msg = "Error(Context, InvalidInput)";
        let decoded = decode_error(msg);
        assert!(decoded.contains("Invalid input"));
    }
}

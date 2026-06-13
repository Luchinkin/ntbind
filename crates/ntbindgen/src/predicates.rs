//! Name predicates.
//!
//! Centralizes "is this PDB name something we strip / treat as anonymous?"
//! so each check has exactly one definition.

// Field names stripped from struct fieldlists entirely.
//
// The C++ predicate accepts any of the prefixes followed by trailing chars
// from `[0-9a-b]` -- so `Reserved1`, `SpareBytes2a`, `Padding42b` all match.
// We replicate that with a single helper.
#[must_use]
pub fn is_reserved_field(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "Reserved",
        "reserved",
        "ReservedBits",
        "ReservedFlags",
        "ReservedPad",
        "Fill",
        "Padding",
        "Pad",
        "pUnused",
        "Unused",
        "unused",
        "__unusedAlignment",
        "UnusedPad",
        "Spare",
        "spare",
        "SpareBit",
        "SpareBits",
        "SpareByte",
        "SpareBytes",
        "SpareShort",
        "SpareShorts",
        "SpareUSHORT",
        "SpareUSHORTS",
        "SpareLong",
        "SpareLongs",
        "SpareULONG",
        "SpareULONGS",
        "SparePtr",
        "SparePointer",
        "SparePointers",
        "SpareSameTebBits",
        "PrcbPad",
        "PlaceholderReserved",
    ];
    for &p in PREFIXES {
        if !name.starts_with(p) {
            continue;
        }
        let tail = &name[p.len()..];
        // Empty tail OR trailing chars from `[0-9ab]` -- matches the C++
        // `is_reserved_field` numeric-suffix rule. `c..z` would also be
        // valid C names so we keep the tail explicitly restricted.
        if tail.bytes().all(|b| b.is_ascii_digit() || b == b'a' || b == b'b') {
            return true;
        }
    }
    false
}

// PDB-given anonymous tag detector. Matches the names Microsoft's compiler
// emits for unnamed structs/unions/enums.
#[must_use]
pub fn is_anonymous_type(name: &str) -> bool {
    let n = name.trim_start_matches('_');
    name.is_empty()
        || n.starts_with("unnamed")
        || name.starts_with("<unnamed-")
        || name.starts_with("<anonymous-")
        || name.starts_with("__unnamed")
        || n == "u" // `_u` special-case
}

// Legacy anonymous union/struct names (`s`, `u`, `e`, `s0..s9`,
// `u0..u9`, `e0..e9`); clear them so the parent's emission inlines the
// union body.
#[must_use]
#[allow(dead_code)] // reserved for future nested-aggregate flattening
pub fn is_legacy_anonymous_variable(name: &str) -> bool {
    if name.len() > 2 {
        return false;
    }
    let mut bytes = name.bytes();
    let first = match bytes.next() {
        Some(b) => b,
        None => return false,
    };
    if !matches!(first, b's' | b'u' | b'e') {
        return false;
    }
    match bytes.next() {
        None => true,
        Some(b) if b.is_ascii_digit() => bytes.next().is_none(),
        _ => false,
    }
}

// Strips common import-decoration prefixes (`__imp_`, etc.).
#[must_use]
pub fn strip_import_decoration(name: &str) -> &str {
    for p in ["__imp_", "_imp_", "imp__", "imp_"] {
        if let Some(rest) = name.strip_prefix(p) {
            return rest;
        }
    }
    name
}

// MIDL fragment types/publics are dropped.
#[must_use]
pub fn is_midl_frag(name: &str) -> bool {
    name.starts_with("__midl_frag")
}

// Public-name validity gate.
//
// Acceptance criteria for publics:
// 1. `is_valid_c_name(name)` -- the plain identifier path.
// 2. `??0` / `??1` (ctor/dtor) mangling where the bare class name is C-valid.
// 3. `@`-separated `Class@@Member` paths whose components are each
//    valid C names of length > 1.
//
// We emit the public after demangling via `demangle_simple_cxx` so the
// generated Rust name is something the compiler can accept.
#[must_use]
pub fn is_acceptable_public_name(name: &str) -> bool {
    if is_valid_c_name(name) {
        return true;
    }
    if let Some(rest) = name.strip_prefix("??0").or_else(|| name.strip_prefix("??1")) {
        // `??0Foo@@...`: take up to the first `@`.
        let bare = rest.split('@').next().unwrap_or("");
        return is_valid_c_name(bare);
    }
    if name.contains('@') && !name.contains("__") {
        return name
            .split('@')
            .filter(|s| !s.is_empty())
            .all(|s| s.len() > 1 && is_valid_c_name(s));
    }
    false
}

// Strict C identifier check: starts with letter or `_`, otherwise all
// chars are alphanumeric or `_`. Empty string is NOT a valid name.
#[must_use]
pub fn is_valid_c_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// Reduces a C++ public name to a plain identifier we can shove into Rust:
// - `??0Class@@QEAA...` -> `Class`
// - `??1Class@@QEAA...` -> `Class_dtor`
// - `Class@@Member@@...` -> `Class_Member`
// - Plain C names pass through untouched.
//
// Simple demangler that only needs a name that snake-cases cleanly and
// stays unique within its symbol set.
#[must_use]
pub fn demangle_simple_cxx(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("??0") {
        let bare = rest.split('@').next().unwrap_or("");
        return bare.to_owned();
    }
    if let Some(rest) = name.strip_prefix("??1") {
        let bare = rest.split('@').next().unwrap_or("");
        return format!("{bare}_dtor");
    }
    if name.contains('@') && !name.contains("__") {
        let parts: Vec<&str> = name
            .split('@')
            .filter(|s| !s.is_empty() && s.len() > 1 && is_valid_c_name(s))
            .collect();
        if !parts.is_empty() {
            return parts.join("_");
        }
    }
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_field_predicate() {
        assert!(is_reserved_field("Reserved"));
        assert!(is_reserved_field("Reserved1"));
        assert!(is_reserved_field("Reserved42a"));
        assert!(is_reserved_field("SpareBytes12"));
        assert!(is_reserved_field("Padding"));
        assert!(is_reserved_field("PrcbPad12"));
        assert!(!is_reserved_field("ReservedThing")); // tail has non-digit-non-ab
        assert!(!is_reserved_field("Version"));
        assert!(!is_reserved_field("Notes"));
    }

    #[test]
    fn anonymous_type_predicate() {
        assert!(is_anonymous_type("__unnamed1234"));
        assert!(is_anonymous_type("<unnamed-tag>"));
        assert!(is_anonymous_type("<anonymous-12345>"));
        assert!(is_anonymous_type("_u"));
        assert!(is_anonymous_type(""));
        assert!(!is_anonymous_type("_KI_FOO"));
    }

    #[test]
    fn legacy_anon_variable_predicate() {
        for n in ["s", "u", "e", "s0", "u9", "e3"] {
            assert!(is_legacy_anonymous_variable(n), "{n}");
        }
        for n in ["s10", "us", "User", "Sx"] {
            assert!(!is_legacy_anonymous_variable(n), "{n}");
        }
    }

    #[test]
    fn import_decoration_stripped() {
        assert_eq!(strip_import_decoration("__imp_NtCreateFile"), "NtCreateFile");
        assert_eq!(strip_import_decoration("_imp_KeWait"), "KeWait");
        assert_eq!(strip_import_decoration("imp__Foo"), "Foo");
        assert_eq!(strip_import_decoration("imp_Bar"), "Bar");
        assert_eq!(strip_import_decoration("Plain"), "Plain");
    }

    #[test]
    fn midl_frag_detected() {
        assert!(is_midl_frag("__midl_frag1234"));
        assert!(!is_midl_frag("FooBar"));
    }
}

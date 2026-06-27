//! Name transforms from PDB identifiers to Rust paths.
//!
//! Maps a PDB type like `_KI_KUSER_SHARED_DATA` into the symbol
//! `ki::kuser_shared_data` with a Rust-friendly snake_case + `_t` suffix.

use std::fmt;

use crate::config::NAMESPACE_PREFIXES;

// Where a generated item lives in the SDK crate.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RustPath {
    // `::`-separated module path, e.g. `"ki"` or `"dxgk::arg"`.
    pub ns: String,
    // Type/value name, e.g. `"kuser_shared_data_t"`.
    pub name: String,
}

impl fmt::Display for RustPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.ns, self.name)
    }
}

// Standalone kernel-global types shared across many PDBs without a
// distinguishing prefix.  Without this fast-path the prefix loop fails
// to match a 3-letter name like `MDL` and the caller routes `_MDL`
// into per-PDB namespaces (`ndis::mdl_t`, `wdf::mdl_t`, ...), one copy
// per load.
//
// `_UNICODE_STRING`, `_STRING`, `_LIST_ENTRY`, `_LARGE_INTEGER` and
// friends are handled earlier by `pdb_io::substitute_native_type`;
// only list TYPES here that the runtime builtins do NOT cover.
const KERNEL_GLOBAL_TYPES: &[&str] = &[
    "mdl",
    "luid",
    "luid_and_attributes",
    "object_attributes",
    "client_id",
    // `_GUID` appears in many PDBs (ntkrnlmp, combase, wdf, ...).
    // Force it into `nt::` so cross-bucket dedup collapses all
    // definitions to a single `nt::guid_t`.
    "guid",
    // `_DEVICE_POWER_STATE` is the kernel-canonical enum but ndis.pdb
    // also defines its own copy; force `nt::` so ndis-side fields
    // share the canonical type.
    "device_power_state",
];

// User-mode globals routed into the `win::` namespace.  `_PEB` is
// pinned here so it stays out of `nt::` and won't collide with
// downstream `nt::peb_t` aliases.
const USER_GLOBAL_TYPES: &[&str] = &["peb"];

// Applies the namespace transform to `pdb_name`. Returns `None` if the
// name doesn't match any prefix recipe -- callers fall back to
// `default_ns + snake_case(pdb_name) + "_t"`.
#[must_use]
pub fn classify(pdb_name: &str) -> Option<RustPath> {
    // PDB tag names start with `_` (e.g. `_KI_FOO`). Strip it for matching.
    let stripped = pdb_name.strip_prefix('_').unwrap_or(pdb_name);
    let lower = stripped.to_ascii_lowercase();

    if KERNEL_GLOBAL_TYPES.contains(&lower.as_str()) {
        return Some(RustPath { ns: "nt".to_owned(), name: format!("{lower}_t") });
    }
    if USER_GLOBAL_TYPES.contains(&lower.as_str()) {
        return Some(RustPath { ns: "win".to_owned(), name: format!("{lower}_t") });
    }

    for (prefix, ns) in NAMESPACE_PREFIXES {
        if !lower.starts_with(prefix) {
            continue;
        }
        // Require at least two more characters after the prefix.
        if lower.len() <= prefix.len() + 1 {
            continue;
        }
        let rest = &lower[prefix.len()..];
        let (sub_ns, body) = match strip_sub_prefix(rest) {
            Some(t) => t,
            None => continue,
        };

        let mut body = body.to_owned();
        if KEYWORDS.contains(&body.as_str()) {
            body.push('_');
        }
        // Names that would start with a digit get a leading `_`.
        if body.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            body.insert(0, '_');
        }
        let mut ns = if sub_ns.is_empty() { (*ns).to_owned() } else { format!("{ns}::{sub_ns}") };
        // `exp::` -> `expi::` rename so generated namespace paths match
        // the wire-format identifier scheme.
        if ns == "exp" || ns.starts_with("exp::") {
            ns.insert(3, 'i');
        }
        return Some(RustPath { ns, name: format!("{body}_t") });
    }

    None
}

// Publics-side analogue of `classify()`: input is already snake_case +
// lowercased; returns `(ns, body)` with no `_t` suffix.  `None` when
// no prefix matches.  Used by the emit path to split per-PDB publics
// into per-namespace `api.hpp` files.
#[must_use]
pub fn classify_for_public(snake_name: &str) -> Option<(String, String)> {
    for (prefix, ns) in NAMESPACE_PREFIXES {
        if !snake_name.starts_with(prefix) {
            continue;
        }
        if snake_name.len() <= prefix.len() + 1 {
            continue;
        }
        let rest = &snake_name[prefix.len()..];
        let (sub_ns, body) = match strip_sub_prefix(rest) {
            Some(t) => t,
            None => continue,
        };

        let mut body = body.to_owned();
        if KEYWORDS.contains(&body.as_str()) {
            body.push('_');
        }
        if body.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            body.insert(0, '_');
        }
        let mut ns = if sub_ns.is_empty() { (*ns).to_owned() } else { format!("{ns}::{sub_ns}") };
        if ns == "exp" || ns.starts_with("exp::") {
            ns.insert(3, 'i');
        }
        return Some((ns, body));
    }
    None
}

// Secondary-prefix dispatch -- `_NAME` (the canonical case) versus
// `pf_NAME`, `px_NAME`, etc. that nest one level deeper.
//
fn strip_sub_prefix(rest: &str) -> Option<(&'static str, &str)> {
    if let Some(body) = rest.strip_prefix('_') {
        return Some(("", body));
    }
    const SUB: &[(&str, &str)] = &[
        ("pf_", "pf"),
        ("px_", "px"),
        ("vx_", "vx"),
        ("ix_", "ix"),
        ("vp_", "vp"),
        ("vf_", "vf"),
        ("vi_", "vi"),
        ("vz_", "vz"),
        ("p_", "p"),
        ("v_", "v"),
        ("i_", "i"),
        ("x_", "x"),
        ("z_", "z"),
    ];
    for (pat, ns) in SUB {
        if let Some(body) = rest.strip_prefix(pat) {
            return Some((*ns, body));
        }
    }
    None
}

// Default namespace bucket when `classify` returns `None`.
//
// Applies snake-case conversion (PDB names like `FooBar` -> `foo_bar`) and
// appends the `_t` suffix expected by the rest of the SDK.
#[must_use]
pub fn fallback_path(default_ns: &str, pdb_name: &str) -> RustPath {
    let stripped = pdb_name.trim_start_matches('_');
    let snake = to_snake_case(stripped);
    let body = if snake.is_empty() {
        "anonymous".to_owned()
    } else if KEYWORDS.contains(&snake.as_str()) {
        format!("{snake}_")
    } else if snake.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{snake}")
    } else {
        snake
    };
    RustPath { ns: default_ns.to_owned(), name: format!("{body}_t") }
}

// Snake-cases a PDB identifier. PDB tag names already arrive as
// underscore-separated UPPER (`_KI_FOO_BAR`) and just need lowercasing;
// CamelCase names (`MmFooBar`) get inflected boundaries (`mm_foo_bar`).
#[must_use]
pub fn to_snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'_' {
            // collapse runs but preserve as separator
            if !out.ends_with('_') {
                out.push('_');
            }
            continue;
        }
        let ch = b as char;
        if ch.is_ascii_uppercase() {
            let prev = bytes.get(i.wrapping_sub(1)).copied();
            let next = bytes.get(i + 1).copied();
            let prev_lower = prev.is_some_and(|p| (p as char).is_ascii_lowercase());
            let next_lower = next.is_some_and(|n| (n as char).is_ascii_lowercase());
            // FooBar -> foo_bar; ABc -> a_bc; ABBR -> abbr
            if i != 0 && !out.ends_with('_') && (prev_lower || (prev.is_some() && next_lower)) {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    // Trim trailing underscore artifacts.
    while out.ends_with('_') {
        out.pop();
    }
    out
}

// Strict Rust reserved-word list; used to escape generated identifiers by
// appending `_`.
//
const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "union", "raw",
];

// Appends a trailing `_` if `s` would shadow a Rust keyword. Generated
// identifiers -- fields, variants, function names -- pipe through this
// before they're emitted.
#[must_use]
pub fn escape_keyword(s: &str) -> std::borrow::Cow<'_, str> {
    if KEYWORDS.contains(&s) {
        std::borrow::Cow::Owned(format!("{s}_"))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

// Computes the longest common prefix length to strip from a set of enum
// variant names:
//
// - the prefix must end at a `_` boundary or a CamelCase->lowercase
//   transition (`Ab` -> keep `A`),
// - the remaining suffix on every variant must still be a valid C
//   identifier (i.e. start with a letter or `_`, not a digit).
//
// Returns `0` (no stripping) when only a single variant is present or no
// suffix is valid.
#[must_use]
pub fn common_variant_prefix_len(names: &[&str]) -> usize {
    if names.len() < 2 {
        return 0;
    }

    fn trim_boundary(p: &str) -> &str {
        let mut bytes = p.as_bytes();
        loop {
            match bytes {
                [] => break,
                [.., b'_'] => break,
                // `aB` transition (lowercase followed by uppercase) -- the
                // uppercase byte opens the next CamelCase token. Drop *it*
                // and stop; the prefix keeps the lowercase tail so the next
                // variant's first char (also uppercase) survives.
                [.., a, b] if a.is_ascii_lowercase() && b.is_ascii_uppercase() => {
                    bytes = &bytes[..bytes.len() - 1];
                    break;
                },
                _ => bytes = &bytes[..bytes.len() - 1],
            }
        }
        // SAFETY: we only sliced at ASCII byte boundaries.
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }

    fn valid_suffix(s: &str) -> bool {
        !s.is_empty() && s.chars().next().is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
    }

    let mut prefix: &str = names[0];
    prefix = trim_boundary(prefix);
    for &n in &names[1..] {
        if prefix.len() > n.len() {
            prefix = trim_boundary(&prefix[..n.len()]);
        }
        while !prefix.is_empty() && (!n.starts_with(prefix) || !valid_suffix(&n[prefix.len()..])) {
            prefix = trim_boundary(&prefix[..prefix.len() - 1]);
        }
    }
    prefix.len()
}

// SDBM hash.  Used as the per-entry XOR-LCG key.
#[must_use]
pub fn sdbm_hash(s: &str) -> u64 {
    let mut h: u64 = 0;
    for &b in s.as_bytes() {
        h = (b as u64)
            .wrapping_add(h.wrapping_shl(6))
            .wrapping_add(h.wrapping_shl(16))
            .wrapping_sub(h);
    }
    // Make sure we never hand back 0 -- that would defeat the cipher and
    // looks like an "uninitialized" marker downstream.
    if h == 0 { 0xa79d_ebf4_9fdb_6a93 } else { h }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_prefix() {
        let p = classify("_KI_KUSER_SHARED_DATA").unwrap();
        assert_eq!(p.ns, "ki");
        assert_eq!(p.name, "kuser_shared_data_t");
    }

    #[test]
    fn classify_dxgk_arg() {
        let p = classify("_DXGKARG_PRESENT").unwrap();
        assert_eq!(p.ns, "dxgk::arg");
        assert_eq!(p.name, "present_t");
    }

    #[test]
    fn classify_falls_back() {
        assert!(classify("_FOO_BAR_BAZ").is_none());
        let p = fallback_path("misc", "_FOO_BAR_BAZ");
        assert_eq!(p.ns, "misc");
        assert_eq!(p.name, "foo_bar_baz_t");
    }

    #[test]
    fn keyword_escaping() {
        let p = fallback_path("misc", "type");
        assert_eq!(p.name, "type__t"); // "type" -> "type_" via keyword escape, then "_t" suffix
    }

    #[test]
    fn snake_case_camel() {
        assert_eq!(to_snake_case("FooBarBaz"), "foo_bar_baz");
        assert_eq!(to_snake_case("MmFoo"), "mm_foo");
        assert_eq!(to_snake_case("ALLCAPS"), "allcaps");
        assert_eq!(to_snake_case("already_snake"), "already_snake");
    }

    #[test]
    fn sdbm_is_nonzero() {
        assert_ne!(sdbm_hash("_BOOT_OPTIONS.Version"), 0);
    }

    #[test]
    fn enum_prefix_strips_at_underscore_and_camel_boundaries() {
        // Underscore boundary.
        let names = ["BOOT_NONE", "BOOT_SEED", "BOOT_EXT"];
        let n = common_variant_prefix_len(&names);
        assert_eq!(n, 5, "BOOT_ prefix should strip");
        assert_eq!(&names[0][n..], "NONE");

        // CamelCase boundary.
        let names = ["BootEntropySourceNone", "BootEntropySourceSeed"];
        let n = common_variant_prefix_len(&names);
        let trimmed = &names[0][n..];
        // Must still be a valid C name (start with a letter).
        assert!(trimmed.starts_with(|c: char| c.is_ascii_alphabetic()));
        assert!(trimmed.contains("None"));
    }

    #[test]
    fn enum_prefix_zero_for_disjoint_names() {
        let names = ["BootFoo", "MaxValues"];
        assert_eq!(common_variant_prefix_len(&names), 0);
    }

    #[test]
    fn enum_prefix_zero_for_single_variant() {
        let names = ["JustOne"];
        assert_eq!(common_variant_prefix_len(&names), 0);
    }
}

//! Code emission. Lowers a merged IR namespace into target-language source.
//!
//! Each target backend (`rust`, `cpp`) is responsible for writing per-type
//! files plus whatever crate / build-tree scaffolding is appropriate for
//! that ecosystem. The dispatch layer here just routes by [`Target`].

pub mod common;
pub mod cpp;
pub mod rust;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::ir::TypeDecl;
use crate::merge::MergedNamespace;

// Outputs target -- selects which backend(s) write source files for a given
// namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Rust,
    Cpp,
}

// Generation knobs forwarded from CLI.
#[derive(Clone, Copy, Debug)]
pub struct EmitOptions {
    // Emits per-namespace publics aggregator (`api.rs` / `api.hpp`). Skipped
    // during iteration on type lowering -- the public file can hit tens of
    // MB on `ntkrnlmp.pdb`.
    pub publics: bool,
    // When `true`, every cell is shipped plaintext (no XOR-LCG): the
    // generator emits `key = 0` for every header and the runtime /
    // patcher both fall through `encode_decode`'s short-circuit.
    pub no_encrypt: bool,
}

// Drives emission for one merged namespace, dispatching to the requested
// backend.
pub fn write_unit(
    ns: &MergedNamespace,
    out_root: &Path,
    opts: EmitOptions,
    target: Target,
) -> Result<()> {
    match target {
        Target::Rust => rust::write_unit(ns, out_root, opts),
        Target::Cpp => cpp::write_unit(ns, out_root, opts),
    }
}

// Write the exact source-image owner for every emitted offset identifier.
// The generated namespace is not sufficient provenance when several PDBs
// share one namespace (for example ntkrnlmp.pdb and hal.pdb). The auth-server
// consumes this sidecar as `OffsetOwnerManifest`.
pub fn write_offset_owner_manifest(out_root: &Path, namespaces: &[MergedNamespace]) -> Result<()> {
    // The server normalizes identifiers case-insensitively. Keep the
    // generated key space canonical here as well so duplicate CodeView names
    // that differ only in case are merged instead of emitted as collisions.
    let mut owners: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for ns in namespaces {
        for ty in &ns.types {
            let (original_name, owner_image, fields) = match ty {
                TypeDecl::Struct(s) | TypeDecl::Union(s) => {
                    (&s.original_name, s.owner_image, &s.fields)
                },
                TypeDecl::Enum(_) | TypeDecl::Stub(_) => continue,
            };
            owners
                .entry(original_name.to_ascii_lowercase() + ".$")
                .or_default()
                .insert(owner_image);
            for field in fields {
                owners
                    .entry(field.identifier.to_ascii_lowercase())
                    .or_default()
                    .insert(owner_image);
            }
        }
    }

    let mut json = String::from("{\n");
    for (index, (identifier, images)) in owners.iter().enumerate() {
        if index != 0 {
            json.push_str(",\n");
        }
        json.push_str("  ");
        json.push_str(&json_quote(identifier));
        json.push_str(": [");
        for (image_index, image) in images.iter().enumerate() {
            if image_index != 0 {
                json.push_str(", ");
            }
            json.push_str(&json_quote(image));
        }
        json.push(']');
    }
    json.push_str("\n}\n");
    fs::write(out_root.join("offset-owner-manifest.json"), json)?;
    Ok(())
}

fn json_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            },
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

// Crate-/tree-level finalization (lib.rs + Cargo.toml for Rust; nothing
// for C++ since each `.hpp` is standalone). Run once after every namespace
// has been written.
pub fn finalize(
    out_root: &Path,
    namespaces: &[MergedNamespace],
    opts: EmitOptions,
    target: Target,
) -> Result<()> {
    match target {
        Target::Rust => rust::finalize_crate(out_root, namespaces),
        Target::Cpp => cpp::finalize_tree(out_root, namespaces, opts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{FieldDecl, StructDecl, TypeRef};
    use crate::name::RustPath;

    #[test]
    fn owner_manifest_emits_type_and_field_sources() {
        let root =
            std::env::temp_dir().join(format!("ntbindgen-owner-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let field = FieldDecl {
            original_name: "NextFilter".to_owned(),
            rust_name: "next_filter".to_owned(),
            identifier: "_NDIS_FILTER_BLOCK.NextFilter".to_owned(),
            ty: TypeRef::Primitive("u64"),
            bit_offset: 64,
            bit_size: 64,
            key: 0,
            bitfield: None,
            per_build: Vec::new(),
        };
        let ns = MergedNamespace {
            default_ns: "ndis",
            hint_image: "ndis.sys",
            types: vec![TypeDecl::Struct(StructDecl {
                original_name: "_NDIS_FILTER_BLOCK".to_owned(),
                path: RustPath { ns: "ndis".to_owned(), name: "filter_block_t".to_owned() },
                owner_image: "ndis.sys",
                size: 0x100,
                fields: vec![field],
                summary_key: 0,
            })],
            publics: Vec::new(),
        };

        write_offset_owner_manifest(&root, &[ns]).unwrap();
        let json = std::fs::read_to_string(root.join("offset-owner-manifest.json")).unwrap();
        assert!(json.contains("\"_ndis_filter_block.$\": [\"ndis.sys\"]"));
        assert!(json.contains("\"_ndis_filter_block.nextfilter\": [\"ndis.sys\"]"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

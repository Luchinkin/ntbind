//! Code emission. Lowers a merged IR namespace into target-language source.
//!
//! Each target backend (`rust`, `cpp`) is responsible for writing per-type
//! files plus whatever crate / build-tree scaffolding is appropriate for
//! that ecosystem. The dispatch layer here just routes by [`Target`].

pub mod common;
pub mod cpp;
pub mod rust;

use std::path::Path;

use anyhow::Result;

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

// Crate-/tree-level finalization (lib.rs + Cargo.toml for Rust; nothing
// for C++ since each `.hpp` is standalone). Run once after every namespace
// has been written.
pub fn finalize(out_root: &Path, namespaces: &[MergedNamespace], target: Target) -> Result<()> {
    match target {
        Target::Rust => rust::finalize_crate(out_root, namespaces),
        Target::Cpp => cpp::finalize_tree(out_root, namespaces),
    }
}

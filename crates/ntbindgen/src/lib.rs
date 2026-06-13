//! ntbindgen library -- exposes the IR, emit, merge, and PDB-loading primitives
//! that the CLI binary drives.
//!
//! Crates that want to embed the generator (e.g. tests that build small
//! synthetic IRs and assert the emitted Rust/C++ shape) should depend on
//! this lib target.

pub mod config;
pub mod emit;
pub mod ir;
pub mod merge;
pub mod name;
pub mod pdb_io;
pub mod predicates;

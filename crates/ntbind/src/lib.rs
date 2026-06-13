//! Runtime support for ntbind-generated code: the [`symtbl`] wire format,
//! XOR-LCG cipher, declarative macros that emit symbol-table entries plus
//! inline accessors, and the [`opaque::Opaque<N>`] storage backing
//! generated types. The companion `ntbind-patch` crate fixes up entries
//! post-link against a target build.

#![cfg_attr(not(test), no_std)]
pub mod crypto;
pub mod error;
pub mod nt;
pub mod opaque;
pub mod public;
pub mod symtbl;

#[doc(hidden)]
pub mod __macro_support;

mod macros;

/// Marker preserved alongside generator output so the patcher and SDK can
/// reject mismatched ABI versions.
pub const ABI_VERSION: u32 = 1;

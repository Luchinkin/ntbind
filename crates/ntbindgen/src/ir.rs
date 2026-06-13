//! Intermediate representation produced by `pdb_io` and consumed by `emit`.
//!
//! Keeps emitter and PDB-reader concerns separate so future cross-build
//! merging (gathering multiple Windows versions into a single IR before
//! emit) drops in cleanly.

use crate::name::RustPath;

// One PDB unit's worth of generated symbols.
pub struct Unit {
    pub default_ns: &'static str,
    pub hint_image: &'static str,
    pub types: Vec<TypeDecl>,
    pub publics: Vec<PublicDecl>,
}

pub enum TypeDecl {
    Struct(StructDecl),
    Enum(EnumDecl),
    Union(StructDecl),
    // Opaque-pointee declaration -- a minimal name binding emitted to keep
    // `*mut crate::ns::Camel` references resolvable when the kernel never
    // exposes a full TPI definition for the pointee. Carries no fields,
    // no `.symtbl` entries, no `SDK_VERIFY` -- just the type name.
    Stub(StubDecl),
}

pub struct StubDecl {
    // PDB-original name (best-effort -- for orphans we synthesize one from
    // the pointee path itself).
    pub original_name: String,
    // Where the stub lives in the generated tree.
    pub path: RustPath,
    // C++-side declaration keyword (`struct`/`union`/`enum class`).
    // Drives the forward-decl form.
    pub kind: PointeeKind,
}

// C++-side keyword for a forward-declared pointer pointee. Drives both
// `struct ns::foo*` rendering and `namespace ns { struct foo; }` forward
// decl emission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PointeeKind {
    Struct,
    Union,
    Enum,
}

pub struct StructDecl {
    // PDB-original name, e.g. `_KI_FOO`.
    pub original_name: String,
    // Where the type lives in the generated tree.
    pub path: RustPath,
    // Byte size from the PDB.
    pub size: u64,
    pub fields: Vec<FieldDecl>,
    // Wire-format key for the struct-summary cell (`<Parent>.$`).
    // Computed at load time; the no-encrypt pipeline zeroes it out
    // alongside every field/public key.
    pub summary_key: u64,
}

pub struct FieldDecl {
    // PDB-original local name of the field, e.g. `Version`.
    pub original_name: String,
    // Generated Rust accessor name, e.g. `version`.
    pub rust_name: String,
    // Canonical identifier -- `<Parent>.<...>.<Field>` (dots
    // preserved across anonymous-nested levels). Wire-format consumers
    // (patcher, symbol-table walker) match on this string verbatim.
    pub identifier: String,
    pub ty: TypeRef,
    pub bit_offset: u32,
    pub bit_size: u16,
    pub key: u64,
    // Bitfield metadata when the field is a packed sub-word. `None` means
    // the field is byte-aligned and emits a regular `field!` accessor.
    pub bitfield: Option<BitfieldInfo>,
    // Per-build observation list, populated by the cross-build merger.
    // Empty when the field was lowered from a single build. Each entry
    // records `(build_name, byte_offset)` -- `byte_offset` is the field's
    // location in that build, `u32::MAX` when absent.
    pub per_build: Vec<(String, u32)>,
}

// Runtime parameters for the bit-field accessor: storage word size and
// signedness of the underlying integer.
#[derive(Clone, Copy, Debug)]
pub struct BitfieldInfo {
    // Backing integer size in bytes -- 1/2/4/8.
    pub storage_bytes: u8,
    // Sign-extend on read?
    pub signed: bool,
}

pub struct EnumDecl {
    pub original_name: String,
    pub path: RustPath,
    pub underlying: TypeRef,
    pub variants: Vec<EnumVariant>,
}

pub struct EnumVariant {
    pub original_name: String,
    pub rust_name: String,
    pub value: i128,
}

// One exported / addressable symbol.
//
// `signature` is filled when the PDB's IPI stream carried an
// `LF_FUNC_ID` for this name pointing at an `LF_PROCEDURE` we managed
// to lower; that's the case Selene-style typed call-sites unlock.
// When the IPI didn't carry function-type info (most data exports,
// some compiler-generated thunks) it stays `None` and the emitter
// falls back to the legacy untyped `Public<c_void>` / `sdk::unknown_ptr`
// form.
pub struct PublicDecl {
    pub original_name: String,
    pub rust_name: String,
    pub rva: u32,
    pub key: u64,
    pub signature: Option<FnSig>,
}

// Calling convention recovered from a PDB `LF_PROCEDURE` record.  We
// only emit `extern "system"` today because every x64 Windows public
// (kernel- and user-mode) uses the Microsoft x64 ABI; the enum is here
// so adding 32-bit / ARM64 support later doesn't churn callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallConv {
    System,
}

// A function signature recovered from `LF_PROCEDURE` + `LF_ARGLIST`.
//
// `variadic` is set when the PDB's argument list ended in a `NoType`
// sentinel (the CodeView encoding of trailing `...`).  Variadic
// signatures CANNOT be lowered to a usable Rust function-pointer type
// today (Rust has no stable variadic-FFI declaration syntax), so the
// Rust emitter falls back to `Public<c_void>` when this is `true`; the
// C++ emitter emits a properly variadic `sdk::function<R(args..., ...)>`.
#[derive(Clone, Debug)]
pub struct FnSig {
    pub return_type: TypeRef,
    pub params: Vec<TypeRef>,
    pub variadic: bool,
    pub calling_conv: CallConv,
}

// A reference to another type from a field or enum-underlying slot. Kept
// simple -- anything we can't model precisely is reduced to opaque storage.
#[derive(Clone, Debug)]
pub enum TypeRef {
    // Maps directly to a Rust primitive -- e.g. `u32`, `*mut c_void`, `i64`.
    Primitive(&'static str),
    // Pointer to an unknown / opaque pointee. Renders as `*mut c_void`
    // (Rust) / `void*` (C++) -- no forward decl needed.
    Pointer,
    // Pointer whose pointee is one of our generated types. Carries the
    // pointee's `RustPath` + its declaration keyword so the C++ emitter
    // can render `<kw> ns::name*` and a matching forward declaration; Rust
    // renders this as `*mut crate::<ns>::<CamelName>` (kind irrelevant).
    TypedPointer {
        path: RustPath,
        kind: PointeeKind,
    },
    // Resolves to a generated type by its `RustPath`.
    UserDefined(RustPath),
    // Externally defined type path. Used to substitute PDB-native types
    // for hand-curated wrappers -- Rust references `crates/ntbind/src/nt.rs`,
    // C++ references `sdkgen::nt::*` from the vendored support library.
    External {
        // Absolute Rust path, e.g. `::ntbind::nt::ListEntryT`.
        rust_path: &'static str,
        // Absolute C++ path, e.g. `nt::list_entry_t`.
        cpp_path: &'static str,
        // Byte size, so we can compute `bit_size` for the wire entry.
        byte_size: u64,
    },
    // Element type + element count. Element count = total_bytes / elem_size
    // pre-computed by the IR builder so the emitter doesn't have to.
    Array {
        element: Box<TypeRef>,
        count: usize,
    },
    // Anything we can't model -- emitted as `[u8; SIZE]`.
    Opaque(u64),
    // Pointer to a non-user-defined pointee.  Closes the Selene-parity
    // gap where primitive pointees (`wchar_t*`, `uint32_t*`), pointer-
    // to-pointer (`void**`), and any other non-Class/Union/Enum target
    // used to collapse to an untyped `*mut c_void`.  Pointers to user-
    // defined types still use [`TypeRef::TypedPointer`] so the orphan-
    // stub injector keeps its `PointeeKind` hint without an extra lookup.
    Ref(Box<TypeRef>),
    // Function-pointer type recovered from `LF_POINTER -> LF_PROCEDURE`.
    // Renders as `unsafe extern "system" fn(...) -> ret` (Rust) and
    // `sdk::function<R(args...)>*` (C++) -- the C++ form bakes the
    // pointer in, the Rust form doesn't need an outer `*mut`.
    FnPtr(Box<FnSig>),
}

//! Unit tests for the Rust emit pipeline. Each test builds a small
//! synthetic `MergedNamespace`, runs `emit::write_unit` into a tempdir,
//! then reads the resulting source files and asserts they contain the
//! expected fragments. We're testing emit shape, not PDB ingestion.

use std::path::{Path, PathBuf};

use ntbindgen::emit::{self, EmitOptions, Target};
use ntbindgen::ir::{
    CallConv, EnumDecl, EnumVariant, FieldDecl, FnSig, PointeeKind, PublicDecl, StructDecl,
    StubDecl, TypeDecl, TypeRef,
};
use ntbindgen::merge::MergedNamespace;
use ntbindgen::name::RustPath;

fn rp(ns: &str, name: &str) -> RustPath {
    RustPath { ns: ns.to_owned(), name: name.to_owned() }
}

fn field(name: &str, ty: TypeRef, bit_offset: u32, bit_size: u16) -> FieldDecl {
    FieldDecl {
        original_name: name.to_owned(),
        rust_name: name.to_ascii_lowercase(),
        identifier: format!("_TEST.{name}"),
        ty,
        bit_offset,
        bit_size,
        key: 0xa79d_ebf4_9fdb_6a93,
        bitfield: None,
        per_build: Vec::new(),
    }
}

fn ns_with(types: Vec<TypeDecl>) -> MergedNamespace {
    MergedNamespace { default_ns: "nt", hint_image: "ntoskrnl.exe", types, publics: Vec::new() }
}

fn emit_one_named(ns: MergedNamespace, suffix: &str) -> (PathBuf, String) {
    let tmp =
        std::env::temp_dir().join(format!("ntbindgen_test_{}_{}", std::process::id(), suffix));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let opts = EmitOptions { publics: false, no_encrypt: false };
    let nsvec = vec![ns];
    for n in &nsvec {
        emit::write_unit(n, &tmp, opts, Target::Rust).unwrap();
    }
    emit::finalize(&tmp, &nsvec, opts, Target::Rust).unwrap();
    let body = read_file(&tmp.join("src/nt/foo_t.rs"));
    (tmp, body)
}
fn read_file(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|_| format!("[no such file: {}]", p.display()))
}

fn make_struct(name: &str, size: u64, fields: Vec<FieldDecl>) -> StructDecl {
    let original_name = format!("_{}", name.to_ascii_uppercase());
    let summary_key = ntbindgen::name::sdbm_hash(&format!("{original_name}.$"));
    StructDecl {
        original_name,
        path: rp("nt", &format!("{name}_t")),
        owner_image: "ntoskrnl.exe",
        size,
        fields,
        summary_key,
    }
}

#[test]
fn struct_emits_non_exhaustive_send_sync_debug_layout() {
    let s = make_struct("foo", 16, vec![field("Version", TypeRef::Primitive("u32"), 0, 32)]);
    let ns = ns_with(vec![TypeDecl::Struct(s)]);
    let (_tmp, body) = emit_one_named(ns, "hygiene");

    assert!(body.contains("#[non_exhaustive]"), "missing #[non_exhaustive]");
    assert!(body.contains("unsafe impl ::core::marker::Send"), "missing Send");
    assert!(body.contains("unsafe impl ::core::marker::Sync"), "missing Sync");
    assert!(body.contains("impl ::core::fmt::Debug for FooT"), "missing Debug impl");
    assert!(body.contains("pub const LAYOUT: ::core::alloc::Layout"), "missing LAYOUT const");
    assert!(body.contains("pub const SIZE: usize = 0x10"), "missing SIZE const");
}

#[test]
fn field_emits_offset_and_bit_size_consts() {
    let s = make_struct("foo", 8, vec![field("Version", TypeRef::Primitive("u32"), 0x20, 32)]);
    let ns = ns_with(vec![TypeDecl::Struct(s)]);
    let (_tmp, body) = emit_one_named(ns, "field_consts");

    assert!(body.contains("pub const VERSION_OFFSET: usize = 0x4"), "byte offset const missing");
    assert!(body.contains("pub const VERSION_BIT_SIZE: u16 = 32"), "bit-size const missing");
}

#[test]
fn copy_primitive_field_gets_value_and_volatile_accessors() {
    let s = make_struct("foo", 8, vec![field("Version", TypeRef::Primitive("u32"), 0, 32)]);
    let ns = ns_with(vec![TypeDecl::Struct(s)]);
    let (_tmp, body) = emit_one_named(ns, "value_accessors");

    assert!(body.contains("pub unsafe fn read_version(&self) -> u32"));
    assert!(body.contains("pub unsafe fn write_version(&mut self, value: u32)"));
    assert!(body.contains("pub unsafe fn read_volatile_version(&self) -> u32"));
    assert!(body.contains("pub unsafe fn write_volatile_version(&mut self, value: u32)"));
}

#[test]
fn value_accessor_collision_is_suppressed() {
    // Two fields whose companion names would clash on `read_volatile_x`:
    //   - field `volatile_x`         -> companion `read_volatile_x`
    //   - field `x` (Copy primitive) -> companion `read_volatile_x`
    // The emit pre-pass must suppress BOTH `x`'s companions, not just the
    // one that names the collision.
    let s = make_struct(
        "foo",
        16,
        vec![
            field("x", TypeRef::Primitive("u32"), 0, 32),
            field("volatile_x", TypeRef::Primitive("u32"), 0x20, 32),
        ],
    );
    let ns = ns_with(vec![TypeDecl::Struct(s)]);
    let (_tmp, body) = emit_one_named(ns, "collision");

    // Neither field should emit `read_volatile_*` because the names collide.
    let dupes = body.matches("pub unsafe fn read_volatile_x(").count();
    assert_eq!(dupes, 0, "expected zero `read_volatile_x` definitions, got {dupes}");
    // The base pointer accessors come through the `_ntbind::field!` macro
    // -- assert the macro invocations are present (the expanded signature
    // lives inside the macro body, not in the emitted source).
    assert!(body.contains("name = x,"), "missing field! macro for x");
    assert!(body.contains("name = volatile_x,"), "missing field! {{ name = volatile_x }}");
}

#[test]
fn enum_tryfrom_uses_unknown_discriminant() {
    let e = EnumDecl {
        original_name: "_FOO_E".to_owned(),
        path: rp("nt", "foo_e_t"),
        underlying: TypeRef::Primitive("i32"),
        variants: vec![
            EnumVariant {
                original_name: "FooA".to_owned(),
                rust_name: "a".to_owned(),
                value: 0,
                build_tag: None,
            },
            EnumVariant {
                original_name: "FooB".to_owned(),
                rust_name: "b".to_owned(),
                value: 1,
                build_tag: None,
            },
        ],
    };
    let ns = ns_with(vec![TypeDecl::Enum(e)]);
    let tmp = std::env::temp_dir().join(format!("ntbindgen_test_enum_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    emit::write_unit(&ns, &tmp, EmitOptions { publics: false, no_encrypt: false }, Target::Rust)
        .unwrap();
    emit::finalize(&tmp, &[ns], EmitOptions { publics: false, no_encrypt: false }, Target::Rust)
        .unwrap();
    let body = read_file(&tmp.join("src/nt/foo_e_t.rs"));

    assert!(body.contains("impl ::core::convert::TryFrom<i32> for FooET"), "missing TryFrom impl");
    assert!(
        body.contains("::ntbind::error::UnknownDiscriminant<Self, i32>"),
        "TryFrom Error should be UnknownDiscriminant<Self, i32>"
    );
    assert!(
        body.contains("::ntbind::error::UnknownDiscriminant::new(other)"),
        "Err arm should construct UnknownDiscriminant::new"
    );
}

#[test]
fn orphan_typed_pointer_pointee_gets_stub() {
    // Build a namespace containing exactly one struct that points at a
    // pointee whose type isn't itself in `types`. inject_orphan_stubs must
    // synthesize a Stub TypeDecl for the orphan.
    let s = make_struct(
        "foo",
        8,
        vec![field(
            "Ptr",
            TypeRef::TypedPointer {
                path: rp("nt", "ghost_t"),
                kind: PointeeKind::Struct,
                volatile_pointee: false,
            },
            0,
            64,
        )],
    );
    let mut nsvec = vec![ns_with(vec![TypeDecl::Struct(s)])];
    ntbindgen::emit::common::inject_orphan_stubs(&mut nsvec);

    let stub_count = nsvec[0].types.iter().filter(|t| matches!(t, TypeDecl::Stub(_))).count();
    assert_eq!(stub_count, 1, "exactly one orphan stub expected");
    let stub_path = nsvec[0]
        .types
        .iter()
        .find_map(|t| match t {
            TypeDecl::Stub(s) => Some(&s.path),
            _ => None,
        })
        .unwrap();
    assert_eq!(stub_path.ns, "nt");
    assert_eq!(stub_path.name, "ghost_t");
}

#[test]
fn stub_renders_phantomdata_marker() {
    let stub = StubDecl {
        original_name: "_GHOST".to_owned(),
        path: rp("nt", "ghost_t"),
        kind: PointeeKind::Struct,
    };
    let ns = ns_with(vec![TypeDecl::Stub(stub)]);
    let tmp = std::env::temp_dir().join(format!("ntbindgen_test_stub_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    emit::write_unit(&ns, &tmp, EmitOptions { publics: false, no_encrypt: false }, Target::Rust)
        .unwrap();
    let body = read_file(&tmp.join("src/nt/ghost_t.rs"));

    assert!(body.contains("pub struct GhostT(::core::marker::PhantomData<()>)"));
    assert!(body.contains("#[non_exhaustive]"));
    assert!(body.contains("#[repr(transparent)]"));
}

#[test]
fn namespace_prelude_re_exports_named_types() {
    let s1 = make_struct("foo", 4, vec![]);
    let s2 = make_struct("bar", 4, vec![]);
    let ns = ns_with(vec![TypeDecl::Struct(s1), TypeDecl::Struct(s2)]);
    let tmp = std::env::temp_dir().join(format!("ntbindgen_test_prelude_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    emit::write_unit(&ns, &tmp, EmitOptions { publics: false, no_encrypt: false }, Target::Rust)
        .unwrap();
    emit::finalize(&tmp, &[ns], EmitOptions { publics: false, no_encrypt: false }, Target::Rust)
        .unwrap();
    let mod_rs = read_file(&tmp.join("src/nt/mod.rs"));

    assert!(mod_rs.contains("pub mod prelude {"));
    assert!(mod_rs.contains("pub use super::foo_t::*;"));
    assert!(mod_rs.contains("pub use super::bar_t::*;"));
}

#[test]
fn typed_public_renders_with_fn_pointer_type() {
    // Build a public with the same shape ntbindgen produces from an
    // IPI `LF_FUNC_ID -> LF_PROCEDURE`:
    // `extern "system" fn(*mut nt::KeventT, i32, u8) -> i32`.
    let kevent = StructDecl {
        original_name: "_KEVENT".to_owned(),
        path: rp("nt", "kevent_t"),
        owner_image: "ntoskrnl.exe",
        size: 24,
        fields: vec![],
        summary_key: 0,
    };
    let sig = FnSig {
        return_type: TypeRef::Primitive("i32"),
        params: vec![
            TypeRef::TypedPointer {
                path: rp("nt", "kevent_t"),
                kind: PointeeKind::Struct,
                volatile_pointee: false,
            },
            TypeRef::Primitive("i32"),
            TypeRef::Primitive("u8"),
        ],
        variadic: false,
        calling_conv: CallConv::System,
    };
    let pub_typed = PublicDecl {
        original_name: "KeSetEvent".to_owned(),
        rust_name: "ke_set_event".to_owned(),
        rva: 0x1000,
        key: 0xa79d_ebf4_9fdb_6a93,
        signature: Some(sig),
    };
    let pub_untyped = PublicDecl {
        original_name: "DbgPrint".to_owned(),
        rust_name: "dbg_print".to_owned(),
        rva: 0x2000,
        key: 0xbeef_cafe_dead_5051,
        signature: None,
    };
    let ns = MergedNamespace {
        default_ns: "nt",
        hint_image: "ntoskrnl.exe",
        types: vec![TypeDecl::Struct(kevent)],
        publics: vec![pub_typed, pub_untyped],
    };
    let tmp = std::env::temp_dir().join(format!("ntbindgen_test_typed_pub_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    emit::write_unit(&ns, &tmp, EmitOptions { publics: true, no_encrypt: false }, Target::Rust)
        .unwrap();
    let body = read_file(&tmp.join("src/nt/api.rs"));

    // Typed public renders the recovered signature, not `c_void`.
    assert!(
        body.contains(
            "pub fn ke_set_event() -> Public<unsafe extern \"system\" fn(*mut \
             crate::nt::KeventT, i32, u8) -> i32>"
        ),
        "typed public signature missing from emitted api.rs:\n{body}"
    );
    // Untyped public keeps the legacy fallback.
    assert!(
        body.contains("pub fn dbg_print() -> Public<::core::ffi::c_void>"),
        "untyped public should render as c_void:\n{body}"
    );
}

#[test]
fn variadic_public_falls_back_to_c_void() {
    // Variadic signatures CAN'T be lowered to a stable Rust fn-pointer
    // type -- the emitter must drop back to `Public<c_void>` and let
    // the user write a fixed-arity transmute.
    let sig = FnSig {
        return_type: TypeRef::Primitive("i32"),
        params: vec![TypeRef::Pointer],
        variadic: true,
        calling_conv: CallConv::System,
    };
    let p = PublicDecl {
        original_name: "DbgPrint".to_owned(),
        rust_name: "dbg_print".to_owned(),
        rva: 0x3000,
        key: 0x1234_5678_9abc_def0,
        signature: Some(sig),
    };
    let ns = MergedNamespace {
        default_ns: "nt",
        hint_image: "ntoskrnl.exe",
        types: vec![],
        publics: vec![p],
    };
    let tmp =
        std::env::temp_dir().join(format!("ntbindgen_test_variadic_pub_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    emit::write_unit(&ns, &tmp, EmitOptions { publics: true, no_encrypt: false }, Target::Rust)
        .unwrap();
    let body = read_file(&tmp.join("src/nt/api.rs"));

    assert!(
        body.contains("pub fn dbg_print() -> Public<::core::ffi::c_void>"),
        "variadic signature must NOT leak into the Rust fn-pointer type:\n{body}"
    );
}

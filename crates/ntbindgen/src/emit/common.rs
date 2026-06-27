//! Cross-backend helpers -- string transforms and IR walkers shared by the
//! Rust and C++ emitters.

use std::collections::BTreeMap;

use crate::ir::{FieldDecl, PointeeKind, StubDecl, TypeDecl, TypeRef};
use crate::merge::MergedNamespace;
use crate::name::RustPath;

// "kuser_shared_data_t" -> "KuserSharedDataT" (Rust struct names).
#[must_use]
pub fn upper_camel_case(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut capitalize = true;
    for ch in snake.chars() {
        if ch == '_' {
            capitalize = true;
            continue;
        }
        if capitalize {
            out.extend(ch.to_uppercase());
            capitalize = false;
        } else {
            out.push(ch);
        }
    }
    out
}

// Canonical `RustPath` for a type declaration (regardless of backend
// -- both the Rust and C++ emitter use the same `ns::name` keying).
#[must_use]
pub fn ty_path(t: &TypeDecl) -> &RustPath {
    match t {
        TypeDecl::Struct(s) | TypeDecl::Union(s) => &s.path,
        TypeDecl::Enum(e) => &e.path,
        TypeDecl::Stub(s) => &s.path,
    }
}

// Walks every emitted type's field list, collect typed-pointer pointees
// whose RustPath isn't itself in the emitted set, and inject
// `TypeDecl::Stub` declarations so the pointer references resolve
// against a real type name.
//
// Used by both emitters -- the Rust side needs `*mut crate::ns::Foo` to
// resolve to a real declaration, and the C++ side gets a tidy place to
// emit a self-contained `.hpp` for header-per-declaration symmetry.
pub fn inject_orphan_stubs(namespaces: &mut [MergedNamespace]) {
    // 1. Build a set of emitted (ns, name) pairs.
    let mut emitted: rustc_hash::FxHashSet<(String, String)> = rustc_hash::FxHashSet::default();
    for ns in namespaces.iter() {
        for ty in &ns.types {
            let p = ty_path(ty);
            emitted.insert((p.ns.clone(), p.name.clone()));
        }
    }

    // 2. Walk every struct field AND every public-signature parameter /
    //    return type collecting orphan `TypedPointer` pointees.  Both
    //    sources can name a forward-decl-only PDB type the lowering
    //    pipeline didn't get to emit; without a stub for it the
    //    generated Rust crate fails to compile (`crate::ns::Foo` does
    //    not resolve).
    let mut orphans: BTreeMap<(String, String), PointeeKind> = BTreeMap::new();
    for ns in namespaces.iter() {
        for ty in &ns.types {
            let fields: &[FieldDecl] = match ty {
                TypeDecl::Struct(s) | TypeDecl::Union(s) => &s.fields,
                TypeDecl::Enum(_) | TypeDecl::Stub(_) => &[],
            };
            collect_orphans(fields, &emitted, &mut orphans);
        }
        for p in &ns.publics {
            if let Some(sig) = &p.signature {
                walk_orphans(&sig.return_type, &emitted, &mut orphans);
                for param in &sig.params {
                    walk_orphans(param, &emitted, &mut orphans);
                }
            }
        }
    }

    // 3. Group orphans by *top-level* namespace so each lands in the
    //    matching MergedNamespace's `types` list. Sub-namespaces of the
    //    same top-level go together -- write_unit splits them again via
    //    the nested NsTree.
    let mut per_top: BTreeMap<String, Vec<StubDecl>> = BTreeMap::new();
    for ((ns, name), kind) in orphans {
        let top = ns.split("::").next().unwrap_or(&ns).to_owned();
        let original_name = format!("_orphan_{}_{}", ns.replace("::", "_"), name);
        let path = crate::name::RustPath { ns: ns.clone(), name };
        per_top.entry(top).or_default().push(StubDecl { original_name, path, kind });
    }

    // 4. Attach stubs to the matching MergedNamespace (by `default_ns`'s
    //    top-level segment). If no namespace owns that top-level (rare),
    //    append to the first available namespace as a fallback.
    for ns in namespaces.iter_mut() {
        let owner_top = ns.default_ns.split("::").next().unwrap_or(ns.default_ns).to_owned();
        if let Some(stubs) = per_top.remove(&owner_top) {
            for stub in stubs {
                ns.types.push(TypeDecl::Stub(stub));
            }
        }
    }
    if let Some(first) = namespaces.first_mut() {
        for (_, stubs) in per_top {
            for stub in stubs {
                first.types.push(TypeDecl::Stub(stub));
            }
        }
    }
}

fn collect_orphans(
    fields: &[FieldDecl],
    emitted: &rustc_hash::FxHashSet<(String, String)>,
    out: &mut BTreeMap<(String, String), PointeeKind>,
) {
    for f in fields {
        walk_orphans(&f.ty, emitted, out);
    }
}

// Recursively collects orphan `TypedPointer` pointees found in a
// `TypeRef`.  Shared by the struct-field walker and the public-signature
// walker.
fn walk_orphans(
    t: &TypeRef,
    emitted: &rustc_hash::FxHashSet<(String, String)>,
    out: &mut BTreeMap<(String, String), PointeeKind>,
) {
    match t {
        TypeRef::TypedPointer { path, kind, .. } => {
            let key = (path.ns.clone(), path.name.clone());
            if !emitted.contains(&key) {
                out.entry(key).or_insert(*kind);
            }
        },
        TypeRef::Array { element, .. } => walk_orphans(element, emitted, out),
        // `Ref` and `FnPtr` are typed-pointer carriers from the IPI
        // lowering pipeline.  Recurse so an orphan pointee that only
        // appears inside a nested fn-pointer argument still gets its
        // stub injected.
        TypeRef::Ref(inner) | TypeRef::Volatile(inner) => walk_orphans(inner, emitted, out),
        TypeRef::FnPtr(sig) => {
            walk_orphans(&sig.return_type, emitted, out);
            for p in &sig.params {
                walk_orphans(p, emitted, out);
            }
        },
        TypeRef::Primitive(_)
        | TypeRef::Pointer
        | TypeRef::UserDefined(_)
        | TypeRef::External { .. }
        | TypeRef::Opaque(_) => {},
    }
}

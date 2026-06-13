//! Cross-build merging -- fold multiple per-build [`Unit`]s into one
//! emit-ready unit per namespace tag.
//!
//! Design: pick the canonical build's type/field instance as the
//! on-source default, and fold every
//! other build's data into per-field per-build offset records used for
//! source-level commentary and runtime offset patching. The wire format
//! itself carries only ONE offset per field -- the canonical default.
//!
//! Inputs are [`LoadedBuild`]s, each a (build, unit) pair. Output is a
//! single [`MergedNamespace`] keyed by `ns_tag`. The merger guarantees:
//! - one canonical [`StructDecl`] per `(ns_tag, original_name)` taken from
//!   the canonical build when present, otherwise from the last seen build
//!   with the most-complete field list,
//! - per field, a `per_build` vector recording each non-canonical build's
//!   byte offset (or `u32::MAX` when the field is absent in that build),
//! - publics deduplicated across builds with the canonical build's RVA
//!   winning when multiple builds agree on the name.

use rustc_hash::FxHashMap;

use crate::config::BuildEntry;
use crate::ir::{EnumDecl, FieldDecl, PublicDecl, StructDecl, TypeDecl, Unit};

// A single build's worth of loaded PDB data, tagged with which build it
// came from.
pub struct LoadedBuild {
    pub build: BuildEntry,
    pub unit: Unit,
}

// One namespace's merged contents ready to feed to the emitter.
pub struct MergedNamespace {
    pub default_ns: &'static str,
    pub hint_image: &'static str,
    pub types: Vec<TypeDecl>,
    pub publics: Vec<PublicDecl>,
}

// Merge per-build loads into a vector of namespace-scoped emit units.
//
// All inputs sharing the same `ns_tag` collapse into one `MergedNamespace`
// using `BuildEntry::is_canonical` to disambiguate offsets.
pub fn merge_builds(loaded: Vec<LoadedBuild>) -> Vec<MergedNamespace> {
    // Group by ns_tag in deterministic order.
    let mut by_ns: FxHashMap<&'static str, NamespaceBucket<'_>> = FxHashMap::default();
    for lb in &loaded {
        by_ns
            .entry(lb.unit.default_ns)
            .or_insert_with(|| NamespaceBucket::new(lb.unit.default_ns, lb.unit.hint_image))
            .add(lb);
    }
    let mut out: Vec<MergedNamespace> = by_ns.into_values().map(NamespaceBucket::finish).collect();
    out.sort_by_key(|ns| ns.default_ns);
    out
}

// In-flight namespace aggregator. Owns per-(original_name) buckets keyed by
// `BuildEntry::name`. Builds are visited in input order, so canonicality is
// resolved by `is_canonical` rather than ordering.
//
struct NamespaceBucket<'a> {
    default_ns: &'static str,
    hint_image: &'static str,
    // per type name -> per build name -> the type
    types: FxHashMap<String, FxHashMap<&'static str, &'a TypeDecl>>,
    // per public original name -> per build -> public
    publics: FxHashMap<String, FxHashMap<&'static str, &'a PublicDecl>>,
    seen_builds: Vec<&'a LoadedBuild>,
}

impl<'a> NamespaceBucket<'a> {
    fn new(default_ns: &'static str, hint_image: &'static str) -> Self {
        Self {
            default_ns,
            hint_image,
            types: FxHashMap::default(),
            publics: FxHashMap::default(),
            seen_builds: Vec::new(),
        }
    }

    fn add(&mut self, lb: &'a LoadedBuild) {
        self.seen_builds.push(lb);
        for ty in &lb.unit.types {
            let name = match ty {
                TypeDecl::Struct(s) | TypeDecl::Union(s) => s.original_name.clone(),
                TypeDecl::Enum(e) => e.original_name.clone(),
                TypeDecl::Stub(s) => s.original_name.clone(),
            };
            self.types.entry(name).or_default().insert(lb.build.name, ty);
        }
        for p in &lb.unit.publics {
            self.publics.entry(p.original_name.clone()).or_default().insert(lb.build.name, p);
        }
    }

    fn finish(self) -> MergedNamespace {
        let mut types = Vec::new();
        let mut keys: Vec<&String> = self.types.keys().collect();
        keys.sort();
        for k in keys {
            let per_build = &self.types[k];
            if let Some(merged) = merge_one_type(per_build, &self.seen_builds) {
                types.push(merged);
            }
        }

        let mut publics: Vec<PublicDecl> = Vec::new();
        let mut pub_keys: Vec<&String> = self.publics.keys().collect();
        pub_keys.sort();
        for k in pub_keys {
            let per_build = &self.publics[k];
            if let Some(p) = pick_canonical_public(per_build, &self.seen_builds) {
                publics.push(p);
            }
        }

        MergedNamespace { default_ns: self.default_ns, hint_image: self.hint_image, types, publics }
    }
}

// Pick the canonical [`TypeDecl`] and fold every other build's field
// offsets into the canonical instance's `per_build` vectors.
//
fn merge_one_type(
    per_build: &FxHashMap<&'static str, &TypeDecl>,
    seen_builds: &[&LoadedBuild],
) -> Option<TypeDecl> {
    // Pick the canonical-build entry; fall back to the most complete.
    let canonical = seen_builds
        .iter()
        .filter(|lb| lb.build.is_canonical)
        .find_map(|lb| per_build.get(lb.build.name).copied())
        .or_else(|| best_instance(per_build))?;

    // Easy case: structs/unions get per-build offset folds.
    let (TypeDecl::Struct(s) | TypeDecl::Union(s)) = canonical else {
        return Some(clone_type_decl(canonical));
    };
    let mut merged = clone_struct(s);
    let is_union = matches!(canonical, TypeDecl::Union(_));

    for field in merged.fields.iter_mut() {
        // Gather byte offsets from each build (in declaration order).
        for lb in seen_builds {
            let Some(ty) = per_build.get(lb.build.name) else {
                field.per_build.push((lb.build.name.to_owned(), u32::MAX));
                continue;
            };
            let other_fields = match ty {
                TypeDecl::Struct(s) | TypeDecl::Union(s) => &s.fields,
                TypeDecl::Enum(_) | TypeDecl::Stub(_) => continue,
            };
            let off = other_fields
                .iter()
                .find(|f| f.original_name == field.original_name)
                .map(|f| f.bit_offset / 8)
                .unwrap_or(u32::MAX);
            field.per_build.push((lb.build.name.to_owned(), off));
        }
    }
    Some(if is_union { TypeDecl::Union(merged) } else { TypeDecl::Struct(merged) })
}

fn best_instance<'a>(per_build: &'a FxHashMap<&'static str, &TypeDecl>) -> Option<&'a TypeDecl> {
    // Most fields wins; ties broken by lexicographic build name.
    let mut entries: Vec<(&&'static str, &&TypeDecl)> = per_build.iter().collect();
    entries.sort_by(|a, b| {
        let aw = type_weight(a.1);
        let bw = type_weight(b.1);
        bw.cmp(&aw).then(a.0.cmp(b.0))
    });
    entries.first().map(|(_, t)| **t)
}

fn type_weight(t: &TypeDecl) -> usize {
    match t {
        TypeDecl::Struct(s) | TypeDecl::Union(s) => s.fields.len(),
        TypeDecl::Enum(e) => e.variants.len(),
        TypeDecl::Stub(_) => 0,
    }
}

fn pick_canonical_public(
    per_build: &FxHashMap<&'static str, &PublicDecl>,
    seen_builds: &[&LoadedBuild],
) -> Option<PublicDecl> {
    // Canonical build wins for identity / RVA / name; fall back to any
    // build's entry when canonical is absent.
    let p = seen_builds
        .iter()
        .filter(|lb| lb.build.is_canonical)
        .find_map(|lb| per_build.get(lb.build.name).copied())
        .or_else(|| per_build.values().next().copied())?;
    // Signature can come from any build that recovered one.  If the
    // chosen build has `None`, scan the rest in `seen_builds` order
    // (canonical first) and take the first `Some`.  Selene's writer
    // (`writer.cpp:1118-1133`) walks every build's `type_names`; we
    // shortcut to the first non-None since today we still emit one
    // signature per public, not a union of variants.
    let signature = if p.signature.is_some() {
        p.signature.clone()
    } else {
        seen_builds
            .iter()
            .filter_map(|lb| per_build.get(lb.build.name).copied())
            .find_map(|q| q.signature.clone())
    };
    Some(PublicDecl {
        original_name: p.original_name.clone(),
        rust_name: p.rust_name.clone(),
        rva: p.rva,
        key: p.key,
        signature,
    })
}

fn clone_type_decl(t: &TypeDecl) -> TypeDecl {
    match t {
        TypeDecl::Struct(s) => TypeDecl::Struct(clone_struct(s)),
        TypeDecl::Union(s) => TypeDecl::Union(clone_struct(s)),
        TypeDecl::Enum(e) => TypeDecl::Enum(clone_enum(e)),
        TypeDecl::Stub(s) => TypeDecl::Stub(crate::ir::StubDecl {
            original_name: s.original_name.clone(),
            path: s.path.clone(),
            kind: s.kind,
        }),
    }
}

fn clone_struct(s: &StructDecl) -> StructDecl {
    StructDecl {
        original_name: s.original_name.clone(),
        path: s.path.clone(),
        size: s.size,
        fields: s.fields.iter().map(clone_field).collect(),
        summary_key: s.summary_key,
    }
}

fn clone_field(f: &FieldDecl) -> FieldDecl {
    FieldDecl {
        original_name: f.original_name.clone(),
        rust_name: f.rust_name.clone(),
        identifier: f.identifier.clone(),
        ty: f.ty.clone(),
        bit_offset: f.bit_offset,
        bit_size: f.bit_size,
        key: f.key,
        bitfield: f.bitfield,
        per_build: f.per_build.clone(),
    }
}

fn clone_enum(e: &EnumDecl) -> EnumDecl {
    EnumDecl {
        original_name: e.original_name.clone(),
        path: e.path.clone(),
        underlying: e.underlying.clone(),
        variants: e
            .variants
            .iter()
            .map(|v| crate::ir::EnumVariant {
                original_name: v.original_name.clone(),
                rust_name: v.rust_name.clone(),
                value: v.value,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::TypeRef;
    use crate::name::RustPath;

    fn build(name: &'static str, is_canonical: bool) -> BuildEntry {
        BuildEntry { name, path_suffix: "", is_canonical }
    }

    fn mk_field(orig: &str, bit_off: u32) -> FieldDecl {
        FieldDecl {
            original_name: orig.to_owned(),
            rust_name: orig.to_ascii_lowercase(),
            identifier: format!("_TEST.{orig}"),
            ty: TypeRef::Primitive("u32"),
            bit_offset: bit_off,
            bit_size: 32,
            key: 0xdead_beef,
            bitfield: None,
            per_build: Vec::new(),
        }
    }

    fn mk_struct(name: &str, fields: Vec<FieldDecl>) -> TypeDecl {
        let summary_key = crate::name::sdbm_hash(&format!("{name}.$"));
        TypeDecl::Struct(StructDecl {
            original_name: name.to_owned(),
            path: RustPath {
                ns: "nt".to_owned(),
                name: format!("{}_t", name.trim_start_matches('_').to_ascii_lowercase()),
            },
            size: 0x20,
            fields,
            summary_key,
        })
    }

    fn lb(build_name: &'static str, is_canonical: bool, ty: TypeDecl) -> LoadedBuild {
        LoadedBuild {
            build: build(build_name, is_canonical),
            unit: Unit {
                default_ns: "nt",
                hint_image: "ntoskrnl.exe",
                types: vec![ty],
                publics: vec![],
            },
        }
    }

    #[test]
    fn canonical_offset_wins_others_get_per_build() {
        let s_a = mk_struct("_FOO", vec![mk_field("Version", 0)]);
        let s_b = mk_struct("_FOO", vec![mk_field("Version", 0x40)]);
        let merged = merge_builds(vec![lb("test_a", false, s_a), lb("test_b", true, s_b)]);
        assert_eq!(merged.len(), 1);
        let TypeDecl::Struct(s) = &merged[0].types[0] else {
            panic!("expected struct");
        };
        let f = &s.fields[0];
        assert_eq!(f.bit_offset, 0x40, "canonical build's offset baked");
        assert!(f.per_build.iter().any(|(b, o)| b == "test_a" && *o == 0));
        assert!(f.per_build.iter().any(|(b, o)| b == "test_b" && *o == 8));
    }

    #[test]
    fn missing_field_encoded_as_max() {
        let s_a = mk_struct("_BAR", vec![mk_field("Cookie", 0x80)]);
        let s_b = mk_struct("_BAR", vec![]);
        let merged = merge_builds(vec![lb("test_a", true, s_a), lb("test_b", false, s_b)]);
        let TypeDecl::Struct(s) = &merged[0].types[0] else {
            panic!("expected struct");
        };
        let f = &s.fields[0];
        let b_obs = f.per_build.iter().find(|(b, _)| b == "test_b").unwrap();
        assert_eq!(b_obs.1, u32::MAX);
    }

    #[test]
    fn single_build_no_per_build_drift() {
        let s = mk_struct("_BAZ", vec![mk_field("Tag", 0x10)]);
        let merged = merge_builds(vec![lb("test_a", true, s)]);
        let TypeDecl::Struct(s) = &merged[0].types[0] else {
            panic!("expected struct");
        };
        let f = &s.fields[0];
        assert_eq!(f.bit_offset, 0x10);
        assert_eq!(f.per_build.len(), 1);
        assert_eq!(f.per_build[0].1, 2);
    }
}

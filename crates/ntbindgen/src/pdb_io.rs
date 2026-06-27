//! Read TPI types and DBI publics out of a PDB into [`Unit`] IR.
//!
//! Two notable structural moves vs a naive walk:
//! - Per-parent **anonymous type sink**: when a field's type resolves to an
//!   anonymous class/union/enum (no PDB tag name), the lowering pass mints a
//!   synthetic `u<N>_<field>_t` name, lowers the anon body in-place, and
//!   pushes the new `TypeDecl` into a sink the caller drains into the unit's
//!   types list. The original field gets a `TypeRef::UserDefined` pointing
//!   at the synthetic path so emit can use the same machinery as any other
//!   named struct.
//! - **Bitfield peeling**: `inspect_field_type` walks through `Modifier`
//!   wrappers to find `Bitfield` leaves, extracting the underlying integer
//!   storage size and signedness -- feeds straight into `ntbind::bit_field!`.

use std::path::Path;

use anyhow::{Context, Result};
use pdb::{
    ArgumentList, ClassKind, ClassType, EnumerationType, FallibleIterator, FieldList, IdData,
    ItemFinder, MemberType, PrimitiveKind, SymbolData, TypeData, TypeIndex, UnionType,
};

use crate::config::PdbEntry;
use crate::ir::{
    BitfieldInfo, CallConv, EnumDecl, EnumVariant, FieldDecl, FnSig, PublicDecl, StructDecl,
    TypeDecl, TypeRef, Unit,
};
use crate::name::{self, RustPath};
use crate::predicates;

// Loads a single PDB into the IR.
pub fn load_unit(entry: &PdbEntry, pdb_path: &Path) -> Result<Unit> {
    let file =
        std::fs::File::open(pdb_path).with_context(|| format!("opening {}", pdb_path.display()))?;
    let mut pdb = pdb::PDB::open(file).context("parsing PDB header")?;

    let type_info = pdb.type_information().context("reading TPI stream")?;
    let mut type_finder = type_info.finder();
    let mut iter = type_info.iter();
    while iter.next()?.is_some() {
        type_finder.update(&iter);
    }

    // Pre-build a name -> tidx map of non-forward Class/Union records
    // with a real field list. BaseClass records often point at a
    // forward-ref decl, so resolution falls back to this map.
    let mut class_by_name: rustc_hash::FxHashMap<String, TypeIndex> =
        rustc_hash::FxHashMap::default();
    {
        let mut scan_iter = type_info.iter();
        while let Some(item) = scan_iter.next()? {
            let Ok(data) = item.parse() else { continue };
            let (name, has_fields) = match &data {
                TypeData::Class(c) if !c.properties.forward_reference() && c.fields.is_some() => {
                    (c.name.to_string().into_owned(), true)
                },
                TypeData::Union(u) if !u.properties.forward_reference() => {
                    (u.name.to_string().into_owned(), true)
                },
                _ => continue,
            };
            if has_fields {
                // First-seen instance per name is sufficient for BaseClass resolution.
                class_by_name.entry(name).or_insert(item.index());
            }
        }
    }

    let mut ctx = Lowering { finder: &type_finder, entry, extras: Vec::new(), class_by_name };

    let mut types = Vec::new();
    let mut iter = type_info.iter();
    while let Some(item) = iter.next()? {
        let data = match item.parse() {
            Ok(d) => d,
            Err(_) => continue,
        };
        if let Some(decl) = ctx.lower_top_type(&data) {
            types.push(decl);
        }
    }
    // Drain anon types collected during field lowering. They look just like
    // any other generated type to the emitter.
    types.extend(ctx.extras);

    // De-duplicate types by name: PDB TPI commonly carries multiple
    // non-forward Class/Union records for the same struct (partial
    // public-facing decl vs fuller private decl, with either differing
    // or matching sizes). Tiebreak by (field count, size) descending
    // -- pick the most complete instance; first-seen wins on equal
    // rank. Anon synthetic names are unique by construction.
    {
        use rustc_hash::FxHashMap;
        let rank = |t: &TypeDecl| -> (usize, u64) {
            match t {
                TypeDecl::Struct(s) | TypeDecl::Union(s) => (s.fields.len(), s.size),
                TypeDecl::Enum(e) => (e.variants.len(), 0),
                TypeDecl::Stub(_) => (0, 0),
            }
        };
        let type_name = |t: &TypeDecl| -> String {
            match t {
                TypeDecl::Struct(s) | TypeDecl::Union(s) => s.original_name.clone(),
                TypeDecl::Enum(e) => e.original_name.clone(),
                TypeDecl::Stub(s) => s.original_name.clone(),
            }
        };
        let mut by_name: FxHashMap<String, (usize, (usize, u64))> = FxHashMap::default();
        let mut keep = vec![true; types.len()];
        for (i, t) in types.iter().enumerate() {
            let name = type_name(t);
            let r = rank(t);
            match by_name.get(&name) {
                Some(&(_, prev_r)) if prev_r >= r => {
                    keep[i] = false;
                },
                Some(&(prev_i, _)) => {
                    keep[prev_i] = false;
                    by_name.insert(name, (i, r));
                },
                None => {
                    by_name.insert(name, (i, r));
                },
            }
        }
        let mut i = 0usize;
        types.retain(|_| {
            let k = keep[i];
            i += 1;
            k
        });
    }
    // IPI -- pair `LF_FUNC_ID` (name) with the TPI `LF_PROCEDURE`
    // (signature). Build a name -> tpi_type_index map so the publics
    // ingestion loop can attach signatures by lookup. Missing IPI is
    // non-fatal: untyped publics are emitted instead.
    let signatures_by_name: rustc_hash::FxHashMap<String, TypeIndex> = match pdb.id_information() {
        Ok(id_info) => collect_function_ids(&id_info)?,
        Err(e) => {
            log::warn!("IPI stream unavailable for {}: {e}", pdb_path.display());
            rustc_hash::FxHashMap::default()
        },
    };

    // Publics -- global symbol table.
    let mut publics = Vec::new();
    let mut seen_publics = rustc_hash::FxHashSet::default();
    // The address map applies any OMAP table the linker emitted; without it
    // `p.offset.offset` is the symbol's *section-relative* offset rather
    // than its image RVA, which is wrong for any PDB whose `.text` does
    // not begin at RVA 0.
    let address_map = pdb.address_map().context("reading PDB address map")?;
    let symbol_table = pdb.global_symbols().context("reading DBI globals")?;
    let mut symiter = symbol_table.iter();
    while let Some(symbol) = symiter.next()? {
        let Ok(SymbolData::Public(p)) = symbol.parse() else {
            continue;
        };
        let raw = p.name.to_string().into_owned();
        if raw.is_empty() || predicates::is_midl_frag(&raw) {
            continue;
        }
        let original = predicates::strip_import_decoration(&raw).to_owned();
        if !seen_publics.insert(original.clone()) {
            continue;
        }
        if !predicates::is_acceptable_public_name(&original) {
            continue;
        }
        // Skip symbols whose section is not mapped at runtime (debug
        // metadata, eliminated COMDATs, OMAP holes).
        let Some(rva) = p.offset.to_rva(&address_map) else { continue };
        let rust_name = sanitize_public_name(&original);
        let ident = format!("${original}${}", entry.hint_image);
        let key = name::sdbm_hash(&ident);
        // IPI keys functions on the demangled bare name (`bar`, `Foo`);
        // S_PUB32 carries the mangled symbol (`?bar@Foo@@QEAA...`).
        // Demangle the public so both streams agree on the lookup key.
        let ipi_key = predicates::demangle_simple_cxx(&original);
        let signature = signatures_by_name
            .get(&ipi_key)
            .or_else(|| signatures_by_name.get(&original))
            .and_then(|idx| lower_procedure_signature(*idx, &type_finder, entry.ns_tag));
        publics.push(PublicDecl { original_name: original, rust_name, rva: rva.0, key, signature });
    }
    // Nt/Zw pair merge: if both exist for the same suffix, keep the Nt
    // form and tag the Zw counterpart as an alias on the same record.
    merge_nt_zw_publics(&mut publics);

    Ok(Unit { default_ns: entry.ns_tag, hint_image: entry.hint_image, types, publics })
}

fn sanitize_public_name(orig: &str) -> String {
    // Decode ?0/?1 C++ ctor/dtor mangling and `@`-separated member paths.
    let demangled = predicates::demangle_simple_cxx(orig);
    let snake = name::to_snake_case(&demangled);
    let escaped = name::escape_keyword(&snake).into_owned();
    if escaped.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{escaped}")
    } else if escaped.is_empty() {
        "anonymous".to_owned()
    } else {
        escaped
    }
}

// Walks the IPI stream and collects every `LF_FUNC_ID` record into a
// `name -> TypeIndex` map -- the TypeIndex points at the function's
// `LF_PROCEDURE` in TPI.
fn collect_function_ids(
    id_info: &pdb::IdInformation<'_>,
) -> Result<rustc_hash::FxHashMap<String, TypeIndex>> {
    let mut map = rustc_hash::FxHashMap::default();
    let mut iter = id_info.iter();
    while let Some(item) = iter.next()? {
        let Ok(data) = item.parse() else { continue };
        if let IdData::Function(f) = data {
            // CodeView's `LF_FUNC_ID.name` carries the function's bare
            // identifier (e.g. `ZwQueryValueKey`, or `bar` for a C++
            // method `Foo::bar`).  Insert verbatim; the S_PUB32-side
            // lookup applies the same demangling for collision.
            let name = f.name.to_string().into_owned();
            map.insert(name, f.function_type);
        }
    }
    Ok(map)
}

// Resolves an IPI `LF_FUNC_ID`'s `function_type` field -- a TPI index
// pointing at an `LF_PROCEDURE` -- into a fully lowered `FnSig`.
//
// Returns `None` when:
// - the TPI entry isn't an `LF_PROCEDURE` (member function records use
//   `LF_MFUNCTION`; we don't lower those because they're never publics);
// - the argument list cannot be resolved (corrupted PDB / unsupported
//   leaf type).
fn lower_procedure_signature(
    proc_idx: TypeIndex,
    finder: &ItemFinder<'_, TypeIndex>,
    default_ns: &str,
) -> Option<FnSig> {
    let item = finder.find(proc_idx).ok()?;
    let data = item.parse().ok()?;
    lower_procedure_data(&data, finder, default_ns)
}

// Lower an already-parsed `TypeData::Procedure` (or any leaf that comes
// through here as one) into a `FnSig`.  Split from
// `lower_procedure_signature` so `resolve_pointer` can re-use it when
// it has already parsed the underlying `LF_POINTER` pointee.
fn lower_procedure_data(
    data: &TypeData<'_>,
    finder: &ItemFinder<'_, TypeIndex>,
    default_ns: &str,
) -> Option<FnSig> {
    let TypeData::Procedure(proc) = data else {
        return None;
    };
    let return_type = match proc.return_type {
        Some(idx) => resolve_type(idx, finder, default_ns).unwrap_or(TypeRef::Opaque(0)),
        None => TypeRef::Primitive("::core::ffi::c_void"),
    };
    let arglist_item = finder.find(proc.argument_list).ok()?;
    let arglist: ArgumentList = match arglist_item.parse().ok()? {
        TypeData::ArgumentList(a) => a,
        _ => return None,
    };
    let mut variadic = false;
    let mut effective_args = arglist.arguments.clone();
    if let Some(last) = effective_args.last()
        && is_no_type_index(*last, finder)
    {
        variadic = true;
        effective_args.pop();
    }
    let mut params = Vec::with_capacity(effective_args.len());
    for arg_idx in effective_args {
        let ty = resolve_type(arg_idx, finder, default_ns).unwrap_or(TypeRef::Opaque(0));
        params.push(ty);
    }
    Some(FnSig { return_type, params, variadic, calling_conv: CallConv::System })
}

// True when `idx` is the CodeView `NoType` sentinel that terminates a
// variadic argument list.  Implemented as "looks up to a `Primitive`
// with kind `NoType`" rather than a raw `0x0000` check because the pdb
// crate hides the raw index encoding behind `TypeIndex`.
fn is_no_type_index(idx: TypeIndex, finder: &ItemFinder<'_, TypeIndex>) -> bool {
    let Ok(item) = finder.find(idx) else { return false };
    matches!(item.parse(), Ok(TypeData::Primitive(p)) if p.kind == PrimitiveKind::NoType)
}

fn merge_nt_zw_publics(publics: &mut [PublicDecl]) {
    // Keep both `Nt*` and `Zw*` publics. Cross-copy `LF_FUNC_ID`
    // signatures so callers on either side see typed parameters even
    // when the PDB only carried an IPI record for one half of the pair.
    use rustc_hash::FxHashMap;
    let mut nt_index: FxHashMap<String, usize> = FxHashMap::default();
    let mut zw_index: FxHashMap<String, usize> = FxHashMap::default();
    for (i, p) in publics.iter().enumerate() {
        if let Some(suffix) = p.original_name.strip_prefix("Nt") {
            nt_index.insert(suffix.to_owned(), i);
        } else if let Some(suffix) = p.original_name.strip_prefix("Zw") {
            zw_index.insert(suffix.to_owned(), i);
        }
    }
    let mut updates: Vec<(usize, FnSig)> = Vec::new();
    for (suffix, &nt_i) in &nt_index {
        if let Some(&zw_i) = zw_index.get(suffix) {
            if publics[nt_i].signature.is_none()
                && let Some(sig) = &publics[zw_i].signature
            {
                updates.push((nt_i, sig.clone()));
            }
            if publics[zw_i].signature.is_none()
                && let Some(sig) = &publics[nt_i].signature
            {
                updates.push((zw_i, sig.clone()));
            }
        }
    }
    for (i, sig) in updates {
        publics[i].signature = Some(sig);
    }
}

// Lowering context -- what every lower-* function needs.
//
struct Lowering<'a> {
    finder: &'a ItemFinder<'a, TypeIndex>,
    entry: &'a PdbEntry,
    // Anonymous types harvested from inside other types' field lists.
    extras: Vec<TypeDecl>,
    // Name -> TypeIndex for non-forward Class/Union records with a real
    // FieldList. BaseClass records often reference the forward-ref
    // decl, so resolution falls back to a name lookup.
    class_by_name: rustc_hash::FxHashMap<String, TypeIndex>,
}

impl<'a> Lowering<'a> {
    fn lower_top_type(&mut self, data: &TypeData<'_>) -> Option<TypeDecl> {
        match data {
            TypeData::Class(c) => self.lower_class(c),
            TypeData::Union(u) => self.lower_union(u),
            TypeData::Enumeration(e) => self.lower_enum(e),
            _ => None,
        }
    }

    fn classify_or_fallback(&self, name_raw: &str) -> RustPath {
        name::classify(name_raw).unwrap_or_else(|| name::fallback_path(self.entry.ns_tag, name_raw))
    }

    fn lower_class(&mut self, c: &ClassType<'_>) -> Option<TypeDecl> {
        if c.properties.forward_reference() {
            return None;
        }
        let original = c.name.to_string();
        let original = original.as_ref();
        if predicates::is_anonymous_type(original)
            || predicates::is_midl_frag(original)
            || original.contains('<')
            || original.contains("::")
            || substitute_native_type(original).is_some()
        {
            return None;
        }
        // Dedup is deferred to load_unit so the post-pass can pick the
        // most complete instance of multiple Class records with the same name.
        let path = self.classify_or_fallback(original);
        let fields = self.lower_fields(c.fields, original, &path).unwrap_or_default();
        let summary_key = name::sdbm_hash(&format!("{original}.$"));
        let decl = StructDecl {
            original_name: original.to_owned(),
            path,
            size: c.size,
            fields,
            summary_key,
        };
        Some(if c.kind == ClassKind::Class || c.kind == ClassKind::Struct {
            TypeDecl::Struct(decl)
        } else {
            TypeDecl::Union(decl)
        })
    }

    fn lower_union(&mut self, u: &UnionType<'_>) -> Option<TypeDecl> {
        if u.properties.forward_reference() {
            return None;
        }
        let original = u.name.to_string();
        let original = original.as_ref();
        if predicates::is_anonymous_type(original)
            || predicates::is_midl_frag(original)
            || original.contains('<')
            || original.contains("::")
            || substitute_native_type(original).is_some()
        {
            return None;
        }
        // Dedup deferred to load_unit; same rationale as lower_class.
        let path = self.classify_or_fallback(original);
        let fields = self.lower_fields(Some(u.fields), original, &path).unwrap_or_default();
        let summary_key = name::sdbm_hash(&format!("{original}.$"));
        Some(TypeDecl::Union(StructDecl {
            original_name: original.to_owned(),
            path,
            size: u.size,
            fields,
            summary_key,
        }))
    }

    fn lower_enum(&mut self, e: &EnumerationType<'_>) -> Option<TypeDecl> {
        if e.properties.forward_reference() {
            return None;
        }
        let original = e.name.to_string();
        let original = original.as_ref();
        if predicates::is_anonymous_type(original)
            || predicates::is_midl_frag(original)
            || original.contains('<')
            || original.contains("::")
        {
            return None;
        }
        // Dedup deferred to load_unit; same rationale as lower_class.
        let path = self.classify_or_fallback(original);
        let underlying = resolve_type(e.underlying_type, self.finder, self.entry.ns_tag)
            .unwrap_or(TypeRef::Primitive("i32"));

        // Per-variant tuple: (original_name, value, build_tag). build_tag
        // is set by the cross-build merge in merge.rs on variants from a
        // non-canonical build so the emitter can annotate them.
        let mut raw: Vec<(String, i128, Option<&'static str>)> = Vec::new();
        if let Ok(field_list) = self.finder.find(e.fields)
            && let Ok(TypeData::FieldList(fl)) = field_list.parse()
        {
            collect_enum_raw(&fl, self.finder, &mut raw);
        }
        let prefix_len = {
            let names: Vec<&str> = raw.iter().map(|(n, _, _)| n.as_str()).collect();
            name::common_variant_prefix_len(&names)
        };
        let mut variants = Vec::with_capacity(raw.len());
        let mut used = rustc_hash::FxHashSet::default();
        for (original_v, value, build_tag) in raw {
            let trimmed = &original_v[prefix_len..];
            let mut rust_name = name::to_snake_case(trimmed);
            if rust_name.is_empty() {
                rust_name = name::to_snake_case(&original_v);
            }
            if rust_name.is_empty() {
                rust_name = "variant".to_owned();
            }
            if rust_name.starts_with(|c: char| c.is_ascii_digit()) {
                rust_name.insert(0, '_');
            }
            rust_name = name::escape_keyword(&rust_name).into_owned();
            while !used.insert(rust_name.clone()) {
                rust_name.push('_');
            }
            variants.push(EnumVariant { original_name: original_v, rust_name, value, build_tag });
        }
        Some(TypeDecl::Enum(EnumDecl {
            original_name: original.to_owned(),
            path,
            underlying,
            variants,
        }))
    }

    fn lower_fields(
        &mut self,
        field_list_idx: Option<TypeIndex>,
        parent_original: &str,
        parent_path: &RustPath,
    ) -> Option<Vec<FieldDecl>> {
        let idx = field_list_idx?;
        let item = self.finder.find(idx).ok()?;
        let parsed = item.parse().ok()?;
        let TypeData::FieldList(fl) = parsed else {
            return None;
        };
        let mut out = Vec::new();
        let mut used = rustc_hash::FxHashSet::default();
        let mut anon_counter = 0u32;
        self.collect_fields(
            &fl,
            parent_original,
            parent_path,
            &mut anon_counter,
            &mut out,
            &mut used,
        );
        Some(out)
    }

    fn collect_fields(
        &mut self,
        fl: &FieldList<'_>,
        parent_original: &str,
        parent_path: &RustPath,
        anon_counter: &mut u32,
        out: &mut Vec<FieldDecl>,
        used: &mut rustc_hash::FxHashSet<String>,
    ) {
        self.collect_fields_with_base(fl, parent_original, parent_path, 0, anon_counter, out, used);
    }

    // Flatten legacy anon-union members (`u`/`u0..u9`/`s`/`s0..s9`/
    // `e`/`e0..e9`) into the parent struct, adjusting field offsets by
    // the outer base. Lets consumers reach `section->file_object`
    // instead of `section->u1.file_object`.
    #[allow(clippy::too_many_arguments)]
    fn collect_fields_with_base(
        &mut self,
        fl: &FieldList<'_>,
        parent_original: &str,
        parent_path: &RustPath,
        base_bit_offset: u32,
        anon_counter: &mut u32,
        out: &mut Vec<FieldDecl>,
        used: &mut rustc_hash::FxHashSet<String>,
    ) {
        for field in &fl.fields {
            // Flatten base classes (LF_BCLASS): splice the base's
            // fields into the derived struct's list, shifting each
            // field's offset by the BaseClass record's `offset`
            // (typically 0 for single-base kernel records).
            if let TypeData::BaseClass(b) = field {
                // PDB BaseClass records often reference the forward-ref
                // decl; fall back through `class_by_name` if so.
                if let Some(base_fl_idx) = self.resolve_base_fields_idx(b.base_class)
                    && let Ok(base_fl_item) = self.finder.find(base_fl_idx)
                    && let Ok(TypeData::FieldList(base_fl)) = base_fl_item.parse()
                {
                    let nested_base = base_bit_offset.saturating_add(b.offset.saturating_mul(8));
                    self.collect_fields_with_base(
                        &base_fl,
                        parent_original,
                        parent_path,
                        nested_base,
                        anon_counter,
                        out,
                        used,
                    );
                }
                continue;
            }
            if let TypeData::Member(m) = field {
                // Flatten path: legacy anon name + anon-typed Class/Union.
                if let Some(inner_fields_idx) = self.detect_anon_flatten_target(m)
                    && let Ok(inner_item) = self.finder.find(inner_fields_idx)
                    && let Ok(TypeData::FieldList(inner_fl)) = inner_item.parse()
                {
                    let inner_base = base_bit_offset
                        .saturating_add(u32::try_from(m.offset * 8).unwrap_or(u32::MAX));
                    self.collect_fields_with_base(
                        &inner_fl,
                        parent_original,
                        parent_path,
                        inner_base,
                        anon_counter,
                        out,
                        used,
                    );
                    continue;
                }
                // Normal path: lower the member, then rebase its
                // bit_offset by the accumulated base for flatten contexts.
                if let Some(mut decl) =
                    self.lower_member(m, parent_original, parent_path, anon_counter, used)
                {
                    if base_bit_offset != 0 {
                        decl.bit_offset = decl.bit_offset.saturating_add(base_bit_offset);
                    }
                    out.push(decl);
                }
            }
        }
        if let Some(cont) = fl.continuation
            && let Ok(item) = self.finder.find(cont)
            && let Ok(TypeData::FieldList(next)) = item.parse()
        {
            self.collect_fields_with_base(
                &next,
                parent_original,
                parent_path,
                base_bit_offset,
                anon_counter,
                out,
                used,
            );
        }
    }

    // Returns the inner FieldList's TypeIndex when `m` is a flatten
    // candidate (legacy-anon name AND anonymous Class/Union type with
    // a non-forward-ref body). Pure predicate; caller splices.
    fn detect_anon_flatten_target(&self, m: &MemberType<'_>) -> Option<TypeIndex> {
        let name = m.name.to_string();
        if !predicates::is_legacy_anonymous_variable(name.as_ref()) {
            return None;
        }
        let item = self.finder.find(m.field_type).ok()?;
        let data = item.parse().ok()?;
        match data {
            TypeData::Class(c) if !c.properties.forward_reference() => {
                let n = c.name.to_string();
                if !predicates::is_anonymous_type(n.as_ref()) {
                    return None;
                }
                c.fields
            },
            TypeData::Union(u) if !u.properties.forward_reference() => {
                let n = u.name.to_string();
                if !predicates::is_anonymous_type(n.as_ref()) {
                    return None;
                }
                Some(u.fields)
            },
            _ => None,
        }
    }

    // Resolve the FieldList TypeIndex for the Class/Union behind a
    // BaseClass record. Try the BaseClass tidx directly first; if it's
    // a forward-ref, fall back through `class_by_name` to the full
    // definition by name.
    fn resolve_base_fields_idx(&self, base_class_tidx: TypeIndex) -> Option<TypeIndex> {
        // First, try the BaseClass tidx directly.
        let direct_item = self.finder.find(base_class_tidx).ok()?;
        let direct = direct_item.parse().ok()?;
        let (name, direct_fields) = match direct {
            TypeData::Class(c) => {
                let fields = if c.properties.forward_reference() { None } else { c.fields };
                (c.name.to_string().into_owned(), fields)
            },
            TypeData::Union(u) => {
                let fields = if u.properties.forward_reference() { None } else { Some(u.fields) };
                (u.name.to_string().into_owned(), fields)
            },
            _ => return None,
        };
        if let Some(fl) = direct_fields {
            return Some(fl);
        }
        // Direct was forward-ref or missing -- fall back to name lookup.
        let full_idx = *self.class_by_name.get(&name)?;
        let full_item = self.finder.find(full_idx).ok()?;
        match full_item.parse().ok()? {
            TypeData::Class(c) => c.fields,
            TypeData::Union(u) => Some(u.fields),
            _ => None,
        }
    }

    fn lower_member(
        &mut self,
        m: &MemberType<'_>,
        parent_original: &str,
        parent_path: &RustPath,
        anon_counter: &mut u32,
        used: &mut rustc_hash::FxHashSet<String>,
    ) -> Option<FieldDecl> {
        let original = m.name.to_string().into_owned();
        if original.is_empty() || predicates::is_reserved_field(&original) {
            return None;
        }
        let mut rust_name = name::to_snake_case(&original);
        if rust_name.is_empty() {
            rust_name = "field".to_owned();
        }
        rust_name = name::escape_keyword(&rust_name).into_owned();
        while !used.insert(rust_name.clone()) {
            rust_name.push('_');
        }
        let info = self.inspect_field_type(
            m.field_type,
            parent_original,
            parent_path,
            &original,
            &rust_name,
            anon_counter,
        );
        let bit_offset: u32 =
            u32::try_from(m.offset * 8).ok()?.saturating_add(info.bit_offset_in_field);
        let identifier = format!("{parent_original}.{original}");
        let key = name::sdbm_hash(&identifier);
        Some(FieldDecl {
            original_name: original,
            rust_name,
            identifier,
            ty: info.ty,
            bit_offset,
            bit_size: info.bit_size,
            key,
            bitfield: info.bitfield,
            per_build: Vec::new(),
        })
    }

    // Resolve a field's type, peeling bitfield wrappers and synthesizing
    // anonymous nested types into self.extras when needed.
    //
    fn inspect_field_type(
        &mut self,
        idx: TypeIndex,
        parent_original: &str,
        parent_path: &RustPath,
        field_original: &str,
        field_snake: &str,
        anon_counter: &mut u32,
    ) -> FieldTypeInfo {
        // Bitfield path first.
        if let Some((bf, underlying_idx)) = peel_bitfield(idx, self.finder) {
            let underlying = self.finder.find(underlying_idx).ok().and_then(|i| i.parse().ok());
            let (ty, signed, storage_bytes) = match underlying.as_ref() {
                Some(TypeData::Primitive(p)) => (
                    TypeRef::Primitive(primitive_to_rust(p.kind)),
                    primitive_is_signed(p.kind),
                    primitive_bytes(p.kind),
                ),
                _ => (TypeRef::Primitive("u32"), false, 4),
            };
            return FieldTypeInfo {
                ty,
                bit_size: bf.length as u16,
                bit_offset_in_field: bf.position as u32,
                bitfield: Some(BitfieldInfo { storage_bytes, signed }),
            };
        }

        // Anonymous nested class/union/enum: synthesize a sibling type.
        if let Some(anon_ref) = self.synthesize_anonymous(
            idx,
            parent_original,
            parent_path,
            field_original,
            field_snake,
            anon_counter,
        ) {
            return FieldTypeInfo {
                ty: anon_ref.ty,
                bit_size: anon_ref.bit_size,
                bit_offset_in_field: 0,
                bitfield: None,
            };
        }

        // Regular field path.
        let ty = resolve_type(idx, self.finder, self.entry.ns_tag).unwrap_or(TypeRef::Opaque(0));
        let bit_size = sizeof(&ty, self.finder).saturating_mul(8).min(u16::MAX as u64) as u16;
        FieldTypeInfo { ty, bit_size, bit_offset_in_field: 0, bitfield: None }
    }

    // Detect anonymous class/union/enum at `idx` and, if found, lower it
    // into an extras-list entry under a synthetic `u<N>_<field>_t` name.
    // Returns the substituted `TypeRef` plus bit size.
    //
    fn synthesize_anonymous(
        &mut self,
        idx: TypeIndex,
        parent_original: &str,
        parent_path: &RustPath,
        field_original: &str,
        field_snake: &str,
        anon_counter: &mut u32,
    ) -> Option<AnonSubst> {
        let item = self.finder.find(idx).ok()?;
        let data = item.parse().ok()?;
        // Peel typedefs/modifiers.
        let data = match data {
            TypeData::Modifier(m) => {
                let inner = self.finder.find(m.underlying_type).ok()?;
                inner.parse().ok()?
            },
            other => other,
        };
        // Identifier convention for fields inside an anonymous nested
        // type: `<ParentOrig>.<AnonFieldName>.<InnerField>`. Build the
        // dotted prefix and pass it through as the new `parent_original`
        // so inner field identifiers come out canonical.
        let dotted_parent = format!("{parent_original}.{field_original}");
        match data {
            TypeData::Class(c) if !c.properties.forward_reference() => {
                let n = c.name.to_string();
                if !predicates::is_anonymous_type(n.as_ref()) {
                    return None;
                }
                let parent_stem = parent_path.name.trim_end_matches("_t");
                let synthetic_name = format!("{parent_stem}_u{}_{field_snake}_t", *anon_counter);
                *anon_counter += 1;
                let synthetic_path =
                    RustPath { ns: parent_path.ns.clone(), name: synthetic_name.clone() };
                // IR-side original_name keeps the collapsed form for
                // file-system safety; the wire identifier uses `dotted_parent`.
                let synthetic_original =
                    format!("{parent_original}::{synthetic_name}").replace("::", "_");
                let fields = self
                    .lower_fields(c.fields, &dotted_parent, &synthetic_path)
                    .unwrap_or_default();
                let summary_key = name::sdbm_hash(&format!("{synthetic_original}.$"));
                let decl = StructDecl {
                    original_name: synthetic_original,
                    path: synthetic_path.clone(),
                    size: c.size,
                    fields,
                    summary_key,
                };
                // TypeData::Class always has class/struct/interface kinds --
                // anon unions arrive via `TypeData::Union`, handled in the
                // arm below.
                self.extras.push(TypeDecl::Struct(decl));
                Some(AnonSubst {
                    ty: TypeRef::UserDefined(synthetic_path),
                    bit_size: (c.size.saturating_mul(8)).min(u16::MAX as u64) as u16,
                })
            },
            TypeData::Union(u) if !u.properties.forward_reference() => {
                let n = u.name.to_string();
                if !predicates::is_anonymous_type(n.as_ref()) {
                    return None;
                }
                let parent_stem = parent_path.name.trim_end_matches("_t");
                let synthetic_name = format!("{parent_stem}_u{}_{field_snake}_t", *anon_counter);
                *anon_counter += 1;
                let synthetic_path =
                    RustPath { ns: parent_path.ns.clone(), name: synthetic_name.clone() };
                let synthetic_original =
                    format!("{parent_original}::{synthetic_name}").replace("::", "_");
                let fields = self
                    .lower_fields(Some(u.fields), &dotted_parent, &synthetic_path)
                    .unwrap_or_default();
                let summary_key = name::sdbm_hash(&format!("{synthetic_original}.$"));
                let decl = StructDecl {
                    original_name: synthetic_original,
                    path: synthetic_path.clone(),
                    size: u.size,
                    fields,
                    summary_key,
                };
                self.extras.push(TypeDecl::Union(decl));
                Some(AnonSubst {
                    ty: TypeRef::UserDefined(synthetic_path),
                    bit_size: (u.size.saturating_mul(8)).min(u16::MAX as u64) as u16,
                })
            },
            TypeData::Enumeration(e) if !e.properties.forward_reference() => {
                let n = e.name.to_string();
                if !predicates::is_anonymous_type(n.as_ref()) {
                    return None;
                }
                let parent_stem = parent_path.name.trim_end_matches("_t");
                let synthetic_name = format!("{parent_stem}_u{}_{field_snake}_t", *anon_counter);
                *anon_counter += 1;
                let synthetic_path =
                    RustPath { ns: parent_path.ns.clone(), name: synthetic_name.clone() };
                // Reuse the regular enum lowering pipeline by sub-calling
                // `lower_enum` with `seen` bypassed (the synthetic name is
                // unique-by-construction so we don't risk a clash).
                let underlying = resolve_type(e.underlying_type, self.finder, self.entry.ns_tag)
                    .unwrap_or(TypeRef::Primitive("i32"));
                let mut raw: Vec<(String, i128, Option<&'static str>)> = Vec::new();
                if let Ok(field_list) = self.finder.find(e.fields)
                    && let Ok(TypeData::FieldList(fl)) = field_list.parse()
                {
                    collect_enum_raw(&fl, self.finder, &mut raw);
                }
                let names: Vec<&str> = raw.iter().map(|(s, _, _)| s.as_str()).collect();
                let prefix_len = name::common_variant_prefix_len(&names);
                let mut variants = Vec::new();
                let mut used = rustc_hash::FxHashSet::default();
                for (orig_v, value, build_tag) in raw {
                    let trimmed = &orig_v[prefix_len..];
                    let mut r = name::to_snake_case(trimmed);
                    if r.is_empty() {
                        r = name::to_snake_case(&orig_v);
                    }
                    if r.is_empty() {
                        r = "variant".to_owned();
                    }
                    if r.starts_with(|c: char| c.is_ascii_digit()) {
                        r.insert(0, '_');
                    }
                    r = name::escape_keyword(&r).into_owned();
                    while !used.insert(r.clone()) {
                        r.push('_');
                    }
                    variants.push(EnumVariant {
                        original_name: orig_v,
                        rust_name: r,
                        value,
                        build_tag,
                    });
                }
                let synthetic_original =
                    format!("{parent_original}::{synthetic_name}").replace("::", "_");
                self.extras.push(TypeDecl::Enum(EnumDecl {
                    original_name: synthetic_original,
                    path: synthetic_path.clone(),
                    underlying: underlying.clone(),
                    variants,
                }));
                Some(AnonSubst {
                    ty: TypeRef::UserDefined(synthetic_path),
                    bit_size: (sizeof(&underlying, self.finder) * 8).min(u16::MAX as u64) as u16,
                })
            },
            _ => None,
        }
    }
}

struct AnonSubst {
    ty: TypeRef,
    bit_size: u16,
}

struct FieldTypeInfo {
    ty: TypeRef,
    bit_size: u16,
    bit_offset_in_field: u32,
    bitfield: Option<BitfieldInfo>,
}

fn collect_enum_raw(
    fl: &FieldList<'_>,
    finder: &ItemFinder<'_, TypeIndex>,
    out: &mut Vec<(String, i128, Option<&'static str>)>,
) {
    for field in &fl.fields {
        if let TypeData::Enumerate(ev) = field {
            let original = ev.name.to_string().into_owned();
            if original.is_empty() {
                continue;
            }
            // Zero-extend within the enum's underlying width before
            // widening to i128, preserving PDB bit patterns
            // (e.g. `0x80000001` in an int32 enum stays `0x80000001`,
            // not `-0x7fffffff`).
            let value = match ev.value {
                pdb::Variant::I8(v) => v as u8 as i128,
                pdb::Variant::U8(v) => v as i128,
                pdb::Variant::I16(v) => v as u16 as i128,
                pdb::Variant::U16(v) => v as i128,
                pdb::Variant::I32(v) => v as u32 as i128,
                pdb::Variant::U32(v) => v as i128,
                pdb::Variant::I64(v) => v as u64 as i128,
                pdb::Variant::U64(v) => v as i128,
            };
            out.push((original, value, None));
        }
    }
    if let Some(cont) = fl.continuation
        && let Ok(item) = finder.find(cont)
        && let Ok(TypeData::FieldList(next)) = item.parse()
    {
        collect_enum_raw(&next, finder, out);
    }
}

// Walk through `Modifier` wrappers to find a `Bitfield`. Returns the
// bitfield descriptor and the index of its underlying integer type.
//
fn peel_bitfield(
    idx: TypeIndex,
    finder: &ItemFinder<'_, TypeIndex>,
) -> Option<(pdb::BitfieldType, TypeIndex)> {
    let mut current = idx;
    for _ in 0..4 {
        let item = finder.find(current).ok()?;
        match item.parse().ok()? {
            TypeData::Bitfield(bf) => return Some((bf, bf.underlying_type)),
            TypeData::Modifier(m) => current = m.underlying_type,
            _ => return None,
        }
    }
    None
}

fn resolve_type(
    idx: TypeIndex,
    finder: &ItemFinder<'_, TypeIndex>,
    default_ns: &str,
) -> Option<TypeRef> {
    let item = finder.find(idx).ok()?;
    let data = item.parse().ok()?;
    Some(resolve_typedata(&data, finder, default_ns))
}

fn resolve_typedata(
    data: &TypeData<'_>,
    finder: &ItemFinder<'_, TypeIndex>,
    default_ns: &str,
) -> TypeRef {
    match data {
        // Primitive with indirection encodes `T*` -- wrap the bare
        // primitive in a `Ref` so the renderers spell `*mut T` / `T*`
        // instead of collapsing to `*mut c_void`.
        TypeData::Primitive(p) => match p.indirection {
            Some(_) => TypeRef::Ref(Box::new(TypeRef::Primitive(primitive_to_rust(p.kind)))),
            None => TypeRef::Primitive(primitive_to_rust(p.kind)),
        },
        TypeData::Pointer(p) => {
            resolve_pointer(p.underlying_type, finder, default_ns, p.attributes.is_volatile())
        },
        // Bare LF_PROCEDURE in a value-position (rare -- usually wrapped
        // in an LF_POINTER which `resolve_pointer` handles).  Lower into
        // `FnPtr` so we don't drop the typing info on the floor.
        TypeData::Procedure(_) => match lower_procedure_data(data, finder, default_ns) {
            Some(sig) => TypeRef::FnPtr(Box::new(sig)),
            None => TypeRef::Pointer,
        },
        // C++ member functions aren't actionable as fn-pointers (need a
        // `this` pointer separately) -- keep them untyped.
        TypeData::MemberFunction(_) => TypeRef::Pointer,
        TypeData::Modifier(m) => {
            let inner =
                resolve_type(m.underlying_type, finder, default_ns).unwrap_or(TypeRef::Opaque(0));
            if m.volatile { TypeRef::Volatile(Box::new(inner)) } else { inner }
        },
        // Class/Union: substitute_native_type wins over the forward-ref
        // guard so wrappers with authoritative size are kept.
        TypeData::Class(c) => {
            let original = c.name.to_string();
            let original = original.as_ref();
            if let Some(sub) = substitute_native_type(original) {
                return sub;
            }
            // Forward-ref decls still have a full definition emitted
            // elsewhere in the unit; classify the name so the field
            // reference targets that header instead of stripping to
            // Opaque. Fall back to Opaque only for templated/qualified
            // names with no per-type header.
            if original.contains('<') || original.contains("::") {
                TypeRef::Opaque(c.size)
            } else {
                // Unprefixed names (no classify() match) bucket under
                // the PDB's own namespace via `fallback_path`, matching
                // what `lower_class` emits.
                let path = name::classify(original)
                    .unwrap_or_else(|| name::fallback_path(default_ns, original));
                TypeRef::UserDefined(path)
            }
        },
        TypeData::Union(u) => {
            let original = u.name.to_string();
            let original = original.as_ref();
            if let Some(sub) = substitute_native_type(original) {
                return sub;
            }
            // Same forward-ref reasoning as TypeData::Class above.
            if original.contains('<') || original.contains("::") {
                TypeRef::Opaque(u.size)
            } else {
                let path = name::classify(original)
                    .unwrap_or_else(|| name::fallback_path(default_ns, original));
                TypeRef::UserDefined(path)
            }
        },
        TypeData::Enumeration(e) if !e.properties.forward_reference() => {
            let original = e.name.to_string();
            let original = original.as_ref();
            if original.contains('<') || original.contains("::") {
                resolve_type(e.underlying_type, finder, default_ns)
                    .unwrap_or(TypeRef::Primitive("i32"))
            } else {
                // Same fallback as Class/Union above; unprefixed enum
                // names resolve via `fallback_path`.
                let path = name::classify(original)
                    .unwrap_or_else(|| name::fallback_path(default_ns, original));
                TypeRef::UserDefined(path)
            }
        },
        TypeData::Array(a) => {
            let elem =
                resolve_type(a.element_type, finder, default_ns).unwrap_or(TypeRef::Opaque(0));
            let total = a.dimensions.last().copied().unwrap_or(0) as u64;
            let elem_size = sizeof(&elem, finder).max(1);
            let count = (total / elem_size) as usize;
            TypeRef::Array { element: Box::new(elem), count }
        },
        TypeData::Bitfield(_) => {
            // Bitfields are emitted as their underlying integer slot -- the
            // bit_offset/bit_size carried by the parent field captures the
            // actual placement; we pick this up via `peel_bitfield`.
            TypeRef::Primitive("u32")
        },
        _ => TypeRef::Opaque(0),
    }
}

// Substitute PDB-native types for our hand-curated wrappers in
// `ntbind::nt::*`.
//
fn substitute_native_type(original: &str) -> Option<TypeRef> {
    // Pure-primitive subs first.
    match original {
        "_LARGE_INTEGER" => return Some(TypeRef::Primitive("i64")),
        "_ULARGE_INTEGER" => return Some(TypeRef::Primitive("u64")),
        _ => {},
    }
    // Structural subs -- paths to hand-curated wrappers.  The Rust side
    // lives in `crates/ntbind/src/nt.rs`; the C++ side is mirrored in
    // `cpp/include/ntbind/`.
    let (rust_path, cpp_path, byte_size): (&'static str, &'static str, u64) = match original {
        "_M128A" => ("::ntbind::nt::M128aT", "m128a_t", 16),
        "_LIST_ENTRY" => ("::ntbind::nt::ListEntryT", "nt::list_entry_t", 16),
        "_KTRAP_FRAME" => ("::ntbind::nt::Trapframe", "nt::trapframe", 0x190),
        "_CONTEXT" => ("::ntbind::nt::Context", "nt::context", 0x4d0),
        "_XSAVE_FORMAT" => ("::ntbind::nt::XsaveFormat", "nt::xsave_format", 0x200),
        "_KEXCEPTION_FRAME" => ("::ntbind::nt::Exframe", "nt::exframe", 0x140),
        "_UNICODE_STRING" | "_CUNICODE_STRING" | "_UNICODE_STRING64" | "_CUNICODE_STRING64" => {
            ("::ntbind::nt::UnicodeView", "nt::unicode_view", 16)
        },
        "_UNICODE_STRING32" | "_CUNICODE_STRING32" => {
            ("::ntbind::nt::UnicodeView32", "nt::unicode_view32", 8)
        },
        "_STRING" | "_CSTRING" | "_STRING64" | "_CSTRING64" => {
            ("::ntbind::nt::AsciiView", "nt::ascii_view", 16)
        },
        "_STRING32" | "_CSTRING32" => ("::ntbind::nt::AsciiView32", "nt::ascii_view32", 8),
        _ => return None,
    };
    Some(TypeRef::External { rust_path, cpp_path, byte_size })
}

fn primitive_bytes(kind: PrimitiveKind) -> u8 {
    match kind {
        PrimitiveKind::Char
        | PrimitiveKind::RChar
        | PrimitiveKind::I8
        | PrimitiveKind::UChar
        | PrimitiveKind::U8
        | PrimitiveKind::Bool8 => 1,
        PrimitiveKind::WChar
        | PrimitiveKind::RChar16
        | PrimitiveKind::Short
        | PrimitiveKind::I16
        | PrimitiveKind::UShort
        | PrimitiveKind::U16
        | PrimitiveKind::Bool16 => 2,
        PrimitiveKind::RChar32
        | PrimitiveKind::Long
        | PrimitiveKind::I32
        | PrimitiveKind::ULong
        | PrimitiveKind::U32
        | PrimitiveKind::Bool32
        | PrimitiveKind::HRESULT
        | PrimitiveKind::F32 => 4,
        PrimitiveKind::Quad
        | PrimitiveKind::I64
        | PrimitiveKind::UQuad
        | PrimitiveKind::U64
        | PrimitiveKind::Bool64
        | PrimitiveKind::F64 => 8,
        _ => 4,
    }
}

fn primitive_is_signed(kind: PrimitiveKind) -> bool {
    matches!(
        kind,
        PrimitiveKind::Char
            | PrimitiveKind::RChar
            | PrimitiveKind::I8
            | PrimitiveKind::Short
            | PrimitiveKind::I16
            | PrimitiveKind::Long
            | PrimitiveKind::I32
            | PrimitiveKind::Quad
            | PrimitiveKind::I64
            | PrimitiveKind::HRESULT
    )
}

fn primitive_to_rust(kind: PrimitiveKind) -> &'static str {
    match kind {
        PrimitiveKind::Void | PrimitiveKind::NoType => "::core::ffi::c_void",
        PrimitiveKind::RChar => "char",
        PrimitiveKind::Char | PrimitiveKind::I8 => "i8",
        PrimitiveKind::UChar | PrimitiveKind::U8 | PrimitiveKind::Bool8 => "u8",
        PrimitiveKind::WChar | PrimitiveKind::RChar16 => "wchar",
        PrimitiveKind::RChar32 => "u32",
        PrimitiveKind::Short | PrimitiveKind::I16 => "i16",
        PrimitiveKind::UShort | PrimitiveKind::U16 | PrimitiveKind::Bool16 => "u16",
        PrimitiveKind::Long | PrimitiveKind::I32 => "i32",
        PrimitiveKind::ULong | PrimitiveKind::U32 | PrimitiveKind::Bool32 => "u32",
        PrimitiveKind::Quad | PrimitiveKind::I64 => "i64",
        PrimitiveKind::UQuad | PrimitiveKind::U64 | PrimitiveKind::Bool64 => "u64",
        PrimitiveKind::Octa | PrimitiveKind::I128 => "i128",
        PrimitiveKind::UOcta | PrimitiveKind::U128 => "u128",
        PrimitiveKind::F32 | PrimitiveKind::F32PP => "f32",
        PrimitiveKind::F64 => "f64",
        PrimitiveKind::HRESULT => "i32",
        PrimitiveKind::F16 => "u16",
        PrimitiveKind::F48 => "u64",
        PrimitiveKind::F80 => "u128",
        PrimitiveKind::F128 => "u128",
        PrimitiveKind::Complex32 => "u64",
        PrimitiveKind::Complex64 => "u128",
        PrimitiveKind::Complex80 => "u128",
        PrimitiveKind::Complex128 => "u128",
        _ => "u64",
    }
}

// Resolve a pointer's pointee.  Class/Union/Enum pointees produce a
// `TypedPointer` carrying a `PointeeKind` for the orphan-stub injector
// to consume.  Procedure pointees produce a `FnPtr(sig)` -- a typed
// function pointer that the renderers can spell as
// `unsafe extern "system" fn(...) -> ret` (Rust) or
// `sdk::function<R(args...)>*` (C++).  Everything else recurses through
// `resolve_type` and wraps the result in `Ref` so primitive pointees
// (`wchar_t*`), pointer-to-pointer (`void**`), and any other non-named
// target keep their pointee shape.
//
// Modifier wrappers (`const T*`, `volatile T*`) are peeled with a small
// bounded loop -- CodeView allows chained `LF_MODIFIER`, though packed
// modifiers normally arrive on a single record.
//
fn resolve_pointer(
    idx: TypeIndex,
    finder: &ItemFinder<'_, TypeIndex>,
    default_ns: &str,
    // CodeView encodes `volatile T*` as either an LF_POINTER with
    // `isvolatile` set in attributes, or LF_POINTER -> LF_MODIFIER
    // (volatile) -> T. Caller passes the former via this flag; the
    // peel loop OR's in the latter.
    pointer_volatile: bool,
) -> TypeRef {
    let Ok(item) = finder.find(idx) else {
        return TypeRef::Pointer;
    };
    let Ok(mut data) = item.parse() else {
        return TypeRef::Pointer;
    };
    // Bounded modifier-peel.  In practice ntoskrnl chains never go
    // beyond depth 1; cap at 4 to guard against pathological PDBs
    // without risking an unbounded loop on a corrupted chain.
    // Track `saw_volatile` so the qualifier survives onto the pointee.
    // `const` is intentionally dropped: it doesn't affect the wire
    // format and consumers don't dispatch on it.
    let mut saw_volatile = pointer_volatile;
    for _ in 0..4 {
        match data {
            TypeData::Modifier(m) => {
                if m.volatile {
                    saw_volatile = true;
                }
                let Ok(inner) = finder.find(m.underlying_type) else {
                    return TypeRef::Pointer;
                };
                let Ok(inner_data) = inner.parse() else {
                    return TypeRef::Pointer;
                };
                data = inner_data;
            },
            _ => break,
        }
    }
    let classify_or_fallback = |original: &str| -> Option<RustPath> {
        if original.contains('<') || original.contains("::") || original.is_empty() {
            return None;
        }
        Some(name::classify(original).unwrap_or_else(|| name::fallback_path(default_ns, original)))
    };
    match data {
        TypeData::Class(c) => {
            let original = c.name.to_string();
            // Native-type substitution wins over PDB-side classification
            // so `_UNICODE_STRING*` etc. render as their wrappers.
            if let Some(sub) = substitute_native_type(original.as_ref()) {
                let inner = if saw_volatile { TypeRef::Volatile(Box::new(sub)) } else { sub };
                return TypeRef::Ref(Box::new(inner));
            }
            match classify_or_fallback(original.as_ref()) {
                Some(path) => TypeRef::TypedPointer {
                    path,
                    kind: crate::ir::PointeeKind::Struct,
                    volatile_pointee: saw_volatile,
                },
                None => TypeRef::Pointer,
            }
        },
        TypeData::Union(u) => {
            let original = u.name.to_string();
            if let Some(sub) = substitute_native_type(original.as_ref()) {
                let inner = if saw_volatile { TypeRef::Volatile(Box::new(sub)) } else { sub };
                return TypeRef::Ref(Box::new(inner));
            }
            match classify_or_fallback(original.as_ref()) {
                Some(path) => TypeRef::TypedPointer {
                    path,
                    kind: crate::ir::PointeeKind::Union,
                    volatile_pointee: saw_volatile,
                },
                None => TypeRef::Pointer,
            }
        },
        TypeData::Enumeration(e) => {
            let original = e.name.to_string();
            match classify_or_fallback(original.as_ref()) {
                Some(path) => TypeRef::TypedPointer {
                    path,
                    kind: crate::ir::PointeeKind::Enum,
                    volatile_pointee: saw_volatile,
                },
                None => TypeRef::Pointer,
            }
        },
        // Pointer-to-function: emit `FnPtr(sig)` directly. Wrapping in
        // `Ref(FnPtr(...))` would render as a double pointer.
        TypeData::Procedure(_) => match lower_procedure_data(&data, finder, default_ns) {
            Some(sig) => TypeRef::FnPtr(Box::new(sig)),
            None => TypeRef::Pointer,
        },
        ref other => {
            let mut inner = resolve_typedata(other, finder, default_ns);
            if saw_volatile {
                inner = TypeRef::Volatile(Box::new(inner));
            }
            TypeRef::Ref(Box::new(inner))
        },
    }
}

// Best-effort byte size of a resolved [`TypeRef`].
//
fn sizeof(r: &TypeRef, _finder: &ItemFinder<'_, TypeIndex>) -> u64 {
    match r {
        TypeRef::Primitive(n) => match *n {
            "i8" | "u8" | "char" => 1,
            "i16" | "u16" | "wchar" => 2,
            "i32" | "u32" | "f32" => 4,
            "i64" | "u64" | "f64" => 8,
            "i128" | "u128" => 16,
            _ => 8,
        },
        TypeRef::Pointer | TypeRef::TypedPointer { .. } | TypeRef::Ref(_) | TypeRef::FnPtr(_) => 8,
        TypeRef::Array { element, count } => sizeof(element, _finder) * *count as u64,
        TypeRef::Opaque(s) => *s,
        TypeRef::UserDefined(_) => 0,
        TypeRef::External { byte_size, .. } => *byte_size,
        // `Volatile(T)` is a qualifier-only wrapper: same layout as T.
        TypeRef::Volatile(inner) => sizeof(inner, _finder),
    }
}

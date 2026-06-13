//! Orchestration -- resolve each entry's identifier to a real address /
//! offset, then write the encrypted payload back into `.symdsc`.
//!
//! Identifier conventions:
//! - `<Type>.<Field>`  -- field offset record (7-byte [`OffsetEntry`]).
//! - `<Type>.$`        -- whole-struct size record (7-byte [`OffsetEntry`]).
//! - `$<Name>$<Image>` -- exported public (17-byte [`PublicEntry`]).

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use ntbind::crypto::encode_decode;
use ntbind::symtbl::{OffsetEntry, PublicEntry};
use pdb::FallibleIterator;

use crate::pe::{PeView, find_symtbl, parse_pe, recompute_checksum};
use crate::walk::{SymTableEntry, walk_entries};

/// One target module -- its file base on the running system + (optionally)
/// the PDB we resolve symbols out of.
pub struct ModuleTarget {
    /// Image hint exactly as embedded in the identifier suffix, e.g.
    /// `"ntoskrnl.exe"`. Case-sensitive match.
    pub hint: String,
    /// Resolved base virtual address of the module on the *target* system.
    pub base: u64,
    /// Optional PDB providing RVA lookups for arbitrary publics. When `None`
    /// the patcher only updates entries whose RVA was baked at generation
    /// time (every public emitted by `ntbindgen` has one), using the original
    /// RVA + base.
    pub pdb_path: Option<std::path::PathBuf>,
}

pub struct PatchOptions {
    pub modules: Vec<ModuleTarget>,
    /// Strip the `.symtbl` index section after walking it; no driver
    /// code reads it at runtime, so dropping it shrinks both the
    /// on-disk `.sys` and committed memory after load.
    pub strip_symtbl: bool,
}

#[derive(Debug, Default)]
pub struct PatchReport {
    pub publics_resolved: usize,
    pub publics_missing: usize,
    pub fields_left_alone: usize,
    /// Bytes removed when `--strip-symtbl` was requested; `0` otherwise.
    pub bytes_stripped: usize,
}

/// Reads `input`, apply [`PatchOptions`], write `output`. Returns a brief
/// report of what was touched.
pub fn run(input: &Path, output: &Path, opts: PatchOptions) -> Result<PatchReport> {
    let mut buf = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let view = parse_pe(&buf).context("parsing PE")?;
    let symtbl =
        find_symtbl(&view).context(".symtbl section missing -- not a ntbind-generated PE?")?;
    let entries = walk_entries(&buf, &view, symtbl)?;
    log::info!("walked {} symtbl entries", entries.len());
    // Per-image RVA tables, loaded lazily.
    let mut rva_tables: HashMap<String, HashMap<String, u32>> = HashMap::new();
    // First-resolved per image (for the sanity-check log).  Captures the
    // base used + the first symbol the loop patched against it so the
    // user can spot-check on the target machine before loading.
    let mut first_sample: HashMap<String, (String, u64, u64)> = HashMap::new();

    let mut report = PatchReport::default();
    for entry in &entries {
        // Field / summary path: identifier doesn't start with `$`.
        if !entry.identifier.starts_with('$') {
            report.fields_left_alone += 1;
            continue;
        }

        // Public: `$<Name>$<Image>`.
        let body = &entry.identifier[1..];
        let Some(sep) = body.find('$') else {
            log::warn!("malformed public identifier: {:?}", entry.identifier);
            report.publics_missing += 1;
            continue;
        };
        let name = &body[..sep];
        let image = &body[sep + 1..];

        let Some(module) = opts.modules.iter().find(|m| m.hint.eq_ignore_ascii_case(image)) else {
            // Patcher would normally bail; instead we leave the entry alone
            // and report -- useful for partial-patch dry runs and for the
            // `auto-modules` path where some referenced images may genuinely
            // not be loaded on the target.
            log::debug!("no target for module {image:?} -- leaving {name:?} untouched");
            report.publics_missing += 1;
            continue;
        };

        // Resolve RVA via per-image table (loaded from PDB on first hit).
        let rva = if let Some(pdb_path) = &module.pdb_path {
            let table = rva_tables.entry(image.to_owned()).or_insert_with(|| {
                load_public_rvas(pdb_path).unwrap_or_else(|e| {
                    log::warn!("failed to read PDB {pdb_path:?}: {e:#}");
                    HashMap::new()
                })
            });
            match table.get(name).copied() {
                Some(r) => r,
                None => {
                    log::debug!("public {name:?} absent in {image:?} PDB");
                    report.publics_missing += 1;
                    continue;
                },
            }
        } else {
            // No PDB -- fall back to the RVA baked at generation time.
            // Decrypt the existing payload to recover it.
            let Some(existing) = read_payload_17(&buf, &view, entry.payload_va, entry.key) else {
                log::warn!("payload for {} is outside any section -- skipping", entry.identifier);
                report.publics_missing += 1;
                continue;
            };
            existing.offset
        };

        let resolved = PublicEntry {
            virtual_address: module.base + rva as u64,
            offset: rva,
            sys_idx: 0,
            exists: 1,
        };
        let new_bytes = encode_decode::<17>(resolved.to_bytes(), entry.key);
        if let Some(off) = file_offset_for_va(&view, entry.payload_va) {
            buf[off..off + 17].copy_from_slice(&new_bytes);
            report.publics_resolved += 1;
            first_sample
                .entry(image.to_ascii_lowercase())
                .or_insert_with(|| (name.to_owned(), module.base, resolved.virtual_address));
        } else {
            log::warn!(
                "VA 0x{:x} for {} maps outside any section",
                entry.payload_va,
                entry.identifier
            );
            report.publics_missing += 1;
        }
    }

    if !first_sample.is_empty() {
        let mut rows: Vec<(&String, &(String, u64, u64))> = first_sample.iter().collect();
        rows.sort_by(|a, b| a.0.cmp(b.0));
        log::info!("sample resolutions (verify against the target system before loading):");
        for (image, (name, base, va)) in rows {
            log::info!("  {image}!{name} -> 0x{va:x}  (base 0x{base:x} + rva 0x{:x})", va - base);
        }
    }

    if opts.strip_symtbl {
        // Re-parse to refresh section offsets after any payload writes
        // (no offsets shifted, but keep this explicit).
        let removed = crate::pe::strip_symtbl_section(&mut buf)
            .context("stripping .symtbl after patching")?;
        report.bytes_stripped = removed;
        log::info!("stripped .symtbl: {removed} bytes removed");
    }

    // Re-derive checksum field offset against the (possibly shorter)
    // buffer: only the section table moves on strip, never the
    // optional-header CheckSum.  Reusing the original offset is safe.
    recompute_checksum(&mut buf, view.checksum_field_off)?;
    std::fs::write(output, &buf).with_context(|| format!("writing {}", output.display()))?;
    Ok(report)
}

fn file_offset_for_va(view: &PeView, va: u64) -> Option<usize> {
    view.sections
        .iter()
        .find(|s| s.contains_va(view.image_base, va))?
        .va_to_file_offset(view.image_base, va)
}

fn read_payload_17(buf: &[u8], view: &PeView, va: u64, key: u64) -> Option<PublicEntry> {
    let off = file_offset_for_va(view, va)?;
    if off + 17 > buf.len() {
        return None;
    }
    let encrypted: [u8; 17] =
        buf[off..off + 17].try_into().expect("bounds-checked slice -> fixed-size array");
    let plain = encode_decode::<17>(encrypted, key);
    Some(PublicEntry::from_bytes(plain))
}

// Load (name -> RVA) for every public the PDB knows about.
fn load_public_rvas(pdb_path: &Path) -> Result<HashMap<String, u32>> {
    let file = std::fs::File::open(pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;
    // Apply any OMAP the linker emitted: `p.offset.offset` alone is
    // the segment-relative offset, not the image RVA.
    let address_map = pdb.address_map().context("reading PDB address map")?;
    let globals = pdb.global_symbols()?;
    let mut iter = globals.iter();
    let mut out = HashMap::new();
    while let Some(sym) = iter.next()? {
        if let Ok(pdb::SymbolData::Public(p)) = sym.parse() {
            let Some(rva) = p.offset.to_rva(&address_map) else { continue };
            let name = p.name.to_string().into_owned();
            out.entry(name).or_insert(rva.0);
        }
    }
    Ok(out)
}

#[allow(dead_code)] // future: implement offset patching
fn rewrite_offset_entry(buf: &mut [u8], entry: &SymTableEntry, off_bits: u32, sz: u16) {
    let payload = OffsetEntry::new(off_bits, sz, true);
    let new_bytes = encode_decode::<7>(payload.to_bytes(), entry.key);
    // file_offset_for_va via reverse lookup is the caller's responsibility.
    let _ = (buf, new_bytes);
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::load_public_rvas;
    use crate::pe::{Section, parse_pe};

    // `loaded_user_modules()` enumerates the patcher's own DLLs.
    // Every Windows process has `ntdll.dll` loaded, so it must appear
    // in the result with a non-zero, high-half kernel-or-user VA.
    //
    // Skipped on non-Windows hosts.
    #[cfg(windows)]
    #[test]
    fn loaded_user_modules_includes_ntdll() -> anyhow::Result<()> {
        let modules = crate::discover::loaded_user_modules()?;
        assert!(!modules.is_empty(), "no user-mode modules enumerated");
        let ntdll = modules.get("ntdll.dll").copied();
        assert!(ntdll.is_some(), "ntdll.dll missing from user-mode enumeration: {modules:?}");
        let base = ntdll.unwrap();
        assert!(base != 0, "ntdll.dll base is zero");
        // User-mode loads sit in low canonical range; just sanity-check
        // it's not an obviously-stomped value.
        assert!(base < 0x0001_0000_0000_0000, "ntdll.dll base {base:#x} outside user-mode range");
        Ok(())
    }

    // Cross-checks `load_public_rvas` against the export table of the
    // matching `.exe`.  This is the test that would have caught the
    // missing `to_rva(&address_map)` call: without the address-map
    // conversion, PDB-side RVAs are off by the `.text` section's base
    // and disagree with the EXE export table.
    //
    // Skipped (returns `Ok`) on hosts that don't have
    // `C:\Windows\System32\ntoskrnl.exe` *and* a checked-in
    // `symbols/ntkrnlmp.pdb` matching it.  Run locally after
    // downloading the host's PDB via the GUID from the CodeView
    // debug record (see README).
    #[test]
    fn pdb_rvas_match_local_ntoskrnl_exports() -> anyhow::Result<()> {
        let kernel = Path::new(r"C:\Windows\System32\ntoskrnl.exe");
        let pdb = Path::new("../../symbols/ntkrnlmp.pdb");
        if !kernel.exists() || !pdb.exists() {
            return Ok(());
        }

        let pdb_rvas = load_public_rvas(pdb)?;
        let kernel_bytes = std::fs::read(kernel)?;
        let view = parse_pe(&kernel_bytes)?;
        let exports = parse_exports(&kernel_bytes, &view.sections)?;

        // A small spread of always-exported well-known symbols.  Any
        // single mismatch is a real bug -- a one-off skipped symbol
        // (PDB-only / EXE-only) would already have been filtered out
        // by the for-each-shared-name comparison below.
        let candidates = [
            "DbgPrint",
            "DbgPrintEx",
            "KeBugCheckEx",
            "IoCreateDevice",
            "IoDeleteDevice",
            "ExAllocatePool2",
            "PsLookupProcessByProcessId",
        ];
        let mut compared = 0usize;
        for name in candidates {
            let (Some(&pdb_rva), Some(&exp_rva)) = (pdb_rvas.get(name), exports.get(name)) else {
                continue;
            };
            assert_eq!(
                pdb_rva, exp_rva,
                "{name}: PDB says 0x{pdb_rva:x}, export table says 0x{exp_rva:x}"
            );
            compared += 1;
        }
        assert!(compared >= 3, "expected at least 3 well-known symbols, compared {compared}");
        Ok(())
    }

    // Minimal export-table reader: pulls `{name => rva}` out of a PE.
    fn parse_exports(
        buf: &[u8],
        sections: &[Section],
    ) -> anyhow::Result<std::collections::HashMap<String, u32>> {
        use anyhow::bail;

        let mut out = std::collections::HashMap::new();
        let e_lfanew = u32::from_le_bytes(buf[0x3C..0x40].try_into()?) as usize;
        let coff = e_lfanew + 4;
        let opt = coff + 20;
        let magic = u16::from_le_bytes(buf[opt..opt + 2].try_into()?);
        let is_pe64 = match magic {
            0x10B => false,
            0x20B => true,
            _ => bail!("unknown optional header magic"),
        };
        let dd = opt + if is_pe64 { 112 } else { 96 };
        let (export_rva, _) = (
            u32::from_le_bytes(buf[dd..dd + 4].try_into()?),
            u32::from_le_bytes(buf[dd + 4..dd + 8].try_into()?),
        );
        if export_rva == 0 {
            return Ok(out);
        }

        let rva_to_off = |rva: u32| -> Option<usize> {
            sections
                .iter()
                .find(|s| s.virtual_address <= rva && rva < s.virtual_address + s.raw_size)
                .map(|s| s.raw_pointer as usize + (rva - s.virtual_address) as usize)
        };

        let exp = rva_to_off(export_rva)
            .ok_or_else(|| anyhow::anyhow!("export RVA outside any section"))?;
        let num_funcs = u32::from_le_bytes(buf[exp + 0x14..exp + 0x18].try_into()?);
        let num_names = u32::from_le_bytes(buf[exp + 0x18..exp + 0x1C].try_into()?);
        let addr_funcs_rva = u32::from_le_bytes(buf[exp + 0x1C..exp + 0x20].try_into()?);
        let addr_names_rva = u32::from_le_bytes(buf[exp + 0x20..exp + 0x24].try_into()?);
        let addr_ordinals_rva = u32::from_le_bytes(buf[exp + 0x24..exp + 0x28].try_into()?);
        let af = rva_to_off(addr_funcs_rva)
            .ok_or_else(|| anyhow::anyhow!("AddressOfFunctions outside section"))?;
        let an = rva_to_off(addr_names_rva)
            .ok_or_else(|| anyhow::anyhow!("AddressOfNames outside section"))?;
        let ao = rva_to_off(addr_ordinals_rva)
            .ok_or_else(|| anyhow::anyhow!("AddressOfNameOrdinals outside section"))?;

        for i in 0..num_names as usize {
            let name_rva = u32::from_le_bytes(buf[an + i * 4..an + i * 4 + 4].try_into()?);
            let ord = u16::from_le_bytes(buf[ao + i * 2..ao + i * 2 + 2].try_into()?) as usize;
            if ord >= num_funcs as usize {
                continue;
            }
            let fn_rva = u32::from_le_bytes(buf[af + ord * 4..af + ord * 4 + 4].try_into()?);
            let name_off =
                rva_to_off(name_rva).ok_or_else(|| anyhow::anyhow!("name RVA outside section"))?;
            let end = buf[name_off..].iter().position(|&c| c == 0).unwrap_or(0);
            let name = std::str::from_utf8(&buf[name_off..name_off + end])?.to_owned();
            out.insert(name, fn_rva);
        }
        Ok(out)
    }
}

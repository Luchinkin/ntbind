//! `ntbind-patch` CLI -- patches `.symtbl`-bearing PEs against a target
//! system.  See `--help` for invocation details.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use ntbind_patch::patch::{ModuleTarget, PatchOptions, run};

#[derive(Parser, Debug)]
#[command(name = "ntbind-patch", about = "Patch a ntbind-generated PE's symbol table.")]
struct Args {
    /// Source PE (driver, DLL, or EXE) carrying a `.symtbl` section.
    #[arg(long)]
    input: PathBuf,
    /// Destination path for the patched output. Pass the same path twice
    /// to overwrite in place after a backup.
    #[arg(long)]
    output: PathBuf,
    /// Module base address override. Repeatable -- one per loaded image.
    /// Format: `<image>=<hex>`, e.g. `--module ntoskrnl.exe=0xfffff80012345000`.
    /// Wins over `--auto-modules` for the same image.
    #[arg(long, value_parser = parse_module_arg)]
    module: Vec<ModuleArg>,
    /// PDB to use for resolving an image's publics.
    /// Format: `<image>=<path>`, repeatable.
    #[arg(long, value_parser = parse_pdb_arg)]
    pdb: Vec<PdbArg>,
    /// Auto-detect module bases by enumerating loaded modules.  Two
    /// sets are merged: kernel-mode drivers via `EnumDeviceDrivers`
    /// (covers `ntoskrnl.exe`, `hal.dll`, loaded `.sys` modules) and
    /// user-mode modules in the patcher's own process via
    /// `EnumProcessModulesEx` (covers `ntdll.dll`, `kernel32.dll`,
    /// any DLL the patcher itself has loaded).  Useful when the
    /// patcher runs on the target system; pairs naturally with
    /// `--strip-symtbl`.  Windows-only.
    #[arg(long)]
    auto_modules: bool,
    /// Walk the input's `.symtbl`, print which images its publics
    /// reference (with per-module symbol counts), then exit without
    /// writing any output.  Helpful for figuring out which `--module`
    /// rows you need.
    #[arg(long)]
    list_modules: bool,
    /// Strip `.symtbl` from the patched image once every entry has
    /// been resolved.  No driver code reads `.symtbl` at runtime --
    /// each `.symdsc` cell is referenced directly by its accessor's
    /// static.  Removing the section shrinks both the on-disk `.sys`
    /// and its committed memory after load.
    #[arg(long)]
    strip_symtbl: bool,
}

#[derive(Clone, Debug)]
struct ModuleArg {
    image: String,
    base: u64,
}

#[derive(Clone, Debug)]
struct PdbArg {
    image: String,
    path: PathBuf,
}

fn parse_module_arg(raw: &str) -> Result<ModuleArg, String> {
    let (image, base) =
        raw.split_once('=').ok_or_else(|| format!("expected <image>=<base>, got {raw:?}"))?;
    let base = parse_hex_or_dec(base.trim())
        .ok_or_else(|| format!("could not parse base address {base:?}"))?;
    Ok(ModuleArg { image: image.trim().to_owned(), base })
}

fn parse_pdb_arg(raw: &str) -> Result<PdbArg, String> {
    let (image, path) =
        raw.split_once('=').ok_or_else(|| format!("expected <image>=<path>, got {raw:?}"))?;
    Ok(PdbArg { image: image.trim().to_owned(), path: PathBuf::from(path.trim()) })
}

fn parse_hex_or_dec(s: &str) -> Option<u64> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    // Pre-scan the input's .symtbl so the rest of the flow knows which
    // images the publics actually reference -- list-modules prints
    // them, auto-modules narrows the OS lookup to that set, and the
    // missing-module warning shows the user what to supply.
    let referenced = read_referenced_modules(&args.input)?;

    if args.list_modules {
        print_module_list(&referenced);
        return Ok(());
    }

    // Combine --module / --pdb into ModuleTarget rows.  PDBs without a
    // matching module are warned about and dropped (no payload).
    let mut modules: Vec<ModuleTarget> = Vec::new();
    for ModuleArg { image, base } in &args.module {
        let pdb_path =
            args.pdb.iter().find(|p| p.image.eq_ignore_ascii_case(image)).map(|p| p.path.clone());
        modules.push(ModuleTarget { hint: image.clone(), base: *base, pdb_path });
    }
    for p in &args.pdb {
        if !modules.iter().any(|m| m.hint.eq_ignore_ascii_case(&p.image)) {
            log::warn!("--pdb {}=... has no matching --module; ignored", p.image);
        }
    }

    if args.auto_modules {
        merge_auto_modules(&mut modules, &referenced, &args.pdb)?;
    }

    warn_unresolved_modules(&referenced, &modules);

    let report =
        run(&args.input, &args.output, PatchOptions { modules, strip_symtbl: args.strip_symtbl })
            .with_context(|| format!("patching {:?} -> {:?}", args.input, args.output))?;

    log::info!(
        "publics resolved: {}, missing: {}, fields untouched: {}, bytes stripped: {}",
        report.publics_resolved,
        report.publics_missing,
        report.fields_left_alone,
        report.bytes_stripped
    );
    Ok(())
}

// Reads the input PE's `.symtbl` and returns `{image => symbol_count}`.
fn read_referenced_modules(
    input: &std::path::Path,
) -> Result<std::collections::HashMap<String, usize>> {
    use ntbind_patch::pe::{find_symtbl, parse_pe};
    use ntbind_patch::walk::{referenced_modules, walk_entries};

    let buf = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let view = parse_pe(&buf).context("parsing input PE")?;
    let symtbl =
        find_symtbl(&view).context(".symtbl section missing -- not a ntbind-generated PE?")?;
    let entries = walk_entries(&buf, &view, symtbl)?;
    Ok(referenced_modules(&entries))
}

#[allow(clippy::print_stdout, reason = "--list-modules writes a human-facing report to stdout")]
fn print_module_list(referenced: &std::collections::HashMap<String, usize>) {
    if referenced.is_empty() {
        println!("(no publics in input .symtbl)");
        return;
    }
    let mut rows: Vec<(&String, &usize)> = referenced.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let total: usize = rows.iter().map(|(_, c)| *c).sum();
    println!("referenced modules ({} symbols across {} images):", total, rows.len());
    for (image, count) in rows {
        println!("  {image:<24} {count:>6} symbols");
    }
}

// Folds auto-discovered driver bases into `modules` for every
// referenced image not already covered by an explicit `--module`.
// Auto-found entries inherit any matching `--pdb` row.
fn merge_auto_modules(
    modules: &mut Vec<ModuleTarget>,
    referenced: &std::collections::HashMap<String, usize>,
    pdbs: &[PdbArg],
) -> Result<()> {
    // Probe both kernel-mode drivers and user-mode modules in our own
    // process; a referenced image lives in exactly one of the two.
    let kernel = ntbind_patch::discover::loaded_drivers()
        .map_err(|e| log::warn!("kernel-mode enumeration: {e}"))
        .unwrap_or_default();
    let user = ntbind_patch::discover::loaded_user_modules()
        .map_err(|e| log::warn!("user-mode enumeration: {e}"))
        .unwrap_or_default();
    log::info!(
        "auto-modules: {} kernel-mode, {} user-mode module(s) loaded",
        kernel.len(),
        user.len()
    );
    let mut added = 0usize;
    for image in referenced.keys() {
        if modules.iter().any(|m| m.hint.eq_ignore_ascii_case(image)) {
            continue;
        }
        let key = image.to_ascii_lowercase();
        let Some(&base) = kernel.get(&key).or_else(|| user.get(&key)) else { continue };
        let pdb_path =
            pdbs.iter().find(|p| p.image.eq_ignore_ascii_case(image)).map(|p| p.path.clone());
        log::info!("auto-modules: {image} = 0x{base:x}");
        modules.push(ModuleTarget { hint: image.clone(), base, pdb_path });
        added += 1;
    }
    log::info!("auto-modules: {added} added");
    Ok(())
}

fn warn_unresolved_modules(
    referenced: &std::collections::HashMap<String, usize>,
    modules: &[ModuleTarget],
) {
    let mut unresolved: Vec<(&String, &usize)> = referenced
        .iter()
        .filter(|(image, _)| !modules.iter().any(|m| m.hint.eq_ignore_ascii_case(image)))
        .collect();
    if unresolved.is_empty() {
        return;
    }
    unresolved.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let total: usize = unresolved.iter().map(|(_, c)| *c).sum();
    log::warn!(
        "{total} symbol(s) across {} module(s) have no --module mapping and will be left unpatched:",
        unresolved.len()
    );
    for (image, count) in unresolved {
        log::warn!("  {image:<24} {count:>6} symbols");
    }
}

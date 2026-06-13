//! ntbindgen -- turn Windows PDBs into a Rust + C++ SDK.
//!
//! Pipeline:
//!   1. `config`      -- which build x PDB -> which namespace.
//!   2. `pdb_io`     -- read TPI types and DBI publics for one PDB.
//!   3. `merge`       -- fold per-build loads into one canonical unit per ns.
//!   4. `name`        -- PDB name transform (`_KI_FOO` -> `ki::foo_t`).
//!   5. `emit::rust`  -- per-type/per-namespace Rust source.
//!   6. `emit::cpp`   -- per-type/per-namespace C++ headers.
//!
//! `--target` picks one or both backends.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use ntbindgen::{config, emit, ir, merge, pdb_io};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CliTarget {
    Rust,
    Cpp,
    Both,
}

#[derive(Debug, Parser)]
#[command(name = "ntbindgen", about = "Generate Rust + C++ kernel SDKs from Windows PDBs.")]
struct Args {
    /// Root directory holding PDBs.  The default layout puts each PDB
    /// directly under this path (no per-build subdirs); extend
    /// `config::BUILDS` and use per-build `path_suffix` values when
    /// ingesting multiple Windows revisions for cross-build merging.
    #[arg(long)]
    symbols: PathBuf,
    /// Destination directory. For `--target rust` this becomes the SDK
    /// crate root (Cargo.toml + src/). For `--target cpp` it becomes the
    /// include root (we write `<out>/include/ntbind/...`). For `--target
    /// both` we emit a Rust crate under `<out>/rust` and a C++ tree under
    /// `<out>/cpp`.
    #[arg(long)]
    out: PathBuf,
    /// Limit to a single PDB (matches the `path` field in `config::PDB_ENTRIES`).
    #[arg(long)]
    only: Option<String>,
    /// Skips emission of per-namespace publics files. Cuts generation and
    /// downstream compile time massively while iterating on type lowering --
    /// `ntkrnlmp.pdb` has 40k+ publics.
    #[arg(long)]
    no_publics: bool,
    /// Ships the symbol table in plaintext -- no XOR-LCG cipher.
    /// Every cell's key becomes `0`, making `.symdsc` payloads
    /// readable byte-for-byte and the runtime decode collapse to
    /// `read_volatile`.  Simplifies post-processing at the cost of
    /// trivial inspectability of resolved addresses.
    #[arg(long)]
    no_encrypt: bool,
    /// Restrict to one named build (e.g. `--build win10_20h2`). Useful for
    /// iteration when only one build's symbols are on disk.
    #[arg(long)]
    build: Option<String>,
    /// Outputs target. Default: rust.
    #[arg(long, value_enum, default_value_t = CliTarget::Rust)]
    target: CliTarget,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    if !args.symbols.is_dir() {
        anyhow::bail!("--symbols must point at an existing directory: {:?}", args.symbols);
    }
    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("creating output dir {:?}", args.out))?;

    let opts = emit::EmitOptions { publics: !args.no_publics, no_encrypt: args.no_encrypt };

    // Determine which builds we will iterate. Builds that don't have a
    // matching subdirectory on disk are skipped (but logged), so partial
    // symbol sets still work.
    let candidate_builds: Vec<config::BuildEntry> = config::BUILDS
        .iter()
        .copied()
        .filter(|b| match &args.build {
            Some(filter) => b.name.eq_ignore_ascii_case(filter),
            None => true,
        })
        .filter(|b| {
            let p = args.symbols.join(b.path_suffix);
            if p.is_dir() {
                true
            } else {
                log::info!("skip build {} (no dir at {:?})", b.name, p);
                false
            }
        })
        .collect();

    if candidate_builds.is_empty() {
        anyhow::bail!("no builds available under {:?}", args.symbols);
    }

    // Single-build legacy mode: if exactly one build is present, also fall
    // back to looking for PDBs directly in --symbols. This keeps `--symbols
    // "<...>\Win10 20H2 Symbols"` working alongside the new layered layout.
    let single_build_flat =
        candidate_builds.len() == 1 && !args.symbols.join(candidate_builds[0].path_suffix).is_dir();

    let mut loaded: Vec<merge::LoadedBuild> = Vec::new();
    for build in &candidate_builds {
        let build_root = if single_build_flat {
            args.symbols.clone()
        } else {
            args.symbols.join(build.path_suffix)
        };
        for entry in config::PDB_ENTRIES {
            if let Some(filter) = &args.only
                && !entry.path.eq_ignore_ascii_case(filter)
            {
                continue;
            }
            let pdb_path = build_root.join(entry.path);
            if !pdb_path.exists() {
                log::warn!("skip {} ({}): {:?} not found", build.name, entry.ns_tag, pdb_path);
                continue;
            }
            log::info!("loading {}/{} from {:?}", build.name, entry.ns_tag, pdb_path);

            let unit = pdb_io::load_unit(entry, &pdb_path)
                .with_context(|| format!("parsing {:?}", pdb_path))?;
            log::info!("  {} types, {} publics", unit.types.len(), unit.publics.len());
            loaded.push(merge::LoadedBuild { build: *build, unit });
        }
    }

    if loaded.is_empty() {
        anyhow::bail!("no PDBs loaded -- check --symbols layout");
    }

    log::info!("merging {} (build, PDB) load(s) across builds", loaded.len());
    let mut merged = merge::merge_builds(loaded);
    log::info!("post-merge: {} namespace(s)", merged.len());

    // Inject opaque stubs for typed-pointer pointees the kernel doesn't
    // expose as full TPI definitions. Idempotent -- re-runs are a no-op
    // because the stubs themselves become part of the emitted set.
    let before = merged.iter().map(|n| n.types.len()).sum::<usize>();
    emit::common::inject_orphan_stubs(&mut merged);
    let after = merged.iter().map(|n| n.types.len()).sum::<usize>();
    log::info!("orphan-pointee stubs injected: {}", after - before);

    if opts.no_encrypt {
        // Plaintext mode -- zero every entry key so the generated
        // macros baseline the cipher to a no-op (and the patcher
        // does the same when it rewrites a VA).
        for ns in &mut merged {
            for p in &mut ns.publics {
                p.key = 0;
            }
            for t in &mut ns.types {
                if let ir::TypeDecl::Struct(s) | ir::TypeDecl::Union(s) = t {
                    s.summary_key = 0;
                    for f in &mut s.fields {
                        f.key = 0;
                    }
                }
            }
        }
        log::info!("plain-text mode: all cell keys zeroed");
    }

    // Dispatch to the requested backend(s).
    let backends: &[(emit::Target, PathBuf)] = match args.target {
        CliTarget::Rust => &[(emit::Target::Rust, args.out.clone())],
        CliTarget::Cpp => &[(emit::Target::Cpp, args.out.clone())],
        CliTarget::Both => &[
            (emit::Target::Rust, args.out.join("rust")),
            (emit::Target::Cpp, args.out.join("cpp")),
        ],
    };
    for (target, root) in backends {
        emit_for(target, &merged, root, opts)?;
    }

    Ok(())
}

fn emit_for(
    target: &emit::Target,
    namespaces: &[merge::MergedNamespace],
    root: &Path,
    opts: emit::EmitOptions,
) -> Result<()> {
    std::fs::create_dir_all(root)?;
    for ns in namespaces {
        emit::write_unit(ns, root, opts, *target)
            .with_context(|| format!("emitting {} ({:?})", ns.default_ns, target))?;
    }
    emit::finalize(root, namespaces, *target).context("finalizing target tree")?;
    Ok(())
}

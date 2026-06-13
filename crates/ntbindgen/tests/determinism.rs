//! Determinism + rustdoc smoke tests for the full ntbindgen pipeline.
//!
//! These are slow (~30 s each) so they're gated on a `NTBINDGEN_E2E=1`
//! environment variable. Run with:
//! ```text
//! NTBINDGEN_E2E=1 cargo test -p ntbindgen --test determinism -- --nocapture
//! ```
//! Without the env var both tests `assert!(true)` and return -- keeps `cargo
//! test` cheap by default while making the slow path explicit for CI.
//!
//! The tests delegate to the built `ntbindgen` binary (no library re-entry),
//! which exercises the same `clap` parsing path users hit.
//!
//! They need a PDB to ingest. We pick up `NTBINDGEN_TEST_SYMBOLS` (the env
//! var the harness sets); without it the tests skip. Skip notices use
//! `eprintln!` to surface to the test harness when no PDB set is
//! available.

// eprintln! is fine in integration tests that need to print skip
// reasons and progress for the harness.
//
#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::process::Command;

fn enabled() -> bool {
    std::env::var_os("NTBINDGEN_E2E").is_some()
}

fn symbols_dir() -> Option<PathBuf> {
    std::env::var_os("NTBINDGEN_TEST_SYMBOLS").map(PathBuf::from)
}

fn ntbindgen_binary() -> PathBuf {
    // `cargo test` puts the built bin under target/debug or target/release.
    // We rely on `cargo run --release -p ntbindgen` instead of locating the
    // binary directly -- that way the test re-uses any cached release build.
    PathBuf::from("cargo")
}

fn run_ntbindgen(out: &std::path::Path, symbols: &std::path::Path) {
    // CARGO_MANIFEST_DIR is `crates/ntbindgen`. Workspace root is its
    // grandparent. The ntbind crate lives at `<workspace>/crates/ntbind`.
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent().and_then(|p| p.parent()).unwrap();
    let ntbind_path = workspace.join("crates").join("ntbind");
    let status = Command::new(ntbindgen_binary())
        .args(["run", "--release", "-p", "ntbindgen", "--", "--symbols"])
        .arg(symbols)
        .args(["--out"])
        .arg(out)
        .args(["--only", "ntkrnlmp.pdb", "--no-publics"])
        .env("NTBIND_CRATE_PATH", ntbind_path)
        .status()
        .expect("running ntbindgen");
    assert!(status.success(), "ntbindgen exit status {status:?}");
}

#[test]
fn output_is_byte_identical_across_runs() {
    if !enabled() {
        eprintln!("set NTBINDGEN_E2E=1 to enable this test");
        return;
    }
    let Some(symbols) = symbols_dir() else {
        eprintln!("no symbols dir found -- skipping");
        return;
    };
    let pid = std::process::id();
    let a = std::env::temp_dir().join(format!("ntbindgen_det_a_{pid}"));
    let b = std::env::temp_dir().join(format!("ntbindgen_det_b_{pid}"));
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
    run_ntbindgen(&a, &symbols);
    run_ntbindgen(&b, &symbols);

    diff_trees(&a, &b);
    eprintln!("determinism: a={a:?}, b={b:?}");
}

#[test]
fn generated_sdk_passes_cargo_doc() {
    if !enabled() {
        eprintln!("set NTBINDGEN_E2E=1 to enable this test");
        return;
    }
    let Some(symbols) = symbols_dir() else {
        eprintln!("no symbols dir found -- skipping");
        return;
    };
    let out = std::env::temp_dir().join(format!("ntbindgen_doc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    run_ntbindgen(&out, &symbols);

    let status = Command::new("cargo")
        .current_dir(&out)
        .args(["doc", "--no-deps"])
        .status()
        .expect("running cargo doc");
    assert!(status.success(), "cargo doc exit status {status:?}");
}

// Walk two trees and assert every file path + bytes match.
fn diff_trees(a: &std::path::Path, b: &std::path::Path) {
    let mut a_files = collect(a);
    let mut b_files = collect(b);
    a_files.sort();
    b_files.sort();
    assert_eq!(a_files, b_files, "different file sets across two runs");
    for rel in &a_files {
        let ab = std::fs::read(a.join(rel)).unwrap();
        let bb = std::fs::read(b.join(rel)).unwrap();
        assert_eq!(
            ab,
            bb,
            "byte mismatch in {rel:?}\n  a={:?}\n  b={:?}",
            a.join(rel),
            b.join(rel)
        );
    }
}

fn collect(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(root: &std::path::Path, here: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(here) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_path_buf();
                out.push(rel);
            }
        }
    }
    walk(root, root, &mut out);
    out
}

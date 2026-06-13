# ntbind

Windows kernel SDK generator.  Reads Microsoft PDBs and emits either a
Rust crate or a C++ header tree of type accessors.  Field offsets and
kernel-symbol addresses are resolved at deploy time by a post-link
patcher (`ntbind-patch`), so one compiled driver targets every Windows
build the patcher has a PDB for.

## Repository layout

```
crates/
  ntbind/             Rust runtime: field!/public! macros, types
  ntbindgen/          generator binary: PDB -> Rust crate or C++ headers
  ntbind-patch/       post-link symbol resolver
examples/
  sample-driver/      minimal .sys driver linking the generated SDK
cpp/include/ntbind/   C++ runtime headers
```

## Quickstart

```pwsh
$SYMBOLS = "I:\path\to\symbols"   # holds ntkrnlmp.pdb etc. directly

# Generate the SDK.
cargo run --release -p ntbindgen -- --symbols $SYMBOLS --out sdk --only ntkrnlmp.pdb

# Build the sample driver.
cd examples\sample-driver
cargo -Z json-target-spec build --release
cd ..\..

# Patch against the target system (run on the target, or pass --pdb
# for cross-machine patching).
cargo run --release -p ntbind-patch -- `
    --input  examples\sample-driver\target\x86_64-pc-windows-driver\release\sample_driver.sys `
    --output examples\sample-driver\target\x86_64-pc-windows-driver\release\sample_driver.patched.sys `
    --auto-modules `
    --strip-symtbl
```

## Targets

`ntbindgen --target rust|cpp|both` selects the backend.

- **rust** (default): self-contained Cargo crate; one `.rs` per PDB
  type.  Field offsets go through `ntbind::field!` accessors.
- **cpp**: an `<out>/include/ntbind/<ns>/` header tree.  Each `.hpp`
  is paired with a `magic/<type>.start.hpp` / `.end.hpp` shim.
  Consuming the generated C++ SDK requires `xstd` on the include
  path alongside the runtime headers under `cpp/include/ntbind/`.
  On vanilla clang the runtime's `__builtin_symbol_read*` calls
  resolve through a pure-C++ fallback in `cpp/include/ntbind/common.hpp`;
  a patched LLVM toolchain replaces the fallback with intrinsic
  symbol-table reads (one MOVQ + XOR per access).
- **both**: writes `<out>/rust/` and `<out>/cpp/` side by side.

## Patching a driver or DLL

`ntbind-patch` walks the binary's symbol table, looks up the runtime
address of each referenced module, and writes it back into the image.
Works for both kernel-mode drivers and user-mode DLLs/EXEs.  Flags:

- `--module <image>=<base>`: load address of `<image>` on the *target*
  system.  Repeat per image.  Wins over `--auto-modules` for the same
  image.
- `--auto-modules`: enumerate loaded modules on the running system and
  fill in `--module` for every image the binary references that wasn't
  supplied explicitly.  Two sets are merged: kernel-mode drivers
  (`ntoskrnl.exe`, `hal.dll`, every loaded `.sys`) via
  `EnumDeviceDrivers`, and user-mode modules in the patcher's own
  process (`ntdll.dll`, `kernel32.dll`, any DLL the patcher has
  loaded) via `EnumProcessModulesEx`.
- `--list-modules`: print which images the binary references (with
  per-module symbol counts) and exit.
- `--pdb <image>=<path>`: PDB for `<image>` on the target build.
  Optional; supplies a build-specific RVA lookup.  Without a PDB the
  patcher reuses the RVA the generator baked in, which is correct only
  when the target runs the same build the SDK was generated from.
- `--strip-symtbl`: removes the symbol-table index section from the
  patched image.  Recommended for production -- shrinks both disk size
  and committed memory by roughly the section's raw size.

A "sample resolutions" log line prints one resolved `(image, symbol,
va)` per module -- verify it against the target system before loading.

For user-mode targets where the binary references DLLs the patcher
itself hasn't loaded (`d3d11.dll`, `win32u.dll`, anything outside the
patcher's import graph), use `--module <image>=<base>` explicitly --
`--auto-modules` only sees what the patcher process has mapped.

## Getting the matching PDB

For each module the SDK targets, pull the PDB that matches the
*target* system's build:

1. Read the CodeView `RSDS` record from the target module (debug
   directory entry of type 2) for its PDB GUID + age.
2. `https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><age>/<pdb>`
3. Drop the PDB into the `--symbols` directory, regenerate the SDK,
   rebuild the consuming binary.

New modules are registered in `crates/ntbindgen/src/config.rs` via
the `PdbEntry` table -- each entry maps a PDB filename to its
namespace tag and the `hint_image` (the runtime DLL/EXE that hosts
its publics).

## Writing a driver

`examples/sample-driver/` is the reference template.  It builds as a
NATIVE-subsystem `.sys` against the generated SDK, calls `DbgPrint`
through `nt::api::dbg_print`, and walks the kernel active-process
list through the SDK accessors.  The two pieces worth keeping when
porting to a real target are the `DbgPrint3` ABI shim and
`resolve_dbg_print`; the process-walk body is illustrative.

A new driver crate's `Cargo.toml` should mirror the sample's: a
`cdylib` crate type, `panic = "abort"`, `ntbind` and the generated SDK
crate as dependencies, and the kernel-mode link flags in
`.cargo/config.toml` + `x86_64-pc-windows-driver.json`.  The
toolchain pin in `examples/sample-driver/rust-toolchain.toml` is
required (`-Z build-std` is nightly-only); copy it into any consumer
crate that builds a kernel driver.

## CLI knobs

- `--symbols <dir>`: PDB root.
- `--out <dir>`: output root.
- `--only <pdb_name>`: limit to one PDB (e.g. `ntkrnlmp.pdb`).
- `--target rust|cpp|both`: backend.
- `--build <name>`: restrict to one entry from `config::BUILDS`.
- `--no-publics`: skip per-namespace `api.rs` / `api.hpp`.  Speeds up
  iteration when the kernel-function surface is not needed.
- `--no-encrypt`: ship the symbol table in plaintext (no XOR-LCG).
  Every entry's key becomes `0`, the runtime decode collapses to a
  plain `read_volatile`, and `.symdsc` payloads are byte-for-byte
  inspectable.

The generated Rust SDK crate honors a `NTBIND_CRATE_PATH` env var that
overrides the `ntbind = { path = ... }` dependency line in its
`Cargo.toml`.

## Credit

Wire format and the PDB-driven `.symtbl` patcher design originally
from [Selene](https://github.com/can1357/selene) by can1357.

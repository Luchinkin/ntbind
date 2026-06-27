// Diagnostic: dump publics from both the global symbol table AND per-module
// streams to see where a needle string appears.  Used to verify whether
// missing ndis identifiers are in the public globals (which ntbind reads) or
// only in module-static streams (which it doesn't).
#![allow(clippy::print_stdout, clippy::print_stderr)]

use pdb::FallibleIterator;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let pdb_path = &args[1];
    let needle = args.get(2).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
    let file = std::fs::File::open(pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;

    // 1) Global symbol table (this is all ntbind sees).
    let symtab = pdb.global_symbols()?;
    let mut iter = symtab.iter();
    let mut gcount = 0usize;
    let mut ghits = 0usize;
    while let Some(sym) = iter.next()? {
        gcount += 1;
        if let Ok(pdb::SymbolData::Public(p)) = sym.parse() {
            let name = p.name.to_string().to_string();
            if needle.is_empty() || name.to_ascii_lowercase().contains(&needle) {
                ghits += 1;
                println!("[G] {name}");
            }
        }
    }
    eprintln!("global: scanned {gcount} syms, matched {ghits}");

    // 2) Per-module streams (file-static / internal-linkage symbols).
    let dbi = pdb.debug_information()?;
    let mut modules = dbi.modules()?;
    let mut mcount = 0usize;
    let mut mhits = 0usize;
    let mut mods_processed = 0usize;
    while let Some(m) = modules.next()? {
        let info = match pdb.module_info(&m) {
            Ok(Some(info)) => info,
            _ => continue,
        };
        mods_processed += 1;
        let syms = info.symbols()?;
        let mut it = syms;
        while let Some(sym) = it.next()? {
            mcount += 1;
            // Iterate every symbol kind in the module stream that carries a name.
            let parsed = sym.parse();
            let name_opt = match parsed {
                Ok(pdb::SymbolData::Public(p)) => Some(p.name.to_string().to_string()),
                Ok(pdb::SymbolData::Data(d)) => Some(d.name.to_string().to_string()),
                Ok(pdb::SymbolData::Procedure(d)) => Some(d.name.to_string().to_string()),
                Ok(pdb::SymbolData::Constant(d)) => Some(d.name.to_string().to_string()),
                Ok(pdb::SymbolData::Thunk(d)) => Some(d.name.to_string().to_string()),
                Ok(pdb::SymbolData::Export(d)) => Some(d.name.to_string().to_string()),
                _ => None,
            };
            if let Some(name) = name_opt
                && (needle.is_empty() || name.to_ascii_lowercase().contains(&needle))
            {
                mhits += 1;
                println!("[M:{}] {name}", m.module_name());
            }
        }
    }
    eprintln!("modules: processed {mods_processed}, scanned {mcount} syms, matched {mhits}");
    Ok(())
}

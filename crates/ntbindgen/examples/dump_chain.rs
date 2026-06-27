// Diagnostic: walk the type chain of a single named member through
// LF_POINTER / LF_MODIFIER / LF_PRIMITIVE so we can see exactly where
// the `volatile` qualifier sits in the PDB encoding.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use pdb::FallibleIterator;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let pdb_path = &args[1];
    let class_needle = args[2].to_ascii_lowercase();
    let field_needle = args[3].to_ascii_lowercase();
    let file = std::fs::File::open(pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;
    let tpi = pdb.type_information()?;
    let mut finder = tpi.finder();
    let mut prep_iter = tpi.iter();
    while prep_iter.next()?.is_some() {
        finder.update(&prep_iter);
    }
    let mut iter = tpi.iter();
    while let Some(item) = iter.next()? {
        let Ok(data) = item.parse() else { continue };
        let pdb::TypeData::Class(c) = &data else { continue };
        if c.properties.forward_reference() {
            continue;
        }
        if c.name.to_string().to_ascii_lowercase() != class_needle {
            continue;
        }
        let mut current = c.fields;
        while let Some(fl_idx) = current {
            current = None;
            let fl_item = finder.find(fl_idx)?;
            let pdb::TypeData::FieldList(flist) = fl_item.parse()? else { continue };
            for f in &flist.fields {
                if let pdb::TypeData::Member(m) = f {
                    if m.name.to_string().to_ascii_lowercase() != field_needle {
                        continue;
                    }
                    println!(
                        "found {} class={} field={} field_type={:?}",
                        if c.size > 0 { "non-forward" } else { "forward" },
                        c.name,
                        m.name,
                        m.field_type
                    );
                    walk(m.field_type, &finder, 0);
                    return Ok(());
                }
            }
            if let Some(cont) = flist.continuation {
                current = Some(cont);
            }
        }
    }
    eprintln!("not found");
    Ok(())
}

fn walk(idx: pdb::TypeIndex, finder: &pdb::ItemFinder<'_, pdb::TypeIndex>, depth: usize) {
    let pad = "  ".repeat(depth);
    let item = match finder.find(idx) {
        Ok(x) => x,
        Err(e) => {
            println!("{pad}ERR find: {e}");
            return;
        },
    };
    let data = match item.parse() {
        Ok(x) => x,
        Err(e) => {
            println!("{pad}ERR parse: {e}");
            return;
        },
    };
    match data {
        pdb::TypeData::Pointer(p) => {
            println!("{pad}Pointer attrs={:?} underlying={:?}", p.attributes, p.underlying_type);
            walk(p.underlying_type, finder, depth + 1);
        },
        pdb::TypeData::Modifier(m) => {
            println!(
                "{pad}Modifier const={} volatile={} unaligned={} underlying={:?}",
                m.constant, m.volatile, m.unaligned, m.underlying_type
            );
            walk(m.underlying_type, finder, depth + 1);
        },
        pdb::TypeData::Procedure(p) => {
            println!("{pad}Procedure return={:?} arglist={:?}", p.return_type, p.argument_list);
            if let Ok(al_item) = finder.find(p.argument_list)
                && let Ok(pdb::TypeData::ArgumentList(al)) = al_item.parse()
            {
                for (i, a) in al.arguments.iter().enumerate() {
                    println!("{pad}  arg[{i}] = {:?}", a);
                    walk(*a, finder, depth + 2);
                }
            }
            if let Some(rt) = p.return_type {
                println!("{pad}  return:");
                walk(rt, finder, depth + 2);
            }
        },
        pdb::TypeData::Primitive(p) => {
            println!("{pad}Primitive kind={:?} indirection={:?}", p.kind, p.indirection);
        },
        pdb::TypeData::Class(c) => {
            println!("{pad}Class {} fwd={}", c.name, c.properties.forward_reference());
        },
        other => println!("{pad}Other {:?}", std::mem::discriminant(&other)),
    }
}

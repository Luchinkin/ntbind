// Diagnostic: dump a single PDB type's field list to see what kind of
// records (Member, BaseClass, VBaseClass, …) are present.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use pdb::FallibleIterator;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let pdb_path = &args[1];
    let needle = args[2].to_ascii_lowercase();
    let file = std::fs::File::open(pdb_path)?;
    let mut pdb = pdb::PDB::open(file)?;
    let tpi = pdb.type_information()?;
    let mut finder = tpi.finder();
    let mut prep_iter = tpi.iter();
    while prep_iter.next()?.is_some() {
        finder.update(&prep_iter);
    }
    let mut iter = tpi.iter();
    let mut instance = 0usize;
    while let Some(item) = iter.next()? {
        let Ok(data) = item.parse() else { continue };
        match &data {
            pdb::TypeData::Class(c) => {
                if c.properties.forward_reference() {
                    continue;
                }
                if c.name.to_string().to_ascii_lowercase() != needle {
                    continue;
                }
                instance += 1;
                println!("== INSTANCE #{instance}: class {} size=0x{:x} ==", c.name, c.size);
                if let Some(fl_idx) = c.fields {
                    let mut current = Some(fl_idx);
                    let mut count = 0usize;
                    while let Some(idx) = current {
                        current = None;
                        println!("    walking FieldList tidx=0x{:x}", u32::from(idx));
                        let fl_item = match finder.find(idx) {
                            Ok(x) => x,
                            Err(e) => {
                                println!("    finder.find ERROR: {e}");
                                break;
                            },
                        };
                        let fl = match fl_item.parse() {
                            Ok(x) => x,
                            Err(e) => {
                                println!("    parse ERROR: {e}");
                                break;
                            },
                        };
                        match &fl {
                            pdb::TypeData::FieldList(flist) => {
                                println!(
                                    "    FieldList: {} entries, continuation={:?}",
                                    flist.fields.len(),
                                    flist.continuation
                                );
                                for f in &flist.fields {
                                    count += 1;
                                    if count <= 8 {
                                        match f {
                                            pdb::TypeData::Member(m) => println!(
                                                "      #{count} Member +0x{:04x} {}",
                                                m.offset, m.name
                                            ),
                                            pdb::TypeData::BaseClass(b) => println!(
                                                "      #{count} BaseClass +0x{:04x}",
                                                b.offset
                                            ),
                                            pdb::TypeData::VirtualBaseClass(_) => {
                                                println!("      #{count} VBase")
                                            },
                                            _ => println!("      #{count} Other"),
                                        }
                                    }
                                }
                                if let Some(c) = flist.continuation {
                                    current = Some(c);
                                }
                            },
                            other => println!(
                                "    parsed as non-FieldList: {:?}",
                                std::mem::discriminant(other)
                            ),
                        }
                    }
                    println!("    total fields: {count}");
                } else {
                    println!("    (no fields)");
                }
            },
            pdb::TypeData::Enumeration(e) => {
                if e.properties.forward_reference() {
                    continue;
                }
                if e.name.to_string().to_ascii_lowercase() != needle {
                    continue;
                }
                instance += 1;
                println!(
                    "== INSTANCE #{instance}: enum {} underlying=0x{:x} ==",
                    e.name,
                    u32::from(e.underlying_type)
                );
                let mut current = Some(e.fields);
                let mut count = 0usize;
                while let Some(idx) = current {
                    current = None;
                    let fl_item = match finder.find(idx) {
                        Ok(x) => x,
                        Err(err) => {
                            println!("    finder.find ERROR: {err}");
                            break;
                        },
                    };
                    let fl = match fl_item.parse() {
                        Ok(x) => x,
                        Err(err) => {
                            println!("    parse ERROR: {err}");
                            break;
                        },
                    };
                    let pdb::TypeData::FieldList(flist) = &fl else {
                        println!("    non-FieldList variant payload");
                        break;
                    };
                    for f in &flist.fields {
                        if let pdb::TypeData::Enumerate(en) = f {
                            count += 1;
                            let v = match en.value {
                                pdb::Variant::U8(x) => x as i128,
                                pdb::Variant::U16(x) => x as i128,
                                pdb::Variant::U32(x) => x as i128,
                                pdb::Variant::U64(x) => x as i128,
                                pdb::Variant::I8(x) => x as i128,
                                pdb::Variant::I16(x) => x as i128,
                                pdb::Variant::I32(x) => x as i128,
                                pdb::Variant::I64(x) => x as i128,
                            };
                            println!("    {:<32} = 0x{:x}", en.name, v);
                        }
                    }
                    if let Some(c) = flist.continuation {
                        current = Some(c);
                    }
                }
                println!("    total variants: {count}");
            },
            _ => continue,
        }
    }
    Ok(())
}

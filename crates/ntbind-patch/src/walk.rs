//! Walk the `.symtbl` consolidated section, producing one record per
//! [`ntbind::symtbl::HeaderWithName`].
//!
//! Wire layout:
//! ```text
//!  +0  u32  magic = 0x004D5953 (`SYM\0`)
//!  +4  u64  address of encrypted payload (VA)
//!  +12 u64  encryption key
//!  +20 ..   NUL-terminated ASCII identifier
//! ```

use anyhow::Result;

use crate::pe::{PeView, Section};

pub const MIN_ENTRY_SIZE: usize = 21;

#[derive(Debug, Clone)]
pub struct SymTableEntry {
    /// Byte offset of the header within the original PE buffer.
    pub header_file_off: usize,
    /// Decrypted address pointing at the encrypted payload (still a VA).
    pub payload_va: u64,
    pub key: u64,
    pub identifier: String,
}

/// Walks every header in the consolidated `.symtbl` section.
pub fn walk_entries(buf: &[u8], view: &PeView, symtbl: &Section) -> Result<Vec<SymTableEntry>> {
    let mut out = Vec::new();
    let start = symtbl.raw_pointer as usize;
    // Use raw_size -- the on-disk section size -- to avoid walking into BSS.
    let end = start + symtbl.raw_size as usize;
    let mut pos = start;
    while pos + MIN_ENTRY_SIZE <= end {
        // Magic check.
        let magic = u32::from_le_bytes(
            buf[pos..pos + 4].try_into().expect("bounds-checked slice -> fixed-size array"),
        );
        if magic != ntbind::symtbl::SYM_TBL_MAGIC {
            // Linker may pad with zeros between $list contributions; skip
            // ahead 1 byte and resync.
            pos += 1;
            continue;
        }
        let address = u64::from_le_bytes(
            buf[pos + 4..pos + 12].try_into().expect("bounds-checked slice -> fixed-size array"),
        );
        let key = u64::from_le_bytes(
            buf[pos + 12..pos + 20].try_into().expect("bounds-checked slice -> fixed-size array"),
        );
        // Identifier is NUL-terminated ASCII starting at offset 20.
        let id_start = pos + 20;
        let mut id_end = id_start;
        while id_end < end && buf[id_end] != 0 {
            id_end += 1;
        }
        if id_end >= end {
            break; // truncated tail
        }
        let identifier = String::from_utf8_lossy(&buf[id_start..id_end]).into_owned();
        out.push(SymTableEntry { header_file_off: pos, payload_va: address, key, identifier });
        pos = id_end + 1;
    }
    let _ = view; // future use: pe-wide checks
    Ok(out)
}

/// For each `$Name$Image` public in `entries`, returns
/// `{image_name => symbol_count}`.  Non-public entries are ignored.
pub fn referenced_modules(entries: &[SymTableEntry]) -> std::collections::HashMap<String, usize> {
    let mut counts = std::collections::HashMap::new();
    for e in entries {
        let Some(body) = e.identifier.strip_prefix('$') else { continue };
        let Some(sep) = body.find('$') else { continue };
        let image = body[sep + 1..].to_ascii_lowercase();
        *counts.entry(image).or_insert(0) += 1;
    }
    counts
}

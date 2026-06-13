//! Just enough PE parsing for `.symtbl` walking and checksum recompute.

use anyhow::{Context, Result, bail};

/// Parsed PE header pointing into the original buffer.
#[derive(Debug, Clone)]
pub struct PeView {
    pub image_base: u64,
    /// Byte offset of the `CheckSum` u32 inside the optional header -- needed
    /// to recompute it after we mutate `.symdsc` bytes.
    pub checksum_field_off: usize,
    pub sections: Vec<Section>,
}

/// A single section table entry decoded into convenient fields.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    /// RVA of the section relative to `image_base`.
    pub virtual_address: u32,
    pub virtual_size: u32,
    /// File offset where the section's raw bytes live.
    pub raw_pointer: u32,
    pub raw_size: u32,
}

impl Section {
    /// True iff `va` falls within this section's mapped range.
    pub fn contains_va(&self, image_base: u64, va: u64) -> bool {
        let start = image_base + self.virtual_address as u64;
        let end = start + self.virtual_size as u64;
        (start..end).contains(&va)
    }

    /// Converts a VA to a file offset within the original buffer.
    pub fn va_to_file_offset(&self, image_base: u64, va: u64) -> Option<usize> {
        if !self.contains_va(image_base, va) {
            return None;
        }
        let delta = va - image_base - self.virtual_address as u64;
        // `raw_size` may be smaller than `virtual_size` when the section has
        // uninitialized tail -- refuse to patch beyond the raw bytes since
        // they don't exist on disk.
        if delta >= self.raw_size as u64 {
            return None;
        }
        Some(self.raw_pointer as usize + delta as usize)
    }
}

/// Parses the DOS + NT + section headers, returning a view into the PE.
pub fn parse_pe(buf: &[u8]) -> Result<PeView> {
    if buf.len() < 0x40 {
        bail!("buffer too small for DOS header");
    }
    if &buf[0..2] != b"MZ" {
        bail!("not a PE: missing MZ");
    }
    let e_lfanew = u32::from_le_bytes(
        buf[0x3C..0x40].try_into().expect("bounds-checked slice -> fixed-size array"),
    ) as usize;
    if buf.len() < e_lfanew + 0x18 {
        bail!("buffer truncated before NT headers");
    }
    if &buf[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        bail!("not a PE: bad signature at e_lfanew");
    }
    let coff = e_lfanew + 4;
    if buf.len() < coff + 20 {
        bail!("buffer truncated in COFF header");
    }
    let num_sections = u16::from_le_bytes(
        buf[coff + 2..coff + 4].try_into().expect("bounds-checked slice -> fixed-size array"),
    ) as usize;
    let opt_size = u16::from_le_bytes(
        buf[coff + 16..coff + 18].try_into().expect("bounds-checked slice -> fixed-size array"),
    ) as usize;
    let opt = coff + 20;
    if buf.len() < opt + opt_size {
        bail!("buffer truncated in optional header");
    }
    let magic = u16::from_le_bytes(
        buf[opt..opt + 2].try_into().expect("bounds-checked slice -> fixed-size array"),
    );
    let is_pe64 = match magic {
        0x10B => false,
        0x20B => true,
        _ => bail!("unknown optional header magic 0x{magic:x}"),
    };
    // Image base is at:
    //   PE32:  opt + 28  (u32)
    //   PE32+: opt + 24  (u64)
    let image_base = if is_pe64 {
        u64::from_le_bytes(
            buf[opt + 24..opt + 32].try_into().expect("bounds-checked slice -> fixed-size array"),
        )
    } else {
        u32::from_le_bytes(
            buf[opt + 28..opt + 32].try_into().expect("bounds-checked slice -> fixed-size array"),
        ) as u64
    };
    // Checksum is u32 at opt + 64 (same in both PE32 and PE32+).
    let checksum_field_off = opt + 64;

    let sec_table = opt + opt_size;
    if buf.len() < sec_table + num_sections * 40 {
        bail!("buffer truncated in section table");
    }
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sec_table + i * 40;
        let name_bytes = &buf[off..off + 8];
        let name =
            name_bytes.iter().position(|b| *b == 0).map(|n| &name_bytes[..n]).unwrap_or(name_bytes);
        let name = String::from_utf8_lossy(name).into_owned();
        let virtual_size = u32::from_le_bytes(
            buf[off + 8..off + 12].try_into().expect("bounds-checked slice -> fixed-size array"),
        );
        let virtual_address = u32::from_le_bytes(
            buf[off + 12..off + 16].try_into().expect("bounds-checked slice -> fixed-size array"),
        );
        let raw_size = u32::from_le_bytes(
            buf[off + 16..off + 20].try_into().expect("bounds-checked slice -> fixed-size array"),
        );
        let raw_pointer = u32::from_le_bytes(
            buf[off + 20..off + 24].try_into().expect("bounds-checked slice -> fixed-size array"),
        );
        sections.push(Section { name, virtual_address, virtual_size, raw_pointer, raw_size });
    }
    Ok(PeView { image_base, checksum_field_off, sections })
}

/// Finds the consolidated `.symtbl` section.  `HeaderWithName` statics
/// emit into the `.symtbl$list` COFF group; the linker merges them
/// into the parent `.symtbl` section.
pub fn find_symtbl(view: &PeView) -> Option<&Section> {
    view.sections.iter().find(|s| s.name == ".symtbl")
}

/// Strips the `.symtbl` section from a PE buffer in place; returns the
/// number of bytes removed.  Virtual addresses are not touched so data
/// directory entries (export, import, reloc) remain valid.  Caller must
/// follow up with [`recompute_checksum`].
pub fn strip_symtbl_section(buf: &mut Vec<u8>) -> Result<usize> {
    let view = parse_pe(buf)?;
    let sec_index = view
        .sections
        .iter()
        .position(|s| s.name == ".symtbl")
        .context(".symtbl section missing -- nothing to strip")?;
    let sec = view.sections[sec_index].clone();
    let raw_start = sec.raw_pointer as usize;
    let raw_size = sec.raw_size as usize;

    if raw_start + raw_size > buf.len() {
        bail!(".symtbl raw extent {raw_start}+{raw_size} exceeds buffer");
    }

    let e_lfanew = u32::from_le_bytes(
        buf[0x3C..0x40].try_into().expect("bounds-checked slice -> fixed-size array"),
    ) as usize;
    let coff = e_lfanew + 4;
    let num_sections = u16::from_le_bytes(
        buf[coff + 2..coff + 4].try_into().expect("bounds-checked slice -> fixed-size array"),
    ) as usize;
    let opt_size = u16::from_le_bytes(
        buf[coff + 16..coff + 18].try_into().expect("bounds-checked slice -> fixed-size array"),
    ) as usize;
    let sec_table = coff + 20 + opt_size;

    // 1) Drain the raw bytes.
    buf.drain(raw_start..raw_start + raw_size);

    // 2) Compact the section header table: shift entries after the one
    //    we removed up by 40 bytes, zero the freed trailing slot.
    for i in (sec_index + 1)..num_sections {
        let src = sec_table + i * 40;
        let dst = sec_table + (i - 1) * 40;
        let mut tmp = [0u8; 40];
        tmp.copy_from_slice(&buf[src..src + 40]);
        buf[dst..dst + 40].copy_from_slice(&tmp);
    }
    let last = sec_table + (num_sections - 1) * 40;
    buf[last..last + 40].fill(0);

    // Decrement NumberOfSections.
    let new_count = (num_sections - 1) as u16;
    buf[coff + 2..coff + 4].copy_from_slice(&new_count.to_le_bytes());

    // 3) Adjust PointerToRawData of sections that sat after `.symtbl`.
    for i in 0..(num_sections - 1) {
        let off = sec_table + i * 40;
        let p = u32::from_le_bytes(
            buf[off + 20..off + 24].try_into().expect("bounds-checked slice -> fixed-size array"),
        ) as usize;
        if p > raw_start {
            let np = (p - raw_size) as u32;
            buf[off + 20..off + 24].copy_from_slice(&np.to_le_bytes());
        }
    }

    Ok(raw_size)
}

/// Recomputes the PE checksum after in-place edits. Algorithm: sum every
/// u16 in the file (excluding the checksum field itself), then add the
/// file size. Matches `IMAGEHLP_CheckSumMappedFile`.
pub fn recompute_checksum(buf: &mut [u8], checksum_field_off: usize) -> Result<()> {
    if checksum_field_off + 4 > buf.len() {
        bail!("checksum field offset out of range");
    }
    // Zero the field first.
    buf[checksum_field_off..checksum_field_off + 4].copy_from_slice(&[0; 4]);

    let mut sum: u64 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        let w = u16::from_le_bytes(
            buf[i..i + 2].try_into().expect("bounds-checked slice -> fixed-size array"),
        ) as u64;
        sum += w;
        // Fold the carry into the low 16 bits -- matches `(sum + carry) &
        // 0xffff + (sum >> 16)` collapsed into a single accumulator.
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    // Tail byte if file is odd-length.
    if i < buf.len() {
        sum += buf[i] as u64;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    let checksum = (sum as u32).wrapping_add(buf.len() as u32);
    buf[checksum_field_off..checksum_field_off + 4].copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // PE round-trip on the sample driver build.  Skipped when the
    // sample hasn't been built (CI without the nightly toolchain).
    #[test]
    fn parse_sample_driver_pe() -> Result<()> {
        let path = std::path::Path::new(
            "../../examples/sample-driver/target/x86_64-pc-windows-driver/release/sample_driver.sys",
        );
        if !path.exists() {
            return Ok(());
        }
        let buf = std::fs::read(path).context("reading sample driver")?;
        let view = parse_pe(&buf)?;
        assert!(!view.sections.is_empty(), "must have sections");
        let symtbl = find_symtbl(&view).expect(".symtbl missing");
        assert!(symtbl.virtual_size > 0);
        Ok(())
    }

    // Strip removes `.symtbl` entirely while keeping the PE walkable.
    //
    #[test]
    fn strip_symtbl_keeps_pe_walkable() -> Result<()> {
        let path = std::path::Path::new(
            "../../examples/sample-driver/target/x86_64-pc-windows-driver/release/sample_driver.sys",
        );
        if !path.exists() {
            return Ok(());
        }
        let mut buf = std::fs::read(path).context("reading sample driver")?;
        let original_len = buf.len();
        let before = parse_pe(&buf)?;
        let symtbl_size = find_symtbl(&before).expect(".symtbl missing").raw_size as usize;
        let other_names: Vec<String> = before
            .sections
            .iter()
            .filter(|s| s.name != ".symtbl")
            .map(|s| s.name.clone())
            .collect();

        let removed = strip_symtbl_section(&mut buf)?;
        assert_eq!(removed, symtbl_size, "strip should remove exactly the section's raw bytes");
        assert_eq!(buf.len(), original_len - symtbl_size, "file shrinks by removed amount");

        let after = parse_pe(&buf)?;
        assert!(find_symtbl(&after).is_none(), ".symtbl must be gone");
        assert_eq!(after.sections.len(), before.sections.len() - 1, "section count drops by one");
        let after_names: Vec<String> = after.sections.iter().map(|s| s.name.clone()).collect();
        assert_eq!(after_names, other_names, "remaining sections keep their relative order");
        for s in &after.sections {
            let end = s.raw_pointer as usize + s.raw_size as usize;
            assert!(end <= buf.len(), "section {} extends past EOF after strip", s.name);
        }
        Ok(())
    }
}

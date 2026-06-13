//! On-disk wire format for the ntbind symbol table.
//!
//! Each generated field / public emits a packed [`HeaderWithName`] in
//! `.symtbl$list` pointing at an encrypted [`OffsetEntry`] or [`PublicEntry`]
//! payload. The post-link patcher walks the headers, decrypts, resolves
//! against a target PDB / kernel, and re-encrypts in place.
//!
//! Layout rules:
//! - Everything `#[repr(C, packed)]`, no padding.
//! - All values little-endian (Windows x64).
//! - `magic == 0x004D5953` (`b"SYM\0"` LE) marks a header start.
//! - Identifiers are ASCII, NUL-terminated; the NUL is part of the header.
//!
//! ## Identifier conventions
//! - Field offset: `"<StructName>.<FieldName>"` (e.g. `"_BOOT_OPTIONS.Version"`).
//! - Struct summary: `"<StructName>.$"` -- payload is an [`OffsetEntry`] whose
//!   `bit_offset` field carries the *byte size* of the struct.
//! - Public: `"$<Name>$<HintImage>"` (e.g. `"$KeBugCheck$ntoskrnl.exe"`).

use core::ffi::c_void;

/// Identifier of an entry header in the `.symtbl$list` section.
///
/// Wire bytes: `b"SYM\0"` (little-endian `u32`).
pub const SYM_TBL_MAGIC: u32 = 0x004D_5953;

/// Section name the patcher scans for entry headers.
///
/// COFF treats `$<tag>` as an ordering grouping the linker consolidates into
/// the parent (`.symtbl`). `$list` groups runtime entries; the patcher walks
/// the consolidated section.
pub const SYM_TBL_LIST_SECTION: &str = ".symtbl$list";

/// Discard section for the *payload* statics that headers point at.
///
/// `.symdsc` groups payload statics separately from the header index.
pub const SYM_TBL_DISCARD_SECTION: &str = ".symdsc";

/// Header tail (no identifier) describing one symbol-table entry. Wire size
/// is 20 bytes (4 + 8 + 8). The identifier follows inline; use
/// [`HeaderWithName`] to construct one.
#[repr(C, packed)]
#[derive(Debug)]
pub struct SymbolTableHeader {
    /// Always [`SYM_TBL_MAGIC`].
    pub magic: u32,
    /// Address of the encrypted payload (an [`OffsetEntry`] or [`PublicEntry`]).
    pub address: *const c_void,
    /// Per-entry XOR-LCG key.
    pub encryption_key: u64,
}

const _: () = assert!(core::mem::size_of::<SymbolTableHeader>() == 20);

/// Header packaged with the inline null-terminated identifier. `N` is the
/// identifier byte count including the trailing NUL. Generated code builds
/// these from a string literal:
/// ```ignore
/// const NAME: &[u8] = b"_BOOT_OPTIONS.Version\0";
/// static H: HeaderWithName<{NAME.len()}> = HeaderWithName::new(&PAYLOAD, KEY, NAME);
/// ```
#[repr(C, packed)]
#[derive(Debug)]
pub struct HeaderWithName<const N: usize> {
    /// Magic sentinel (`SYM_TBL_MAGIC`) marking a valid header.
    pub magic: u32,
    /// Pointer to the encrypted payload static (the `OffsetEntry` or
    /// `PublicEntry` cell this header describes).
    pub address: *const c_void,
    /// Per-entry XOR-LCG key.  Patcher reads this verbatim to decrypt
    /// the payload before resolving.
    pub encryption_key: u64,
    /// NUL-terminated identifier bytes, length `N` (NUL included).
    pub identifier: [u8; N],
}

impl<const N: usize> HeaderWithName<N> {
    /// Builds a header. `address` should point at the encrypted payload static
    /// for this entry; `identifier` must include the trailing NUL byte.
    #[inline]
    #[must_use]
    pub const fn new(address: *const c_void, encryption_key: u64, identifier: [u8; N]) -> Self {
        assert!(N > 0, "identifier must include NUL terminator");
        assert!(identifier[N - 1] == 0, "identifier must be NUL-terminated");
        Self { magic: SYM_TBL_MAGIC, address, encryption_key, identifier }
    }
}

// SAFETY: `address` is a `*const c_void` pointing at a `'static` payload; the
// header is read by the patcher pre-load (single threaded) and via
// `read_volatile` thereafter. We expose no interior mutability.
unsafe impl<const N: usize> Sync for HeaderWithName<N> {}

/// 7-byte packed payload describing one struct field.
///
/// `bit_offset` doubles as the **byte size** of the parent struct on the
/// `"<Type>.$"` summary entry.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OffsetEntry {
    /// Bit offset of the field within its parent struct.  On the
    /// `"<Type>.$"` summary entry this slot doubles as the byte size of
    /// the parent.
    pub bit_offset: u32,
    /// Width of the field in bits (`0` for a non-bitfield member).
    pub bit_size: u16,
    /// `1` when the field is present in the source PDB, `0` when absent.
    pub exists: u8,
}

const _: () = assert!(core::mem::size_of::<OffsetEntry>() == 7);

/// 17-byte packed payload describing one exported public.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicEntry {
    /// Virtual address resolved by the patcher, or `0` when unresolved.
    pub virtual_address: u64,
    /// Offset from the owning module's base.
    pub offset: u32,
    /// 1-based index identifying which module owns the symbol.
    pub sys_idx: i32,
    /// `1` when the public is present in the source PDB, `0` when absent.
    pub exists: u8,
}

const _: () = assert!(core::mem::size_of::<PublicEntry>() == 17);

impl OffsetEntry {
    #[inline]
    #[must_use]
    /// Builds an `OffsetEntry`.  When `exists` is `false`, packs the
    /// `u32::MAX` sentinel into `bit_offset` so the patcher sees an
    /// unambiguous "absent" shape.
    pub const fn new(bit_offset: u32, bit_size: u16, exists: bool) -> Self {
        Self {
            // Sentinel: clamp bit_offset to MAX to mark "absent" so the
            // patcher sees a consistent in-memory shape.
            bit_offset: if exists { bit_offset } else { u32::MAX },
            bit_size,
            exists: exists as u8,
        }
    }

    /// Packs into 7 wire bytes.
    #[inline]
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 7] {
        let off = self.bit_offset.to_le_bytes();
        let sz = self.bit_size.to_le_bytes();
        [off[0], off[1], off[2], off[3], sz[0], sz[1], self.exists]
    }

    /// Unpacks from 7 wire bytes.
    #[inline]
    #[must_use]
    pub const fn from_bytes(b: [u8; 7]) -> Self {
        Self {
            bit_offset: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            bit_size: u16::from_le_bytes([b[4], b[5]]),
            exists: b[6],
        }
    }
}

impl PublicEntry {
    /// Packs into 17 wire bytes.
    #[inline]
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 17] {
        let va = self.virtual_address.to_le_bytes();
        let off = self.offset.to_le_bytes();
        let sys = self.sys_idx.to_le_bytes();
        [
            va[0],
            va[1],
            va[2],
            va[3],
            va[4],
            va[5],
            va[6],
            va[7],
            off[0],
            off[1],
            off[2],
            off[3],
            sys[0],
            sys[1],
            sys[2],
            sys[3],
            self.exists,
        ]
    }

    /// Unpacks from 17 wire bytes.
    #[inline]
    #[must_use]
    pub const fn from_bytes(b: [u8; 17]) -> Self {
        Self {
            virtual_address: u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            offset: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            sys_idx: i32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            exists: b[16],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_round_trip() {
        let e = OffsetEntry::new(0x80, 0x20, true);
        assert_eq!(OffsetEntry::from_bytes(e.to_bytes()), e);
    }

    #[test]
    fn offset_missing_uses_max() {
        let e = OffsetEntry::new(0, 0, false);
        // Field reads through `&` are UB on packed structs -- copy first.
        let (bit_offset, exists) = ({ e }.bit_offset, { e }.exists);
        assert_eq!(bit_offset, u32::MAX);
        assert_eq!(exists, 0);
    }

    #[test]
    fn public_round_trip() {
        let p = PublicEntry {
            virtual_address: 0xfffff800_12345678,
            offset: 0x3bce0,
            sys_idx: 42,
            exists: 1,
        };
        assert_eq!(PublicEntry::from_bytes(p.to_bytes()), p);
    }

    #[test]
    fn header_size_pinned_to_20() {
        // The Python patcher uses min entry size = 21 (header 20 + NUL).
        assert_eq!(core::mem::size_of::<SymbolTableHeader>(), 20);
    }
}

// Integration test -- `.unwrap()` / `.expect()` are how a failing test
// surfaces a bug.  The library's `unwrap_used`/`expect_used` lints stop
// at this boundary.
//
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end smoke test: simulate what the generator emits, verify
//! both the field-accessor expansion and the wire format the symbol-table
//! patcher expects.

use std::ffi::c_void;

use ntbind::crypto::encode_decode;
use ntbind::symtbl::{HeaderWithName, OffsetEntry, PublicEntry, SYM_TBL_MAGIC};

// Mirror of the C++ `struct _BOOT_OPTIONS` (size 0x18). Generator output
// shape: opaque storage + accessor methods.
#[repr(C, align(8))]
struct OptionsT {
    _raw: [u8; 0x18],
}

impl OptionsT {
    ntbind::field! {
        name = version,
        ty = u32,
        identifier = b"_BOOT_OPTIONS.Version\0",
        offset_bits = 0,
        size_bits = 32,
        exists = true,
        key = 0xa79d_ebf4_9fdb_6a93u64,
    }

    ntbind::field! {
        name = timeout,
        ty = u32,
        identifier = b"_BOOT_OPTIONS.Timeout\0",
        offset_bits = 0x40,
        size_bits = 32,
        exists = true,
        key = 0xdead_beef_cafe_f00du64,
    }
}

#[test]
fn accessor_reads_through_runtime_offset() {
    // Construct opaque storage and stuff known bytes in. The accessor reads
    // through the offset baked into the symbol table -- which equals the
    // canonical (pre-patch) offset because we never invoked the patcher.
    let mut s = OptionsT { _raw: [0; 0x18] };
    // version at byte 0, timeout at byte 8.
    s._raw[0..4].copy_from_slice(&0xCAFEBABEu32.to_le_bytes());
    s._raw[8..12].copy_from_slice(&0xDEAD0000u32.to_le_bytes());

    let v = unsafe { *s.version() };
    let t = unsafe { *s.timeout() };
    assert_eq!(v, 0xCAFEBABE);
    assert_eq!(t, 0xDEAD0000);
}

#[test]
fn offset_entry_encrypts_round_trip_via_xor_lcg() {
    // The bytes we'd find in `.symdsc` for an OffsetEntry, decrypted, must
    // match the original. This is the round-trip the patcher relies on.
    let entry = OffsetEntry::new(0x80, 0x20, true);
    let key = 0xa79d_ebf4_9fdb_6a93u64;
    let cipher = encode_decode::<7>(entry.to_bytes(), key);
    let plain = encode_decode::<7>(cipher, key);
    assert_eq!(OffsetEntry::from_bytes(plain), entry);
}

#[test]
fn public_entry_encrypts_round_trip() {
    let entry = PublicEntry { virtual_address: 0, offset: 0x3bce0, sys_idx: 0, exists: 1 };
    let key = 0xa79d_ebf4_9fdb_6a93u64;
    let cipher = encode_decode::<17>(entry.to_bytes(), key);
    let plain = encode_decode::<17>(cipher, key);
    assert_eq!(PublicEntry::from_bytes(plain), entry);
}

#[test]
fn header_layout_matches_reference_walker() {
    // The reference walker assumes this exact layout:
    //   u32 magic | u64 address | u64 key | ASCII identifier + \0
    // with minimum entry size 21 (header 20 + at least 1 ID byte).
    const ID: &[u8] = b"_BOOT_OPTIONS.Version\0";
    let h = HeaderWithName::<{ ID.len() }>::new(
        0xfffff800_12345678 as *const c_void,
        0xa79d_ebf4_9fdb_6a93,
        *b"_BOOT_OPTIONS.Version\0",
    );

    // size_of for a packed struct must match the sum of field sizes.
    assert_eq!(std::mem::size_of_val(&h), 20 + ID.len());

    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(&h as *const _ as *const u8, std::mem::size_of_val(&h))
    };
    assert_eq!(&bytes[0..4], &SYM_TBL_MAGIC.to_le_bytes());
    assert_eq!(
        &bytes[4..12],
        &(0xfffff800_12345678u64).to_le_bytes(),
        "address pointer at offset 4"
    );
    assert_eq!(&bytes[12..20], &(0xa79d_ebf4_9fdb_6a93u64).to_le_bytes(), "key at offset 12");
    assert_eq!(&bytes[20..], ID, "identifier (NUL-terminated) at offset 20");
}

// Mirror of a small bitfield-bearing PDB type. Lay out 8 bytes of storage
// holding three fields:
//   bits  0..1 -> `enabled` (1 bit)
//   bits  1..5 -> `level`   (4 bits, unsigned)
//   bits  5..11 -> `cookie` (6 bits, signed)
// All inside a u32 storage word at byte offset 0.
#[repr(C)]
struct BitsT {
    _raw: [u8; 0x8],
}

impl BitsT {
    ntbind::bit_field! {
        name = enabled,
        setter = set_enabled,
        ty = bool,
        identifier = b"_BITS.Enabled\0",
        offset_bits = 0,
        size_bits = 1,
        storage_bytes = 4,
        signed = false,
        exists = true,
        key = 0xa79d_ebf4_9fdb_6a93u64,
    }
    ntbind::bit_field! {
        name = level,
        setter = set_level,
        ty = u8,
        identifier = b"_BITS.Level\0",
        offset_bits = 1,
        size_bits = 4,
        storage_bytes = 4,
        signed = false,
        exists = true,
        key = 0xdead_beef_cafe_f00du64,
    }
    ntbind::bit_field! {
        name = cookie,
        setter = set_cookie,
        ty = i8,
        identifier = b"_BITS.Cookie\0",
        offset_bits = 5,
        size_bits = 6,
        storage_bytes = 4,
        signed = true,
        exists = true,
        key = 0xfeed_face_dead_beefu64,
    }
}

#[test]
fn bitfield_unsigned_extracts_correctly() {
    // Storage word: bits laid out little-endian within a u32 at byte 0.
    // We want enabled=1, level=0b1010 (10), cookie=arbitrary.
    // Bits:   0      | 1..4 (level=10)  | 5..10 (cookie)
    // value = 1 | (10<<1) | (cookie<<5)
    let mut s = BitsT { _raw: [0; 0x8] };
    let cookie_unsigned: u32 = 0b101010; // 6-bit pattern
    let word: u32 = 1 | (0b1010 << 1) | (cookie_unsigned << 5);
    s._raw[0..4].copy_from_slice(&word.to_le_bytes());

    assert!(s.enabled());
    assert_eq!(s.level(), 10);
}

#[test]
fn bitfield_signed_sign_extends() {
    let mut s = BitsT { _raw: [0; 0x8] };
    // 6-bit two's complement: 0b101010 (42 unsigned) = -22 signed.
    let cookie_raw: u32 = 0b101010;
    let word: u32 = (cookie_raw & 0x3F) << 5;
    s._raw[0..4].copy_from_slice(&word.to_le_bytes());
    assert_eq!(s.cookie(), -22);
}

#[test]
fn bitfield_signed_positive_passthrough() {
    let mut s = BitsT { _raw: [0; 0x8] };
    // 6-bit two's complement: 0b001010 (10) = 10 signed.
    let cookie_raw: u32 = 0b001010;
    let word: u32 = (cookie_raw & 0x3F) << 5;
    s._raw[0..4].copy_from_slice(&word.to_le_bytes());
    assert_eq!(s.cookie(), 10);
}

#[test]
fn bitfield_setter_preserves_neighbors() {
    // RMW path: write a new `level` value and verify `enabled`/`cookie`
    // -- packed into the same u32 storage word -- survive.
    let mut s = BitsT { _raw: [0; 0x8] };
    let cookie_raw: u32 = 0b011001;
    let initial: u32 = 1 | (0b1111 << 1) | ((cookie_raw & 0x3F) << 5);
    s._raw[0..4].copy_from_slice(&initial.to_le_bytes());
    assert!(s.enabled());
    assert_eq!(s.level(), 0xF);
    assert_eq!(s.cookie(), 25);

    unsafe { s.set_level(0b0010) };
    assert!(s.enabled(), "neighbor bit 0 must survive RMW");
    assert_eq!(s.level(), 2);
    assert_eq!(s.cookie(), 25, "neighbor bits 5..10 must survive RMW");
}

#[test]
fn bitfield_setter_round_trip_signed() {
    let mut s = BitsT { _raw: [0; 0x8] };
    // 6-bit two's complement: -22 = 0b101010 = 42 unsigned in the field.
    unsafe { s.set_cookie(-22) };
    assert_eq!(s.cookie(), -22);
    unsafe { s.set_cookie(7) };
    assert_eq!(s.cookie(), 7);
}

#[test]
fn bitfield_setter_masks_high_bits() {
    // Writing 0xFF into a 4-bit field should keep only the low nibble.
    let mut s = BitsT { _raw: [0; 0x8] };
    unsafe { s.set_level(0xFF) };
    assert_eq!(s.level(), 0xF);
}

#[test]
fn list_entry_iter_walks_cycle_and_stops_at_head() {
    use ntbind::nt::ListEntryT;

    // Build a 3-node cycle by hand: head <-> a <-> b <-> c <-> head.
    let mut head = ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() };
    let mut a = ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() };
    let mut b = ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() };
    let mut c = ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() };

    head.flink = &mut a;
    head.blink = &mut c;
    a.flink = &mut b;
    a.blink = &mut head;
    b.flink = &mut c;
    b.blink = &mut a;
    c.flink = &mut head;
    c.blink = &mut b;

    assert!(!head.is_empty(), "list with three entries reports non-empty");

    let nodes: Vec<*const ListEntryT> = unsafe { head.iter() }.collect();
    assert_eq!(nodes.len(), 3);
    assert_eq!(nodes[0], &raw const a);
    assert_eq!(nodes[1], &raw const b);
    assert_eq!(nodes[2], &raw const c);
    assert_eq!(unsafe { head.len() }, 3);
}

#[test]
fn empty_list_entry_yields_nothing() {
    use ntbind::nt::ListEntryT;

    let mut head = ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() };
    head.flink = &mut head;
    head.blink = &mut head;

    assert!(head.is_empty());
    assert_eq!(unsafe { head.iter() }.count(), 0);
    assert_eq!(unsafe { head.len() }, 0);
}

#[test]
fn containing_record_recovers_enclosing_struct() {
    use ntbind::nt::{ListEntryT, containing_record};

    #[repr(C)]
    struct Outer {
        pad: u64,
        link: ListEntryT,
        tail: u32,
    }

    let outer = Outer {
        pad: 0x1122_3344_5566_7788,
        link: ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() },
        tail: 0xdead_beef,
    };
    let link_ptr = &raw const outer.link;
    let link_offset = core::mem::offset_of!(Outer, link);
    let recovered: *const Outer = containing_record(link_ptr.cast(), link_offset);
    assert_eq!(recovered, &raw const outer);
    assert_eq!(unsafe { (*recovered).pad }, 0x1122_3344_5566_7788);
    assert_eq!(unsafe { (*recovered).tail }, 0xdead_beef);
}

#[test]
fn list_entry_insert_and_unlink() {
    use ntbind::nt::ListEntryT;

    let mut head = ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() };
    head.flink = &mut head;
    head.blink = &mut head;

    let mut a = ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() };
    let mut b = ListEntryT { flink: core::ptr::null_mut(), blink: core::ptr::null_mut() };

    // SAFETY: head, a, b are stack-pinned for the test's lifetime; no
    // concurrent readers exist.
    unsafe { a.insert_after(&mut head) };
    unsafe { b.insert_after(&mut a) };

    let nodes: Vec<*const ListEntryT> = unsafe { head.iter() }.collect();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0], &raw const a);
    assert_eq!(nodes[1], &raw const b);

    // SAFETY: see above; unlink a leaves head <-> b.
    unsafe { a.unlink() };
    let nodes: Vec<*const ListEntryT> = unsafe { head.iter() }.collect();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0], &raw const b);
}

#[test]
fn unicode_view_from_slice_roundtrips() {
    use ntbind::nt::UnicodeView;

    let chars: [u16; 5] = [b'H' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16];
    let view = UnicodeView::from_slice(&chars).expect("5 chars fits u16::MAX bytes");
    assert_eq!(view.len_chars(), 5);
    assert!(!view.is_empty());
    // SAFETY: chars outlives view in this scope.
    let slice = unsafe { view.as_slice() };
    assert_eq!(slice, &chars);

    let empty = UnicodeView::empty();
    assert!(empty.is_empty());
    assert_eq!(empty.len_chars(), 0);
    assert!(unsafe { empty.as_slice() }.is_empty());
}

#[test]
fn unicode_view_from_slice_returns_none_on_overflow() {
    use ntbind::nt::UnicodeView;

    // 32768 chars would encode to 65536 bytes -- one past `u16::MAX`.
    // Slice content is irrelevant; only `len()` is read.
    let too_long: Vec<u16> = vec![0u16; 0x8000];
    assert!(UnicodeView::from_slice(&too_long).is_none());
}

#[test]
fn ascii_view_from_slice_roundtrips() {
    use ntbind::nt::AsciiView;

    let bytes = b"smss.exe";
    let view = AsciiView::from_slice(bytes).expect("8 bytes fits u16::MAX");
    assert_eq!(view.len_bytes(), bytes.len());
    // SAFETY: bytes outlives view in this scope.
    let slice = unsafe { view.as_slice() };
    assert_eq!(slice, bytes);
}

#[test]
fn ascii_view_from_slice_returns_none_on_overflow() {
    use ntbind::nt::AsciiView;

    let too_long: Vec<u8> = vec![0u8; 0x10000];
    assert!(AsciiView::from_slice(&too_long).is_none());
}

#[test]
fn m128a_roundtrips_bytes() {
    use ntbind::nt::M128aT;

    let bytes: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let m = M128aT::from_bytes(bytes);
    assert_eq!(m.low, u64::from_le_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]));
    assert_eq!(m.to_bytes(), bytes);
    assert_eq!(M128aT::zero().to_bytes(), [0u8; 16]);
}

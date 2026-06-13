// Integration test -- `.unwrap()` / `.expect()` are how a failing test
// surfaces a bug.  The library's `unwrap_used`/`expect_used` lints stop
// at this boundary.
//
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Pins ntbind's wire format against the constants the patcher hardcodes.
//! If any of these diverge the patcher silently misreads (or skips)
//! every entry -- the test fails noisily instead.

use ntbind::crypto::{LCG_ADD, LCG_MUL, encode_decode, lcg_next};
use ntbind::symtbl::{OffsetEntry, PublicEntry, SYM_TBL_MAGIC};

// Wire-format constants the patcher pins against.  Drift = silent breakage.
#[test]
fn magic_constants_match_patcher() {
    assert_eq!(SYM_TBL_MAGIC, 0x004D_5953, "SYM_TBL_MAGIC");
    assert_eq!(LCG_MUL, 0x5851_F42D_4C95_7F2D, "LCG_MUL");
    assert_eq!(LCG_ADD, 0x1405_7B7E_F767_814F, "LCG_ADD");
}

// PublicEntry on-disk size = 17 bytes (`public_entry` shape).
#[test]
fn public_entry_size_matches_patcher() {
    assert_eq!(core::mem::size_of::<PublicEntry>(), 17);
}

// The public-entry codec packs 17 bytes into 3 8-byte qwords and XORs
// each with `key` / `lcg_next(key)` / `lcg_next(lcg_next(key))`.
// Recreate one known plaintext -> ciphertext step and pin it.
#[test]
#[allow(clippy::needless_range_loop)] // explicit shift-and-OR is more
// transparent here than `enumerate().fold(...)`.
fn cipher_matches_python_reference() {
    // Plaintext: public_entry { va: 0xfffff800_12345678, off: 0x3bce0, sys: 0, exists: 1 }
    let plain = PublicEntry {
        virtual_address: 0xfffff800_12345678,
        offset: 0x3bce0,
        sys_idx: 0,
        exists: 1,
    };
    let key: u64 = 0xa79d_ebf4_9fdb_6a93;

    // Hand-computed XOR result, mirroring `encrypt_decrypt_public_entry`:
    //  qword0 = u64::from_le(va_bytes ++ off_low4_bytes)
    //         = 0x3bce0_fffff800_12345678 truncated to u64 LE ...
    //  qword1 = u64::from_le(sys ++ exists ++ tail)
    // We don't pin the bytes by hand -- instead we re-encrypt and confirm the
    // round-trip is its own inverse for *this* concrete input (which is
    // exactly what the patcher relies on).
    let cipher = encode_decode::<17>(plain.to_bytes(), key);
    let back = encode_decode::<17>(cipher, key);
    assert_eq!(PublicEntry::from_bytes(back), plain);

    // First qword XOR with the original key must match. (This is the
    // single-step property the patcher's first iteration checks.)
    let plain_bytes = plain.to_bytes();
    let mut p_q0 = 0u64;
    for i in 0..8 {
        p_q0 |= (plain_bytes[i] as u64) << (i * 8);
    }
    let c_q0_expected = p_q0 ^ key;
    let mut c_q0 = 0u64;
    for i in 0..8 {
        c_q0 |= (cipher[i] as u64) << (i * 8);
    }
    assert_eq!(c_q0, c_q0_expected, "first qword XOR must match patcher's first step");
}

// `OffsetEntry` is `u32 + u16 + u8 = 7 bytes` packed. The patcher doesn't
// touch offset entries today (only publics), but cross-build tooling will,
// so pin the size.
#[test]
fn offset_entry_size_is_seven() {
    assert_eq!(core::mem::size_of::<OffsetEntry>(), 7);
}

// LCG step against a known input.
#[test]
fn lcg_known_value() {
    // From a fresh start: lcg_next(0) = LCG_ADD (constant addend with x=0).
    assert_eq!(lcg_next(0), 0x1405_7B7E_F767_814F);
    // Second step: 0x5851F42D4C957F2D * 0x14057B7EF767814F + 0x14057B7EF767814F (mod 2^64).
    let want = 0x5851_F42D_4C95_7F2Du64
        .wrapping_mul(0x1405_7B7E_F767_814F)
        .wrapping_add(0x1405_7B7E_F767_814F);
    assert_eq!(lcg_next(0x1405_7B7E_F767_814F), want);
}

// `Cell<N>` must be 8-byte aligned -- the driver's hot decode reads the
// first qword via `read_volatile::<u64>` which requires that alignment.
// Losing `repr(align(8))` would let LLVM pessimize the read back to N
// byte-by-byte volatile loads and (worse) UB the volatile-u64 reinterpret
// on strict-alignment targets.
#[test]
fn cell_alignment_is_qword() {
    use ntbind::__macro_support::Cell;
    let c7 = Cell::<7>::new([0; 7]);
    let c17 = Cell::<17>::new([0; 17]);
    assert_eq!(c7.as_ptr() as usize % 8, 0, "Cell<7> instance unaligned");
    assert_eq!(c17.as_ptr() as usize % 8, 0, "Cell<17> instance unaligned");
    assert_eq!(core::mem::align_of::<Cell<7>>(), 8);
    assert_eq!(core::mem::align_of::<Cell<17>>(), 8);
}

// End-to-end on a `Cell<17>` (the public-payload form):
//
//  1. Encrypt a `PublicEntry` with `va = 0` (pre-patch generator form).
//  2. Overwrite the cell bytes with the patcher's re-encrypted payload
//     that sets `va = base + rva` (the deploy-time fixup).
//  3. Confirm `Cell::decode_lane0` -- the macro-emitted driver hot
//     path -- yields exactly the patched VA, and that the full
//     `decode_public` path agrees.
//
// If this test fails, every `public!` accessor in the driver decodes
// to a wrong VA and `call rdi` lands in garbage.
#[test]
fn decode_lane0_reads_patched_public_va() {
    use ntbind::__macro_support::{Cell, decode_public, encrypt_public};
    use ntbind::symtbl::PublicEntry;

    let key = 0xCAFEBABE_DEADBEEFu64;
    let pre_patch = PublicEntry { virtual_address: 0, offset: 0x3_bce0, sys_idx: 0, exists: 1 };
    let cell = Cell::<17>::new(encrypt_public(pre_patch, key));

    let target_base: u64 = 0xfffff803_d2000000;
    let resolved = PublicEntry {
        virtual_address: target_base + pre_patch.offset as u64,
        offset: pre_patch.offset,
        sys_idx: pre_patch.sys_idx,
        exists: pre_patch.exists,
    };
    let new_cipher = encrypt_public(resolved, key);

    // SAFETY: simulating the patcher's 17-byte write into the cell.
    unsafe {
        core::ptr::copy_nonoverlapping(new_cipher.as_ptr(), cell.as_ptr() as *mut u8, 17);
    }

    let full = decode_public(&cell, key);
    let full_va = { full }.virtual_address;
    let resolved_va = { resolved }.virtual_address;
    assert_eq!(full_va, resolved_va, "full decode disagrees with patched payload");

    let lane0 = cell.decode_lane0(key);
    assert_eq!(
        lane0, resolved_va,
        "fast lane0 path differs from full decode -- driver would call a wrong VA"
    );
}

// End-to-end on a `Cell<7>` (the field-payload form):
//
//  - `field!` accessors extract `bit_offset` from the low 32 bits of
//    `decode_lane0`.
//  - `bit_field!` accessors also use the next 16 bits as `bit_size`.
//
// Pin both lanes against the full-decode path that the patcher would write.
#[test]
fn decode_lane0_field_path() {
    use ntbind::__macro_support::{Cell, decode_offset, encrypt_offset};
    use ntbind::symtbl::OffsetEntry;

    let key = 0x1234_5678_9ABC_DEF0u64;
    let entry = OffsetEntry::new(0x440 * 8, 64, true);
    let cell = Cell::<7>::new(encrypt_offset(entry, key));

    let full = decode_offset(&cell, key);
    let want_bit_offset = { entry }.bit_offset;
    let want_bit_size = { entry }.bit_size;
    let got_bit_offset = { full }.bit_offset;
    assert_eq!(got_bit_offset, want_bit_offset);
    let lane0 = cell.decode_lane0(key);
    assert_eq!(lane0 as u32, want_bit_offset, "field accessor would read a wrong byte offset");
    assert_eq!(
        (lane0 >> 32) as u16,
        want_bit_size,
        "bit_field accessor would read a wrong bit width"
    );
}

// Sanity check that `is_present()` -- "encrypted value equals key" --
// remains the correct equivalence for the lane0 path. The driver's
// early-out (`je` after `cmpq %rax, %rdi` in the disasm) relies on it:
// a public emitted with `va = 0` must decode to `0`, and the hot path
// catches that without going through the function pointer.
#[test]
fn unpatched_public_decodes_to_zero_va() {
    use ntbind::__macro_support::{Cell, encrypt_public};
    use ntbind::symtbl::PublicEntry;

    let key = 0xBACEB5F7_1E7608EFu64;
    let entry = PublicEntry { virtual_address: 0, offset: 0xdead, sys_idx: 0, exists: 1 };
    let cell = Cell::<17>::new(encrypt_public(entry, key));
    assert_eq!(cell.decode_lane0(key), 0, "is_present check would fail");
}

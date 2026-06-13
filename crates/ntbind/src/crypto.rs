//! XOR-LCG cipher used to encrypt symbol-table payloads.
//!
//! `ntbind-patch` uses the same constants on the rewrite side; do not
//! edit without re-running it against a freshly built artifact to
//! confirm bit-identity.

/// LCG step constant -- `0x5851F42D4C957F2D`.
pub const LCG_MUL: u64 = 0x5851_F42D_4C95_7F2D;
/// LCG addend -- `0x14057B7EF767814F`.
pub const LCG_ADD: u64 = 0x1405_7B7E_F767_814F;

/// Advance the per-entry key by one LCG step.
#[inline]
#[must_use]
pub const fn lcg_next(key: u64) -> u64 {
    LCG_MUL.wrapping_mul(key).wrapping_add(LCG_ADD)
}

/// Encodes or decode an `N`-byte block in place.
///
/// XOR every 8-byte lane with an LCG-advancing key; the final lane is padded
/// out (the tail bytes still get covered, just by a key that ratcheted forward
/// for an unused qword). The operation is its own inverse for a fixed `key`.
///
/// Uses a single-XOR path for `N <= 8` and a generic byte-packed path
/// otherwise.
#[inline]
#[must_use]
pub const fn encode_decode<const N: usize>(input: [u8; N], key: u64) -> [u8; N] {
    if N == 0 {
        return input;
    }
    // Note: `key == 0` is NOT a no-op for `N > 8`.  Lane 0 XORs with
    // `key == 0` (identity), but lane 1 XORs with `lcg_next(0) =
    // LCG_ADD`, lane 2 with `lcg_next(lcg_next(0))`, etc.  This
    // matters because the C++ side runs the same loop -- both sides
    // must agree byte-for-byte, even in plaintext mode where only
    // lane 0 ends up readable without the LCG.

    // Pack into ceil(N/8) qwords (little-endian).
    let qword_count = N.div_ceil(8);
    let mut qwords = [0u64; 64]; // upper bound -- N <= 256 in practice
    assert!(qword_count <= 64, "ntbind::crypto block too large");

    let mut i = 0;
    while i < N {
        qwords[i >> 3] |= (input[i] as u64) << ((i & 7) << 3);
        i += 1;
    }

    let mut k = key;
    let mut j = 0;
    while j < qword_count {
        qwords[j] ^= k;
        k = lcg_next(k);
        j += 1;
    }

    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (qwords[i >> 3] >> ((i & 7) << 3)) as u8;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcg_step_known_values() {
        // Known LCG values for sentinel inputs.
        assert_eq!(lcg_next(0), LCG_ADD);
        assert_eq!(lcg_next(LCG_ADD), LCG_MUL.wrapping_mul(LCG_ADD).wrapping_add(LCG_ADD));
    }

    #[test]
    fn encode_is_its_own_inverse() {
        let key = 0xdead_beef_cafe_f00du64;
        let plaintext = *b"\x05\x00\x00\x00\x20\x00\x01";
        let cipher = encode_decode::<7>(plaintext, key);
        assert_ne!(cipher, plaintext);
        assert_eq!(encode_decode::<7>(cipher, key), plaintext);
    }

    #[test]
    fn small_lane_matches_simple_xor() {
        // Fast path for N<=8 collapses to a single xor with key.
        let key = 0x1122_3344_5566_7788u64;
        let plain = [0xAAu8; 8];
        let mut expected = [0u8; 8];
        for i in 0..8 {
            expected[i] = plain[i] ^ ((key >> (i * 8)) as u8);
        }
        assert_eq!(encode_decode::<8>(plain, key), expected);
    }
}

//! Implementation details exposed to the [`field!`](crate::field!) and
//! [`public!`](crate::public!) macros. Not a stable API.
//!
//! Each call site expands to a payload cell in [`SYM_TBL_DISCARD_SECTION`]
//! and a [`HeaderWithName`] in [`SYM_TBL_LIST_SECTION`] pointing at it; the
//! accessor reads the payload via [`core::ptr::read_volatile`].

use core::cell::UnsafeCell;
use core::ffi::c_void;

use crate::crypto::encode_decode;
use crate::symtbl::{OffsetEntry, PublicEntry};

/// Mutable storage cell for an encrypted payload. The patcher writes new
/// bytes here at deploy time; the running driver reads via `read_volatile`.
/// `UnsafeCell` is required so the patcher can mutate the static and so
/// `read_volatile` is not constant-folded.
// `repr(C, align(8))` lets the hot accessor path issue one
// `read_volatile::<u64>` instead of N byte-by-byte loads. Cells grow 1-7
// bytes of trailing pad on disk; the patcher walks them through their
// header pointer so the pad is invisible to the wire format.
#[repr(C, align(8))]
pub struct Cell<const N: usize> {
    inner: UnsafeCell<[u8; N]>,
}

impl<const N: usize> Cell<N> {
    #[inline]
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { inner: UnsafeCell::new(bytes) }
    }

    #[inline]
    #[must_use]
    pub const fn as_ptr(&self) -> *const c_void {
        self.inner.get() as *const c_void
    }

    /// Reads all `N` bytes through a volatile load.  Used by the
    /// patcher path and tests; the hot driver accessor goes through
    /// [`Cell::decode_lane0`] which only touches the qword actually
    /// consumed.
    #[inline]
    pub fn read(&self) -> [u8; N] {
        // SAFETY: `self.inner.get()` is a valid pointer to `[u8; N]`.
        // We only ever read; concurrent writes only happen pre-load
        // (patcher) and are not observed at runtime.
        unsafe { core::ptr::read_volatile(self.inner.get()) }
    }

    /// Reads and decrypts the first qword of the payload via one volatile
    /// `u64` load. XOR-LCG's first lane reduces to `cipher ^ key`, so this
    /// returns the plaintext low 8 bytes -- `bit_offset` / `bit_size` for
    /// [`OffsetEntry`], `virtual_address` for [`PublicEntry`]. The cell's
    /// `align(8)` invariant keeps the cast to `*const u64` well-aligned.
    #[inline]
    pub fn decode_lane0(&self, key: u64) -> u64 {
        // SAFETY: align(8) on `Cell<N>` plus `inner` being the first
        // field means the inner storage starts at an 8-byte boundary.
        // The volatile load prevents the compiler from constant-folding
        // the pre-patch ciphertext through the static.
        unsafe { core::ptr::read_volatile(self.inner.get() as *const u64) ^ key }
    }
}

// SAFETY: payload bytes are effectively immutable from the
// driver's perspective -- only `read_volatile` is performed on them at runtime.
// Patcher writes happen before the image is loaded.
unsafe impl<const N: usize> Sync for Cell<N> {}

/// Encodes an [`OffsetEntry`] into its 7-byte wire form, then encrypt with
/// `key`. Constant-evaluable so the result is baked into the static.
#[inline]
#[must_use]
pub const fn encrypt_offset(entry: OffsetEntry, key: u64) -> [u8; 7] {
    encode_decode::<7>(entry.to_bytes(), key)
}

/// Encodes a [`PublicEntry`] into its 17-byte wire form, then encrypt.
#[inline]
#[must_use]
pub const fn encrypt_public(entry: PublicEntry, key: u64) -> [u8; 17] {
    encode_decode::<17>(entry.to_bytes(), key)
}

/// Decrypt and unpack an offset payload at runtime.
#[inline]
pub fn decode_offset(cell: &Cell<7>, key: u64) -> OffsetEntry {
    OffsetEntry::from_bytes(encode_decode::<7>(cell.read(), key))
}

/// Decrypt and unpack a public payload at runtime.
#[inline]
pub fn decode_public(cell: &Cell<17>, key: u64) -> PublicEntry {
    PublicEntry::from_bytes(encode_decode::<17>(cell.read(), key))
}

/// Converts a raw masked bitfield value into the user's target type, applying
/// sign extension when `signed`. The `u64` / `i64` lanes keep monomorphization
/// shared across `bool`, `u8`..`u64`, `i8`..`i64` targets.
#[inline]
pub fn bitfield_extract<T: BitfieldOutput>(raw: u64, bit_size: u32, signed: bool) -> T {
    if signed && bit_size < 64 {
        // Sign-extend: detect the sign bit at position bit_size-1 and OR
        // the high bits if it's set.
        let sign_bit = 1u64 << (bit_size - 1);
        let mask = if bit_size >= 64 { u64::MAX } else { (1u64 << bit_size) - 1 };
        let extended = if raw & sign_bit != 0 { (raw | !mask) as i64 } else { raw as i64 };
        T::from_i64(extended)
    } else {
        T::from_u64(raw)
    }
}

/// Implemented by every type a bitfield accessor can return. Carries both
/// the `u64` (unsigned) and `i64` (signed-extended) conversion paths so the
/// `bitfield_extract` helper stays monomorphization-cheap.
pub trait BitfieldOutput: Copy + 'static {
    fn from_u64(v: u64) -> Self;
    fn from_i64(v: i64) -> Self;
    // Convert back to a `u64` lane for storage round-trip. For unsigned
    // targets this is a zero-extend; for signed it preserves the bit
    // pattern (the caller masks down to the field's bit width).
    //
    fn to_u64(self) -> u64;
}

/// Convenience wrapper used by `bit_field!`'s setter -- narrows the user's
/// value down to a `u64` lane for the read-modify-write.
#[inline]
pub fn bitfield_to_u64<T: BitfieldOutput>(value: T) -> u64 {
    value.to_u64()
}

/// Volatile byte-by-byte read of a `T` value from a possibly-unaligned
/// pointer. The kernel may mutate the underlying field while we read; the
/// volatile semantics prevent the compiler from caching or reordering the
/// load past a memory dependency. Returns the bytes interpreted as `T`
/// via [`core::mem::transmute_copy`] (so any `Copy + 'static` `T` works
/// without further trait bounds).
///
/// # Safety
/// - `ptr` must point at `size_of::<T>()` valid bytes for the duration of
///   the call.
/// - The kernel must keep the field's storage live across this read.
/// - The bit pattern at `ptr` must be a valid `T`.
#[inline]
#[allow(clippy::needless_range_loop)] // volatile reads must run in index order
pub unsafe fn read_volatile_bytes<T: Copy + 'static>(ptr: *const u8) -> T {
    let n = ::core::mem::size_of::<T>();
    debug_assert!(n <= 16, "read_volatile_bytes is intended for primitives <= 16 B");
    let mut buf = [0u8; 16];
    // SAFETY: caller's invariants.
    unsafe {
        for i in 0..n {
            buf[i] = ::core::ptr::read_volatile(ptr.add(i));
        }
        ::core::mem::transmute_copy::<[u8; 16], T>(&buf)
    }
}

/// Volatile byte-by-byte write of a `T` value at a possibly-unaligned
/// pointer. Mirror of [`read_volatile_bytes`] for the write direction.
///
/// # Safety
/// - `ptr` must point at `size_of::<T>()` valid bytes the caller may write
///   (exclusive access).
/// - The caller must respect any kernel synchronization invariants for
///   the target field.
#[inline]
#[allow(clippy::needless_range_loop)] // volatile writes must run in index order
pub unsafe fn write_volatile_bytes<T: Copy + 'static>(ptr: *mut u8, value: T) {
    let n = ::core::mem::size_of::<T>();
    debug_assert!(n <= 16, "write_volatile_bytes is intended for primitives <= 16 B");
    let mut buf = [0u8; 16];
    // SAFETY: T is Copy + 'static and <= 16 B; transmute_copy reads exactly
    // size_of::<T>() bytes from the source.
    unsafe {
        ::core::ptr::write(&mut buf as *mut [u8; 16] as *mut T, value);
        for i in 0..n {
            ::core::ptr::write_volatile(ptr.add(i), buf[i]);
        }
    }
}

macro_rules! impl_bitfield_output_uint {
    ($($t:ty),*) => {$(
        impl BitfieldOutput for $t {
            #[inline]
            fn from_u64(v: u64) -> Self { v as $t }
            #[inline]
            fn from_i64(v: i64) -> Self { v as $t }
            #[inline]
            fn to_u64(self) -> u64 { self as u64 }
        }
    )*};
}
macro_rules! impl_bitfield_output_int {
    ($($t:ty),*) => {$(
        impl BitfieldOutput for $t {
            #[inline]
            fn from_u64(v: u64) -> Self { v as $t }
            #[inline]
            fn from_i64(v: i64) -> Self { v as $t }
            #[inline]
            fn to_u64(self) -> u64 { (self as i64) as u64 }
        }
    )*};
}
impl_bitfield_output_uint!(u8, u16, u32, u64, usize);
impl_bitfield_output_int!(i8, i16, i32, i64, isize);

impl BitfieldOutput for bool {
    #[inline]
    fn from_u64(v: u64) -> Self {
        v != 0
    }
    #[inline]
    fn from_i64(v: i64) -> Self {
        v != 0
    }
    #[inline]
    fn to_u64(self) -> u64 {
        self as u64
    }
}

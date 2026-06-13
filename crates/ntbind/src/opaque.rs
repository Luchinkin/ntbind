//! Opaque fixed-size storage backing generated SDK types.
//!
//! Each generated type has a fixed canonical byte size taken from the PDB;
//! the body is opaque and all field access goes through accessor methods
//! that resolve runtime offsets. Alignment defaults to pointer width and is
//! overridden via `repr(align(N))` when the PDB layout demands more.

/// Opaque inline storage for a generated SDK type with fixed canonical size.
#[repr(C, align(8))]
pub struct Opaque<const SIZE: usize> {
    _raw: [u8; SIZE],
}

impl<const SIZE: usize> Opaque<SIZE> {
    /// Zero-initialized storage. Useful for stack-allocating the type in
    /// tests; production code should always work through a pointer or
    /// reference coming from the kernel.
    #[inline]
    #[must_use]
    pub const fn zeroed() -> Self {
        Self { _raw: [0; SIZE] }
    }

    /// Base pointer for offset arithmetic.
    #[inline]
    #[must_use]
    pub const fn as_ptr(&self) -> *const u8 {
        self._raw.as_ptr()
    }

    /// Mutable base pointer.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self._raw.as_mut_ptr()
    }
}

/// Reads a `T` value at a byte-offset within `this`, performing no bounds
/// checking. Generator-emitted accessors call this through the [`field!`](crate::field!)
/// macro after resolving the runtime offset.
///
/// # Safety
/// - `this` must point at a valid `Opaque<SIZE>` (or a layout-compatible
///   struct from generated code).
/// - `byte_offset + size_of::<T>()` must lie within the storage of `*this`.
/// - The bytes at the target offset must currently be a valid `T`.
#[inline]
#[must_use]
pub const unsafe fn field_ptr<T>(this: *const u8, byte_offset: usize) -> *const T {
    // SAFETY: pointer arithmetic delegated to the caller's invariants.
    unsafe { this.add(byte_offset).cast::<T>() }
}

/// Mutable counterpart of [`field_ptr`].
///
/// # Safety
/// Same as [`field_ptr`], plus exclusive access for the duration of writes.
#[inline]
pub const unsafe fn field_ptr_mut<T>(this: *mut u8, byte_offset: usize) -> *mut T {
    // SAFETY: see [`field_ptr`].
    unsafe { this.add(byte_offset).cast::<T>() }
}

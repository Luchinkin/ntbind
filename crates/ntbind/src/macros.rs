//! User-facing declarative macros emitted by the generator. [`field!`],
//! [`bit_field!`], [`public!`], and [`struct_summary!`] each expand to a
//! per-call-site `__PAYLOAD` static in `.symdsc` plus a `__HEADER` in
//! `.symtbl$list`, plus an accessor that reads the payload via volatile
//! loads.

/// Declares a byte-aligned field accessor on an SDK struct.
///
/// Expands to a `pub fn $name(&self) -> *const $ty` method whose body
/// resolves the field's byte offset from the runtime symbol table and
/// returns a pointer into the opaque storage.
///
/// ```ignore
/// impl OptionsT {
///     ntbind::field! {
///         name = version,
///         ty = u32,
///         identifier = b"_BOOT_OPTIONS.Version\0",
///         offset_bits = 0,
///         size_bits = 32,
///         exists = true,
///         key = 0xa79debf49fdb6a93u64,
///     }
/// }
/// ```
#[macro_export]
macro_rules! field {
    (
        name = $name:ident,
        ty = $ty:ty,
        identifier = $id:literal,
        offset_bits = $boff:expr,
        size_bits = $bsize:expr,
        exists = $exists:expr,
        key = $key:expr $(,)?
    ) => {
        #[inline]
        pub fn $name(&self) -> *const $ty {
            $crate::__field_emit!(
                identifier = $id,
                offset_bits = $boff,
                size_bits = $bsize,
                exists = $exists,
                key = $key,
            );
            // `decode_lane0` returns the plaintext low qword (single u64
            // volatile load + xor); `bit_offset` lives in the low 32
            // bits, so the byte offset is `(lane0 as u32) >> 3`.
            let lane0 = __PAYLOAD.decode_lane0($key);
            let byte_off = ((lane0 as u32) >> 3) as usize;
            // SAFETY: generator promises `byte_off + size_of::<$ty>() <= SIZE`
            // for the canonical build the SDK was generated against; the
            // patcher resolves to a valid same-bounds offset on every other
            // build it has a PDB for.  When a field is absent on the
            // target build the wire-format sentinel `bit_offset = MAX`
            // makes `byte_off` a large but harmless value; callers that
            // need an availability check should read the bit_offset
            // directly via `<TYPE>::<FIELD>_BIT_OFFSET` and compare
            // against the sentinel.
            unsafe { (self as *const Self as *const u8).add(byte_off).cast::<$ty>() }
        }
    };
}

/// Internal: emit the per-accessor symbol-table statics. Shared between
/// every public-facing macro flavor.
#[macro_export]
#[doc(hidden)]
macro_rules! __field_emit {
    (
        identifier = $id:literal,
        offset_bits = $boff:expr,
        size_bits = $bsize:expr,
        exists = $exists:expr,
        key = $key:expr $(,)?
    ) => {
        #[unsafe(link_section = ".symdsc")]
        #[used]
        static __PAYLOAD: $crate::__macro_support::Cell<7> =
            $crate::__macro_support::Cell::new($crate::__macro_support::encrypt_offset(
                $crate::symtbl::OffsetEntry::new($boff, $bsize, $exists),
                $key,
            ));

        #[unsafe(link_section = ".symtbl$list")]
        #[used]
        static __HEADER: $crate::symtbl::HeaderWithName<{ $id.len() }> =
            $crate::symtbl::HeaderWithName::new(__PAYLOAD.as_ptr(), $key, *$id);
    };
}

/// Declares a *bitfield* accessor.
///
/// The PDB carries the bit-level offset and bit width of the field plus an
/// underlying integer storage type (`storage_bytes` = 1/2/4/8). At runtime
/// we align the read down to a storage-word boundary, shift right by the
/// in-word offset, mask to `size_bits`, then sign- or zero-extend.
///
/// ```ignore
/// impl FooT {
///     ntbind::bit_field! {
///         name = is_enabled,
///         ty = bool,
///         identifier = b"_FOO.IsEnabled\0",
///         offset_bits = 35,
///         size_bits = 1,
///         storage_bytes = 4,
///         signed = false,
///         exists = true,
///         key = 0xa79debf49fdb6a93u64,
///     }
/// }
/// ```
#[macro_export]
macro_rules! bit_field {
    (
        name = $name:ident,
        setter = $setter:ident,
        ty = $ty:ty,
        identifier = $id:literal,
        offset_bits = $boff:expr,
        size_bits = $bsize:expr,
        storage_bytes = $sb:expr,
        signed = $signed:expr,
        exists = $exists:expr,
        key = $key:expr $(,)?
    ) => {
        /// Reads the bitfield value.
        #[inline]
        pub fn $name(&self) -> $ty {
            $crate::__field_emit!(
                identifier = $id,
                offset_bits = $boff,
                size_bits = $bsize,
                exists = $exists,
                key = $key,
            );
            // One u64 volatile load covers both `bit_offset` (low 32
            // bits) and `bit_size` (next 16 bits).
            let lane0 = __PAYLOAD.decode_lane0($key);
            let bit_offset = (lane0 as u32) as usize;
            let bit_size_from_payload = (lane0 >> 32) as u16 as u32;
            let bit_size: u32 =
                if bit_size_from_payload != 0 { bit_size_from_payload } else { $bsize as u32 };
            let storage: usize = $sb as usize;
            debug_assert!(matches!(storage, 1 | 2 | 4 | 8));
            let aligned_byte = (bit_offset / 8) & !(storage - 1);
            let in_word_shift = (bit_offset - aligned_byte * 8) as u32;
            let base = self as *const Self as *const u8;
            // SAFETY: the generator guarantees the storage word fits inside
            // the canonical struct size.
            let word: u64 = unsafe {
                let p = base.add(aligned_byte);
                match storage {
                    1 => ::core::ptr::read_unaligned(p) as u64,
                    2 => ::core::ptr::read_unaligned(p as *const u16) as u64,
                    4 => ::core::ptr::read_unaligned(p as *const u32) as u64,
                    8 => ::core::ptr::read_unaligned(p as *const u64),
                    _ => 0,
                }
            };
            let mask: u64 = if bit_size >= 64 { u64::MAX } else { (1u64 << bit_size) - 1 };
            let raw: u64 = (word >> in_word_shift) & mask;
            $crate::__macro_support::bitfield_extract::<$ty>(raw, bit_size, $signed)
        }

        /// Writes the bitfield via a read-modify-write of its storage word.
        /// Bits outside the field are preserved.
        ///
        /// # Safety
        /// Caller must hold a unique reference to the struct's storage and
        /// respect any kernel synchronization invariants for the target
        /// field's storage word -- other bitfields packed into the same word
        /// share the same RMW window.
        ///
        /// Emits a second `.symtbl` entry for the same identifier so the
        /// setter has its own offset lookup. The patcher updates both
        /// entries identically -- wire format stays correct.
        #[inline]
        pub unsafe fn $setter(&mut self, value: $ty) {
            $crate::__field_emit!(
                identifier = $id,
                offset_bits = $boff,
                size_bits = $bsize,
                exists = $exists,
                key = $key,
            );
            // See [`field!`] for the lane0 path; the setter needs both
            // `bit_offset` and `bit_size` to compute the storage word.
            let lane0 = __PAYLOAD.decode_lane0($key);
            let bit_offset = (lane0 as u32) as usize;
            let bit_size_from_payload = (lane0 >> 32) as u16 as u32;
            let bit_size: u32 =
                if bit_size_from_payload != 0 { bit_size_from_payload } else { $bsize as u32 };
            let storage: usize = $sb as usize;
            let aligned_byte = (bit_offset / 8) & !(storage - 1);
            let in_word_shift = (bit_offset - aligned_byte * 8) as u32;
            let mask: u64 = if bit_size >= 64 { u64::MAX } else { (1u64 << bit_size) - 1 };
            let value_bits: u64 = $crate::__macro_support::bitfield_to_u64::<$ty>(value) & mask;
            let base = self as *mut Self as *mut u8;
            // SAFETY: bounds checked by canonical-size invariant on the
            // storage word (same as the reader path).
            unsafe {
                let p = base.add(aligned_byte);
                match storage {
                    1 => {
                        let w = ::core::ptr::read_unaligned(p) as u64;
                        let w = (w & !(mask << in_word_shift)) | (value_bits << in_word_shift);
                        ::core::ptr::write_unaligned(p, w as u8);
                    },
                    2 => {
                        let pp = p as *mut u16;
                        let w = ::core::ptr::read_unaligned(pp) as u64;
                        let w = (w & !(mask << in_word_shift)) | (value_bits << in_word_shift);
                        ::core::ptr::write_unaligned(pp, w as u16);
                    },
                    4 => {
                        let pp = p as *mut u32;
                        let w = ::core::ptr::read_unaligned(pp) as u64;
                        let w = (w & !(mask << in_word_shift)) | (value_bits << in_word_shift);
                        ::core::ptr::write_unaligned(pp, w as u32);
                    },
                    8 => {
                        let pp = p as *mut u64;
                        let w = ::core::ptr::read_unaligned(pp);
                        let w = (w & !(mask << in_word_shift)) | (value_bits << in_word_shift);
                        ::core::ptr::write_unaligned(pp, w);
                    },
                    _ => {},
                }
            }
        }
    };
}
/// Declares a whole-struct size record for a generated SDK type.
///
/// ```ignore
/// ntbind::struct_summary! {
///     identifier = b"_EFI_FIRMWARE_INFORMATION.$\0",
///     byte_size = 0x38,
///     exists = true,
///     key = 0xdeadbeefcafef00du64,
/// }
/// ```
#[macro_export]
macro_rules! struct_summary {
    (
        identifier = $id:literal,
        byte_size = $size:expr,
        exists = $exists:expr,
        key = $key:expr $(,)?
    ) => {
        const _: () = {
            #[unsafe(link_section = ".symdsc")]
            #[used]
            static __PAYLOAD: $crate::__macro_support::Cell<7> =
                $crate::__macro_support::Cell::new($crate::__macro_support::encrypt_offset(
                    // bit_offset slot carries the BYTE SIZE; bit_size = 0
                    // matches the offset-entry shape for a struct-summary cell.
                    $crate::symtbl::OffsetEntry::new($size as u32, 0, $exists),
                    $key,
                ));

            #[unsafe(link_section = ".symtbl$list")]
            #[used]
            static __HEADER: $crate::symtbl::HeaderWithName<{ $id.len() }> =
                $crate::symtbl::HeaderWithName::new(__PAYLOAD.as_ptr(), $key, *$id);
        };
    };
}

/// Declares a free-function accessor for a kernel public.
///
/// ```ignore
/// ntbind::public! {
///     name = ke_bug_check,
///     ty = extern "C" fn(u32) -> !,
///     identifier = b"$KeBugCheck$ntoskrnl.exe\0",
///     rva_hint = 0x12345,
///     syscall_idx = 0,
///     exists = true,
///     key = 0xdeadbeefu64,
/// }
/// ```
#[macro_export]
macro_rules! public {
    (
        name = $name:ident,
        ty = $ty:ty,
        identifier = $id:literal,
        rva_hint = $rva:expr,
        syscall_idx = $sys:expr,
        exists = $exists:expr,
        key = $key:expr $(,)?
    ) => {
        #[inline]
        pub fn $name() -> $crate::public::Public<$ty> {
            #[unsafe(link_section = ".symdsc")]
            #[used]
            static __PAYLOAD: $crate::__macro_support::Cell<17> =
                $crate::__macro_support::Cell::new($crate::__macro_support::encrypt_public(
                    $crate::symtbl::PublicEntry {
                        virtual_address: 0,
                        offset: $rva,
                        sys_idx: $sys,
                        exists: $exists as u8,
                    },
                    $key,
                ));

            #[unsafe(link_section = ".symtbl$list")]
            #[used]
            static __HEADER: $crate::symtbl::HeaderWithName<{ $id.len() }> =
                $crate::symtbl::HeaderWithName::new(__PAYLOAD.as_ptr(), $key, *$id);

            // PublicEntry's `virtual_address` is the low 8 bytes; that
            // is exactly what `decode_lane0` returns.
            let va = __PAYLOAD.decode_lane0($key);
            $crate::public::Public::new(va)
        }
    };
}

//! Hand-written wrappers for common PDB-native primitives (`_LIST_ENTRY`,
//! `_UNICODE_STRING`, `_M128A`, `_KTRAP_FRAME`, `_CONTEXT`, `_XSAVE_FORMAT`,
//! `_KEXCEPTION_FRAME`, and string-view siblings).  The generator rewrites
//! these types into the wrappers below; all sizes are pinned to the
//! Windows x64 ABI.

use core::ffi::c_void;
use core::marker::PhantomData;

/// Equivalent of NT's `CONTAINING_RECORD(node, type, field)`.
///
/// Walks back from `node` (a pointer at `field_offset` bytes into an
/// enclosing `T`) to the start of `T`.  The generator emits a
/// `<TYPE>_OFFSET` const for every field so the offset is type-checked
/// at the call site:
///
/// ```ignore
/// let eproc = ntbind::nt::containing_record::<EprocessT>(
///     node,
///     EprocessT::ACTIVE_PROCESS_LINKS_OFFSET,
/// );
/// ```
#[inline]
#[must_use]
pub fn containing_record<T>(node: *const c_void, field_offset: usize) -> *const T {
    (node as usize).wrapping_sub(field_offset) as *const T
}

/// `LIST_ENTRY` -- 16 bytes, two intrusive linked-list pointers.
#[repr(C)]
pub struct ListEntryT {
    /// Forward pointer to the next entry.
    pub flink: *mut ListEntryT,
    /// Backward pointer to the previous entry.
    pub blink: *mut ListEntryT,
}

const _: () = assert!(core::mem::size_of::<ListEntryT>() == 16);

impl ListEntryT {
    /// Returns `true` when the list head's `flink` points at itself.
    /// Safe to call on a self-initialized head.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        core::ptr::eq(self.flink as *const Self, self as *const Self)
    }

    /// Walks `flink` until it loops back to `self`, returning each
    /// intermediate node as a `*const ListEntryT`.
    ///
    /// # Safety
    /// The list must remain coherent for the iterator's lifetime --
    /// either by holding the list lock or by being in a context where
    /// no concurrent insertions/removals can occur.  Caller treats the
    /// yielded pointers as raw kernel memory and dereferences them
    /// under whatever NT contract owns the list.
    #[inline]
    pub unsafe fn iter(&self) -> ListIter<'_> {
        ListIter {
            head: self as *const Self,
            cursor: self.flink as *const Self,
            _life: PhantomData,
        }
    }

    /// Counts entries by walking the list once.  O(N) and inherits the
    /// safety requirements of [`Self::iter`].
    ///
    /// # Safety
    /// See [`Self::iter`].
    #[inline]
    pub unsafe fn len(&self) -> usize {
        // SAFETY: caller upholds the iter contract.
        unsafe { self.iter().count() }
    }

    /// Removes `self` from the list it currently belongs to, fixing up
    /// its neighbors' `flink` / `blink` and pointing `self` at itself.
    ///
    /// # Safety
    /// `flink` and `blink` must point at valid `ListEntryT`s; caller
    /// holds the appropriate lock against concurrent traversal.
    #[inline]
    pub unsafe fn unlink(&mut self) {
        // SAFETY: caller upholds the contract above.
        unsafe {
            (*self.flink).blink = self.blink;
            (*self.blink).flink = self.flink;
        }
        let me: *mut Self = self;
        self.flink = me;
        self.blink = me;
    }

    /// Inserts `self` immediately after `prev`.
    ///
    /// # Safety
    /// `prev` and `prev->flink` must be valid `ListEntryT`s; caller
    /// holds the lock.
    #[inline]
    pub unsafe fn insert_after(&mut self, prev: *mut ListEntryT) {
        // SAFETY: caller upholds the contract above.
        unsafe {
            self.flink = (*prev).flink;
            self.blink = prev;
            (*prev).flink = self as *mut _;
            (*self.flink).blink = self as *mut _;
        }
    }

    /// Inserts `self` immediately before `next`.
    ///
    /// # Safety
    /// `next` and `next->blink` must be valid `ListEntryT`s; caller
    /// holds the lock.
    #[inline]
    pub unsafe fn insert_before(&mut self, next: *mut ListEntryT) {
        // SAFETY: caller upholds the contract above.
        unsafe {
            self.flink = next;
            self.blink = (*next).blink;
            (*next).blink = self as *mut _;
            (*self.blink).flink = self as *mut _;
        }
    }
}

/// Forward iterator over a circular `LIST_ENTRY` chain.  Yields each
/// node's raw pointer; stops when the walk loops back to the head.
///
/// Construct via [`ListEntryT::iter`] -- see that method's safety
/// contract.
pub struct ListIter<'a> {
    head: *const ListEntryT,
    cursor: *const ListEntryT,
    _life: PhantomData<&'a ListEntryT>,
}

impl<'a> Iterator for ListIter<'a> {
    type Item = *const ListEntryT;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.is_null() || core::ptr::eq(self.cursor, self.head) {
            return None;
        }
        let cur = self.cursor;
        // SAFETY: `cur` is a node within a kernel-owned chain whose
        // coherence the `iter()` caller has guaranteed for our lifetime.
        self.cursor = unsafe { (*cur).flink as *const _ };
        Some(cur)
    }
}

/// `UNICODE_STRING` -- wide-character counted slice.  The `_pad` u32
/// carries the natural 4-byte alignment hole introduced by the 8-byte
/// buffer pointer; kernel callers always observe it as zero.
#[repr(C)]
pub struct UnicodeView {
    /// Byte length of the in-use buffer (twice the character count).
    pub length: u16,
    /// Byte capacity of the buffer (>= `length`).
    pub maximum_length: u16,
    _pad: u32,
    /// Pointer to the wide-character buffer; may be null.
    pub buffer: *mut u16,
}

const _: () = assert!(core::mem::size_of::<UnicodeView>() == 16);

impl UnicodeView {
    /// Empty view -- `length = 0`, `buffer = null`.
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self { length: 0, maximum_length: 0, _pad: 0, buffer: core::ptr::null_mut() }
    }

    /// Borrows `slice` as the view's buffer.  The returned view
    /// borrows from `slice`; callers must not let it outlive that
    /// borrow.
    ///
    /// `length` and `maximum_length` are set to `slice.len() * 2`.
    /// Returns `None` when `slice.len() > 0x7FFF` (the encoded byte
    /// count would overflow `UNICODE_STRING.Length`'s `u16`).  No
    /// panic path -- the caller decides how to handle the overflow
    /// case (return an error, log, fall back, etc.).
    #[inline]
    #[must_use]
    pub const fn from_slice(slice: &[u16]) -> Option<Self> {
        let chars = slice.len();
        if chars > 0x7FFF {
            return None;
        }
        let bytes = (chars as u16) * 2;
        Some(Self {
            length: bytes,
            maximum_length: bytes,
            _pad: 0,
            buffer: slice.as_ptr() as *mut u16,
        })
    }

    /// Number of `u16` code units the view describes.
    #[inline]
    #[must_use]
    pub const fn len_chars(&self) -> usize {
        (self.length / 2) as usize
    }

    /// `true` when the view carries no characters (zero length or null
    /// buffer).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0 || self.buffer.is_null()
    }

    /// Borrows the underlying `u16` buffer as a slice.
    ///
    /// # Safety
    /// `buffer` must point at `length / 2` initialized `u16`s; that
    /// memory must outlive the returned slice and not be mutated for
    /// the slice's lifetime.
    #[inline]
    #[must_use]
    pub unsafe fn as_slice(&self) -> &[u16] {
        if self.is_empty() {
            return &[];
        }
        // SAFETY: caller upholds the contract above.
        unsafe { core::slice::from_raw_parts(self.buffer, self.len_chars()) }
    }
}

/// `UNICODE_STRING32` -- same shape, 32-bit pointer.
#[repr(C)]
pub struct UnicodeView32 {
    /// Byte length of the in-use buffer.
    pub length: u16,
    /// Byte capacity of the buffer.
    pub maximum_length: u16,
    /// 32-bit address of the buffer.
    pub buffer: u32,
}

const _: () = assert!(core::mem::size_of::<UnicodeView32>() == 8);

impl UnicodeView32 {
    #[inline]
    #[must_use]
    /// Empty view -- all fields zero.
    pub const fn empty() -> Self {
        Self { length: 0, maximum_length: 0, buffer: 0 }
    }

    #[inline]
    #[must_use]
    /// Number of `u16` code units the view describes.
    pub const fn len_chars(&self) -> usize {
        (self.length / 2) as usize
    }

    #[inline]
    #[must_use]
    /// `true` when the view carries no characters.
    pub const fn is_empty(&self) -> bool {
        self.length == 0 || self.buffer == 0
    }
}

/// `STRING` / `ANSI_STRING` -- byte-character counted slice.
#[repr(C)]
pub struct AsciiView {
    /// Byte length of the in-use buffer.
    pub length: u16,
    /// Byte capacity of the buffer (>= `length`).
    pub maximum_length: u16,
    _pad: u32,
    /// Pointer to the byte buffer; may be null.
    pub buffer: *mut u8,
}

const _: () = assert!(core::mem::size_of::<AsciiView>() == 16);

impl AsciiView {
    /// Borrows `slice` as the view's buffer.  Caller must not let the
    /// view outlive the slice borrow.
    ///
    /// Returns `None` when `slice.len() > u16::MAX` (the length would
    /// overflow `STRING.Length`'s `u16`).  No panic path -- the caller
    /// decides how to handle the overflow.
    #[inline]
    #[must_use]
    pub const fn from_slice(slice: &[u8]) -> Option<Self> {
        let n = slice.len();
        if n > u16::MAX as usize {
            return None;
        }
        let n16 = n as u16;
        Some(Self { length: n16, maximum_length: n16, _pad: 0, buffer: slice.as_ptr() as *mut u8 })
    }

    #[inline]
    #[must_use]
    /// Number of bytes the view describes.
    pub const fn len_bytes(&self) -> usize {
        self.length as usize
    }

    #[inline]
    #[must_use]
    /// `true` when the view carries no bytes.
    pub const fn is_empty(&self) -> bool {
        self.length == 0 || self.buffer.is_null()
    }

    /// Borrows the underlying byte buffer as a slice.
    ///
    /// # Safety
    /// `buffer` must point at `length` initialized bytes; that memory
    /// must outlive the returned slice and not be mutated for its
    /// lifetime.
    #[inline]
    #[must_use]
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.is_empty() {
            return &[];
        }
        // SAFETY: caller upholds the contract above.
        unsafe { core::slice::from_raw_parts(self.buffer, self.len_bytes()) }
    }
}

/// `STRING32` -- same shape, 32-bit pointer.
#[repr(C)]
pub struct AsciiView32 {
    /// Byte length of the in-use buffer.
    pub length: u16,
    /// Byte capacity of the buffer.
    pub maximum_length: u16,
    /// 32-bit address of the buffer.
    pub buffer: u32,
}

const _: () = assert!(core::mem::size_of::<AsciiView32>() == 8);

impl AsciiView32 {
    #[inline]
    #[must_use]
    /// Empty view -- all fields zero.
    pub const fn empty() -> Self {
        Self { length: 0, maximum_length: 0, buffer: 0 }
    }

    #[inline]
    #[must_use]
    /// Number of bytes the view describes.
    pub const fn len_bytes(&self) -> usize {
        self.length as usize
    }

    #[inline]
    #[must_use]
    /// `true` when the view carries no bytes.
    pub const fn is_empty(&self) -> bool {
        self.length == 0 || self.buffer == 0
    }
}

/// `M128A` -- 16-byte SSE-aligned value.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct M128aT {
    /// Low 64 bits.
    pub low: u64,
    /// High 64 bits.
    pub high: i64,
}

const _: () = assert!(core::mem::size_of::<M128aT>() == 16);

impl M128aT {
    #[inline]
    #[must_use]
    /// All-zero value.
    pub const fn zero() -> Self {
        Self { low: 0, high: 0 }
    }

    #[inline]
    #[must_use]
    /// Builds an `M128aT` from 16 little-endian bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        let low = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let high = i64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Self { low, high }
    }

    #[inline]
    #[must_use]
    /// Serializes the value to 16 little-endian bytes.
    pub const fn to_bytes(self) -> [u8; 16] {
        let lo = self.low.to_le_bytes();
        let hi = self.high.to_le_bytes();
        [
            lo[0], lo[1], lo[2], lo[3], lo[4], lo[5], lo[6], lo[7], hi[0], hi[1], hi[2], hi[3],
            hi[4], hi[5], hi[6], hi[7],
        ]
    }
}

/// `KTRAP_FRAME` -- opaque kernel trap frame storage.  Sized for the x64
/// ABI.
#[repr(C)]
pub struct Trapframe(pub [u8; 0x190]);

const _: () = assert!(core::mem::size_of::<Trapframe>() == 0x190);

/// `CONTEXT` -- opaque thread context.  Sized for the x64 ABI
/// (`size_of CONTEXT == 0x4D0` on Windows 10 / 11 x64).
#[repr(C, align(16))]
pub struct Context(pub [u8; 0x4d0]);

const _: () = assert!(core::mem::size_of::<Context>() == 0x4d0);

/// `XSAVE_FORMAT` -- FXSAVE area + XSAVE header, 0x200 bytes on x64.
#[repr(C, align(16))]
pub struct XsaveFormat(pub [u8; 0x200]);

const _: () = assert!(core::mem::size_of::<XsaveFormat>() == 0x200);

/// `KEXCEPTION_FRAME` -- opaque kernel exception frame, 0x140 bytes on
/// x64.
#[repr(C)]
pub struct Exframe(pub [u8; 0x140]);

const _: () = assert!(core::mem::size_of::<Exframe>() == 0x140);

// SAFETY markers: these types are POD; we expose raw pointers in some
// fields, but the kernel itself synchronizes them.  Send/Sync on
// `*mut T` is not auto-derived, so we keep them !Send + !Sync by
// omission -- callers own the synchronization story.
#[allow(dead_code)]
type _AssertNoSync = *const c_void;

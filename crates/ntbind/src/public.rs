//! Helpers for the export ("public") accessor path.
//!
//! A public is a kernel-mode symbol whose VA is filled in by the patcher;
//! [`Public<T>`] wraps the resolved address with conversions to any pointer
//! or function-pointer type the caller annotated.

use core::marker::PhantomData;

/// Typed wrapper around a resolved virtual address.
///
/// The generator names the type after the public's *hinted* signature; the
/// driver-side `T` is whatever the caller annotated. Carries no runtime
/// metadata beyond the address, so storage cost is exactly `usize`.
#[repr(transparent)]
pub struct Public<T: ?Sized> {
    va: u64,
    _marker: PhantomData<*const T>,
}

impl<T: ?Sized> Public<T> {
    /// Constructs from a virtual address. Returned by the accessor functions
    /// emitted by [`crate::public!`].
    #[inline]
    #[must_use]
    pub const fn new(va: u64) -> Self {
        Self { va, _marker: PhantomData }
    }

    /// Raw virtual address.
    #[inline]
    #[must_use]
    pub const fn addr(self) -> u64 {
        self.va
    }

    /// Non-null check. The patcher sets `va = 0` when the public doesn't
    /// exist on the target build.
    #[inline]
    #[must_use]
    pub const fn is_present(self) -> bool {
        self.va != 0
    }
}

impl<T> Public<T> {
    /// Reinterprets as `*const T`. Caller is responsible for `T`'s validity at
    /// the resolved address.
    #[inline]
    #[must_use]
    pub const fn as_ptr(self) -> *const T {
        self.va as *const T
    }

    /// Reinterprets as `*mut T`.
    #[inline]
    #[must_use]
    pub const fn as_mut_ptr(self) -> *mut T {
        self.va as *mut T
    }

    /// Reinterprets as `&'a T` for some externally chosen lifetime.
    ///
    /// # Safety
    /// The address must currently point at a valid `T`, exclusive of any
    /// concurrent writer for the lifetime `'a`.
    #[inline]
    pub const unsafe fn as_ref<'a>(self) -> &'a T {
        // SAFETY: delegated to caller per the contract above.
        unsafe { &*self.as_ptr() }
    }
}

impl<T: ?Sized> Copy for Public<T> {}
impl<T: ?Sized> Clone for Public<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: Copy> Public<F> {
    /// Reinterprets the resolved virtual address as a function pointer
    /// of type `F`, or returns `None` when the patcher has not resolved
    /// the public (`va == 0`).
    ///
    /// `F` is expected to be a function-pointer type the SDK already
    /// attached to this `Public` -- typically
    /// `unsafe extern "system" fn(...) -> ...`.  For ntbindgen-emitted
    /// publics the call site is
    /// `let f = unsafe { foo().as_fn()? };` -- `F` is inferred from
    /// `Self`.
    ///
    /// A `const` size-check guards against misuse of the `F: Copy`
    /// bound (which would otherwise admit `[u8; N]`, primitives wider
    /// than a word, etc.): if `size_of::<F>() != 8` the build fails
    /// rather than reading past the resolved VA at runtime.
    ///
    /// # Safety
    /// Caller asserts `F`'s ABI matches the resolved function's real
    /// signature.  The SDK-emitted callsite always satisfies this; a
    /// hand-written callsite is responsible for the match.
    #[inline]
    #[must_use]
    pub unsafe fn as_fn(self) -> Option<F> {
        const {
            assert!(
                core::mem::size_of::<F>() == core::mem::size_of::<u64>(),
                "Public::as_fn expects F to be a word-sized function pointer; \
                 use raw `.addr()` + `transmute` for non-fn-ptr targets.",
            );
        }
        if !self.is_present() {
            return None;
        }
        // SAFETY: caller upholds the ABI-match contract; the const
        // size-check above forbids non-word-sized `F`, so the copy
        // reads exactly `va`'s 8 bytes.
        Some(unsafe { core::mem::transmute_copy::<u64, F>(&self.va) })
    }
}

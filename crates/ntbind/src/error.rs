//! Error types produced by the generated SDK.
//!
//! The only one today is [`UnknownDiscriminant`], the `Err` payload of the
//! generated `TryFrom<underlying>` impl for every enum -- wraps the raw
//! integer in a typed error that implements [`core::error::Error`] so it
//! composes with `?` and downstream error stacks.

use core::fmt;

/// Error returned by an enum's `TryFrom<underlying>` impl when the supplied
/// integer doesn't match any known discriminant. `T` is the enum type, `U`
/// is the underlying integer kind (e.g. `i32`, `u64`); the unrecognized value
/// is carried so the caller can log or forward it.
pub struct UnknownDiscriminant<T, U: Copy + fmt::Debug + 'static> {
    value: U,
    _enum: core::marker::PhantomData<fn() -> T>,
}

impl<T, U: Copy + fmt::Debug + 'static> UnknownDiscriminant<T, U> {
    #[inline]
    #[must_use]
    /// Builds a wrapper around an unrecognized integer value.
    pub const fn new(value: U) -> Self {
        Self { value, _enum: core::marker::PhantomData }
    }

    #[inline]
    #[must_use]
    /// Returns the unrecognized integer value carried by this error.
    pub const fn value(&self) -> U {
        self.value
    }
}

impl<T, U: Copy + fmt::Debug + 'static> Clone for UnknownDiscriminant<T, U> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, U: Copy + fmt::Debug + 'static> Copy for UnknownDiscriminant<T, U> {}

impl<T, U: Copy + fmt::Debug + 'static> fmt::Debug for UnknownDiscriminant<T, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnknownDiscriminant")
            .field("value", &self.value)
            .field("enum", &core::any::type_name::<T>())
            .finish()
    }
}

impl<T, U: Copy + fmt::Debug + fmt::Display + 'static> fmt::Display for UnknownDiscriminant<T, U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown discriminant {} for enum {}", self.value, core::any::type_name::<T>())
    }
}

impl<T: 'static, U: Copy + fmt::Debug + fmt::Display + 'static> core::error::Error
    for UnknownDiscriminant<T, U>
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_value_and_type() {
        struct Foo;
        let e: UnknownDiscriminant<Foo, i32> = UnknownDiscriminant::new(42);
        let s = format!("{e}");
        assert!(s.contains("42"), "{s}");
        assert!(s.contains("Foo"), "{s}");
    }

    #[test]
    fn implements_core_error() {
        struct Bar;
        let e: UnknownDiscriminant<Bar, i32> = UnknownDiscriminant::new(7);
        let _: &dyn core::error::Error = &e;
    }

    #[test]
    fn value_round_trip() {
        struct Baz;
        let e: UnknownDiscriminant<Baz, u32> = UnknownDiscriminant::new(0xdead_beef);
        assert_eq!(e.value(), 0xdead_beef);
    }
}

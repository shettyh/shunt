use std::fmt;
use std::ops::{BitAnd, BitOr, BitOrAssign};

use serde::Serialize;

/// Bitmask declaring which lifecycle hooks a plugin or compiled route uses.
///
/// The core runner checks these bits on the hot path so routes without body
/// or hook plugins execute unbuffered and allocation-free.
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct HookMask(u32);

impl HookMask {
    pub const EMPTY: Self = Self(0);
    pub const ON_REQUEST_HEADERS: Self = Self(1 << 0);
    pub const REQUEST_BODY_BUFFERED: Self = Self(1 << 1);
    pub const REQUEST_BODY_STREAM: Self = Self(1 << 2);
    pub const ON_ROUTE: Self = Self(1 << 3);
    pub const ON_UPSTREAM_SELECT: Self = Self(1 << 4);
    pub const ON_UPSTREAM_REQUEST: Self = Self(1 << 5);
    pub const ON_RESPONSE_HEADERS: Self = Self(1 << 6);
    pub const RESPONSE_BODY_STREAM: Self = Self(1 << 7);
    pub const ON_COMPLETE: Self = Self(1 << 8);

    /// Creates a mask from raw bits.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the underlying raw bit representation.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if no hook bits are set.
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if all bits in `other` are set in `self`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` if any bit in `other` is set in `self`.
    #[inline]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Combines two masks in a `const` context.
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns human-readable names for all enabled flags in lifecycle order.
    pub fn flag_names(self) -> Vec<&'static str> {
        const FLAGS: &[(HookMask, &str)] = &[
            (HookMask::ON_REQUEST_HEADERS, "on_request_headers"),
            (HookMask::REQUEST_BODY_BUFFERED, "request_body_buffered"),
            (HookMask::REQUEST_BODY_STREAM, "request_body_stream"),
            (HookMask::ON_ROUTE, "on_route"),
            (HookMask::ON_UPSTREAM_SELECT, "on_upstream_select"),
            (HookMask::ON_UPSTREAM_REQUEST, "on_upstream_request"),
            (HookMask::ON_RESPONSE_HEADERS, "on_response_headers"),
            (HookMask::RESPONSE_BODY_STREAM, "response_body_stream"),
            (HookMask::ON_COMPLETE, "on_complete"),
        ];

        FLAGS
            .iter()
            .filter_map(|(flag, name)| self.contains(*flag).then_some(*name))
            .collect()
    }
}

impl BitOr for HookMask {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for HookMask {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for HookMask {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl fmt::Debug for HookMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.flag_names();
        if names.is_empty() {
            f.write_str("HookMask(EMPTY)")
        } else {
            write!(f, "HookMask({})", names.join(" | "))
        }
    }
}

impl fmt::Display for HookMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.flag_names();
        if names.is_empty() {
            f.write_str("EMPTY")
        } else {
            f.write_str(&names.join(" | "))
        }
    }
}

impl Serialize for HookMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.flag_names().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::HookMask;

    #[test]
    fn mask_operations() {
        let m = HookMask::ON_REQUEST_HEADERS | HookMask::RESPONSE_BODY_STREAM;
        assert!(!m.is_empty());
        assert!(m.contains(HookMask::ON_REQUEST_HEADERS));
        assert!(m.contains(HookMask::RESPONSE_BODY_STREAM));
        assert!(!m.contains(HookMask::REQUEST_BODY_BUFFERED));
        assert_eq!(
            m.flag_names(),
            vec!["on_request_headers", "response_body_stream"]
        );
        assert_eq!(HookMask::EMPTY.to_string(), "EMPTY");
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::HookMask;

    #[kani::proof]
    fn hook_mask_bitwise_algebra() {
        let a = HookMask::from_bits(kani::any());
        let b = HookMask::from_bits(kani::any());

        // Identity & emptiness
        assert!(HookMask::EMPTY.is_empty());
        assert_eq!(a | HookMask::EMPTY, a);
        assert_eq!(a & HookMask::EMPTY, HookMask::EMPTY);
        assert_eq!(a.union(b), a | b);

        // Commutativity & idempotence
        assert_eq!(a | b, b | a);
        assert_eq!(a & b, b & a);
        assert_eq!(a | a, a);
        assert_eq!(a & a, a);

        // Containment & intersection laws
        assert!((a | b).contains(a));
        assert!((a | b).contains(b));
        assert!(a.contains(a & b));
        if !b.is_empty() && a.contains(b) {
            assert!(a.intersects(b));
        }
    }
}

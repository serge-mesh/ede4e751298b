//! The 64-bit value of a domain key, an IP run or a cold record (bundles.md §4): `flags` in the low
//! 16 bits and `rich_idx` in the next 32. The top 16 bits are reserved (written as zero, ignored on
//! read so a later format can use them).

use picket_rules::Flags;

/// A key's or run's value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Value(pub u64);

impl Value {
    /// The mask of the bits this format defines.
    pub const DEFINED: u64 = 0x0000_ffff_ffff_ffff;

    /// A value from flags and a rich index (meaningful only with `HAS_RICH`; zero otherwise).
    pub fn new(flags: Flags, rich_idx: u32) -> Value {
        let rich = if flags.contains(Flags::HAS_RICH) {
            u64::from(rich_idx)
        } else {
            0
        };
        Value(u64::from(flags.bits()) | (rich << 16))
    }

    /// A value with flags only.
    pub fn flags_only(flags: Flags) -> Value {
        Value::new(flags.without(Flags::HAS_RICH), 0)
    }

    /// The 16 flag bits.
    pub fn flags(self) -> Flags {
        Flags((self.0 & 0xffff) as u16)
    }

    /// The rich index, when the value has `HAS_RICH`.
    pub fn rich_idx(self) -> Option<u32> {
        self.flags()
            .contains(Flags::HAS_RICH)
            .then_some(((self.0 >> 16) & 0xffff_ffff) as u32)
    }

    /// The value with the reserved bits cleared (how a reader takes a stored value).
    pub fn from_stored(v: u64) -> Value {
        Value(v & Self::DEFINED)
    }

    /// The level bits (`_EXACT` and `_SUBS`).
    pub fn levels(self) -> Flags {
        self.flags().and(Flags::ALL_LEVELS)
    }

    /// True for a plain block (`B_EXACT` and/or `B_SUBS` alone): the only values that may go cold
    /// (bundles.md §1) or into the IPv4 address set (`B_EXACT` alone, bundles.md §4).
    pub fn is_plain_block(self) -> bool {
        self.flags().is_plain_block()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let v = Value::new(Flags::B_EXACT | Flags::HAS_RICH, 7);
        assert_eq!(v.0, 0x0001 | 0x0100 | (7 << 16));
        assert_eq!(v.rich_idx(), Some(7));
        assert_eq!(Value::new(Flags::B_EXACT, 7).rich_idx(), None);
        assert_eq!(Value::new(Flags::B_EXACT, 7).0, 1);
        assert_eq!(Value::from_stored(u64::MAX).0, Value::DEFINED);
        assert!(Value::new(Flags::B_EXACT | Flags::B_SUBS, 0).is_plain_block());
    }
}

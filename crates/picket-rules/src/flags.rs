//! Key flags (bundles.md §4) and precedence levels (rules.md §4, bundles.md §6).

use std::fmt;

use serde::{Deserialize, Serialize};

/// The 16 flag bits of a compiled key, IP run or pattern (bundles.md §4). Bit positions are part
/// of the bundle format: never reorder them.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Flags(pub u16);

impl Flags {
    /// No flags.
    pub const NONE: Flags = Flags(0);
    /// Block at the name itself.
    pub const B_EXACT: Flags = Flags(1 << 0);
    /// Block at every name below it.
    pub const B_SUBS: Flags = Flags(1 << 1);
    /// Exception (`@@`) at the name itself.
    pub const A_EXACT: Flags = Flags(1 << 2);
    /// Exception at every name below it.
    pub const A_SUBS: Flags = Flags(1 << 3);
    /// `$important` block at the name itself.
    pub const IMP_B_EXACT: Flags = Flags(1 << 4);
    /// `$important` block below it.
    pub const IMP_B_SUBS: Flags = Flags(1 << 5);
    /// `@@…$important` at the name itself.
    pub const IMP_A_EXACT: Flags = Flags(1 << 6);
    /// `@@…$important` below it.
    pub const IMP_A_SUBS: Flags = Flags(1 << 7);
    /// The key has rich rules (`rich.json`).
    pub const HAS_RICH: Flags = Flags(1 << 8);

    /// Every `_EXACT` bit.
    pub const ALL_EXACT: Flags =
        Flags(Self::B_EXACT.0 | Self::A_EXACT.0 | Self::IMP_B_EXACT.0 | Self::IMP_A_EXACT.0);
    /// Every `_SUBS` bit.
    pub const ALL_SUBS: Flags =
        Flags(Self::B_SUBS.0 | Self::A_SUBS.0 | Self::IMP_B_SUBS.0 | Self::IMP_A_SUBS.0);
    /// Every level bit (exact and subs).
    pub const ALL_LEVELS: Flags = Flags(Self::ALL_EXACT.0 | Self::ALL_SUBS.0);
    /// Allow bits (`A_*`, `IMP_A_*`).
    pub const ALL_ALLOW: Flags =
        Flags(Self::A_EXACT.0 | Self::A_SUBS.0 | Self::IMP_A_EXACT.0 | Self::IMP_A_SUBS.0);
    /// Block bits (`B_*`, `IMP_B_*`).
    pub const ALL_BLOCK: Flags =
        Flags(Self::B_EXACT.0 | Self::B_SUBS.0 | Self::IMP_B_EXACT.0 | Self::IMP_B_SUBS.0);

    /// The raw bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// True when every bit of `other` is set.
    pub const fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }

    /// True when any bit of `other` is set.
    pub const fn intersects(self, other: Flags) -> bool {
        self.0 & other.0 != 0
    }

    /// Bitwise union.
    pub const fn union(self, other: Flags) -> Flags {
        Flags(self.0 | other.0)
    }

    /// Bitwise intersection.
    pub const fn and(self, other: Flags) -> Flags {
        Flags(self.0 & other.0)
    }

    /// `self` without the bits of `other`.
    pub const fn without(self, other: Flags) -> Flags {
        Flags(self.0 & !other.0)
    }

    /// True when no bit is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The `_EXACT` bits.
    pub const fn exact(self) -> Flags {
        self.and(Self::ALL_EXACT)
    }

    /// The `_SUBS` bits.
    pub const fn subs(self) -> Flags {
        self.and(Self::ALL_SUBS)
    }

    /// Each `_SUBS` bit moved to its `_EXACT` twin (and nothing else kept).
    pub const fn subs_as_exact(self) -> Flags {
        Flags((self.0 & Self::ALL_SUBS.0) >> 1)
    }

    /// Each `_EXACT` bit moved to its `_SUBS` twin (and nothing else kept).
    pub const fn exact_as_subs(self) -> Flags {
        Flags((self.0 & Self::ALL_EXACT.0) << 1)
    }

    /// Adds each level bit's `IMP_` twin (`$important`, bundles.md §4).
    pub const fn with_important(self) -> Flags {
        let b = self.0 & (Self::B_EXACT.0 | Self::B_SUBS.0 | Self::A_EXACT.0 | Self::A_SUBS.0);
        Flags(self.0 | (b << 4))
    }

    /// Moves block bits to their allow twins (`@@`, bundles.md §4).
    pub const fn as_exception(self) -> Flags {
        let b = self.0 & (Self::B_EXACT.0 | Self::B_SUBS.0 | Self::IMP_B_EXACT.0 | Self::IMP_B_SUBS.0);
        let rest = self.0 & !b;
        Flags(rest | (b << 2))
    }

    /// The flags that apply at a name: `_EXACT` bits when the key is the name itself, `_SUBS`
    /// bits (as their exact twins) when the key is a parent (bundles.md §6).
    pub const fn applying(self, at_name: bool) -> Flags {
        if at_name {
            self.exact()
        } else {
            self.subs_as_exact()
        }
    }

    /// The highest level among the level bits (bundles.md §6: `IMP_A` 1, `IMP_B` 2, `A` 3, `B` 4).
    pub fn top_level(self) -> Option<Level> {
        if self.intersects(Flags(Self::IMP_A_EXACT.0 | Self::IMP_A_SUBS.0)) {
            Some(Level::ImportantAllow)
        } else if self.intersects(Flags(Self::IMP_B_EXACT.0 | Self::IMP_B_SUBS.0)) {
            Some(Level::ImportantBlock)
        } else if self.intersects(Flags(Self::A_EXACT.0 | Self::A_SUBS.0)) {
            Some(Level::Allow)
        } else if self.intersects(Flags(Self::B_EXACT.0 | Self::B_SUBS.0)) {
            Some(Level::Block)
        } else {
            None
        }
    }

    /// True when the value is a plain block: `B_EXACT` and/or `B_SUBS` alone, the only values that
    /// may go cold (bundles.md §1).
    pub const fn is_plain_block(self) -> bool {
        self.0 != 0 && self.0 & !(Self::B_EXACT.0 | Self::B_SUBS.0) == 0
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(Flags, &str); 9] = [
            (Flags::B_EXACT, "B_EXACT"),
            (Flags::B_SUBS, "B_SUBS"),
            (Flags::A_EXACT, "A_EXACT"),
            (Flags::A_SUBS, "A_SUBS"),
            (Flags::IMP_B_EXACT, "IMP_B_EXACT"),
            (Flags::IMP_B_SUBS, "IMP_B_SUBS"),
            (Flags::IMP_A_EXACT, "IMP_A_EXACT"),
            (Flags::IMP_A_SUBS, "IMP_A_SUBS"),
            (Flags::HAS_RICH, "HAS_RICH"),
        ];
        let mut first = true;
        for (flag, name) in NAMES {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        let rest = self.0 & !0x01ff;
        if rest != 0 {
            if !first {
                f.write_str("|")?;
            }
            write!(f, "{rest:#06x}")?;
            first = false;
        }
        if first {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

impl std::ops::BitOr for Flags {
    type Output = Flags;
    fn bitor(self, rhs: Flags) -> Flags {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for Flags {
    fn bitor_assign(&mut self, rhs: Flags) {
        *self = self.union(rhs);
    }
}

impl std::ops::BitAnd for Flags {
    type Output = Flags;
    fn bitand(self, rhs: Flags) -> Flags {
        self.and(rhs)
    }
}

/// Precedence levels inside one bundle, highest first (rules.md §4, urlfilter `IsHigherPriority`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// `@@…$important`.
    ImportantAllow = 1,
    /// `…$important` (block).
    ImportantBlock = 2,
    /// `@@` (exception).
    Allow = 3,
    /// Block.
    Block = 4,
}

impl Level {
    /// True for the two allow levels.
    pub const fn is_allow(self) -> bool {
        matches!(self, Level::ImportantAllow | Level::Allow)
    }

    /// The `_EXACT` bit of this level.
    pub const fn exact_flag(self) -> Flags {
        match self {
            Level::ImportantAllow => Flags::IMP_A_EXACT,
            Level::ImportantBlock => Flags::IMP_B_EXACT,
            Level::Allow => Flags::A_EXACT,
            Level::Block => Flags::B_EXACT,
        }
    }

    /// The level number of bundles.md §6 (1 is the highest).
    pub const fn number(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twins() {
        let f = Flags::B_EXACT | Flags::B_SUBS;
        assert_eq!(f.with_important(), f | Flags::IMP_B_EXACT | Flags::IMP_B_SUBS);
        assert_eq!(f.as_exception(), Flags::A_EXACT | Flags::A_SUBS);
        assert_eq!(
            f.with_important().as_exception(),
            Flags::A_EXACT | Flags::A_SUBS | Flags::IMP_A_EXACT | Flags::IMP_A_SUBS
        );
        assert_eq!(Flags::IMP_B_SUBS.subs_as_exact(), Flags::IMP_B_EXACT);
        assert_eq!(Flags::A_EXACT.exact_as_subs(), Flags::A_SUBS);
        assert_eq!(
            (Flags::B_EXACT | Flags::IMP_B_EXACT).top_level(),
            Some(Level::ImportantBlock)
        );
        assert_eq!((Flags::B_SUBS | Flags::A_EXACT).top_level(), Some(Level::Allow));
        assert_eq!(Flags::HAS_RICH.top_level(), None);
        assert!(f.is_plain_block());
        assert!(!(f | Flags::HAS_RICH).is_plain_block());
        assert_eq!(format!("{:?}", f | Flags::HAS_RICH), "B_EXACT|B_SUBS|HAS_RICH");
    }

    #[test]
    fn applying() {
        let f = Flags::B_EXACT | Flags::A_SUBS;
        assert_eq!(f.applying(true), Flags::B_EXACT);
        assert_eq!(f.applying(false), Flags::A_EXACT);
    }
}

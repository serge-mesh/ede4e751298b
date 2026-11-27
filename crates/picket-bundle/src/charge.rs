//! A memory budget charged while deserialising untrusted JSON (README §2 "Bounded", "Untrusted
//! input"; edge.md §17; review round 2, CR1).
//!
//! [`Charged`] wraps a deserializer so that everything a value allocates is charged to a
//! [`Budget`] as it is parsed, however deeply nested and whatever the type: each sequence element
//! (`size_of` the element, and at the end the spare capacity std's `Vec` growth leaves), each map
//! entry, and each owned string's buffer, every allocation as the allocator takes it
//! ([`picket_rules::mem::alloc_bytes`]). Parsing stops with [`LIMITS`] as soon as the budget is
//! spent, so a list of millions of tiny items costs at most the budget, never the items' worth;
//! and what was charged is the memory the parsed value holds, which callers report. Struct fields,
//! tuples and arrays sit inside their parent's slot and cost nothing of their own; identifiers
//! (field and variant names) and skipped values are never kept.

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;

use picket_rules::mem::alloc_bytes;
use serde::de::{
    self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
};

/// The message parsing stops with when the budget is spent (or another limit is hit).
pub(crate) const LIMITS: &str = "rich.json is over its limits";

/// Bytes a parse may still allocate.
pub(crate) struct Budget {
    limit: usize,
    used: Cell<usize>,
}

impl Budget {
    pub fn new(limit: usize) -> Budget {
        Budget {
            limit,
            used: Cell::new(0),
        }
    }

    /// Charges `bytes`, or fails once the total passes the limit.
    pub fn charge<E: de::Error>(&self, bytes: usize) -> Result<(), E> {
        let used = self.used.get().saturating_add(bytes);
        if used > self.limit {
            return Err(E::custom(LIMITS));
        }
        self.used.set(used);
        Ok(())
    }

    /// Gives back `bytes` charged earlier (spare capacity freed).
    pub fn refund(&self, bytes: usize) {
        self.used.set(self.used.get().saturating_sub(bytes));
    }

    /// Bytes charged so far.
    pub fn used(&self) -> usize {
        self.used.get()
    }
}

/// The capacity std's `Vec` ends with after `n` pushes from empty with no size hint (doubling from
/// its minimum non-zero capacity: 8 for 1-byte elements, 4 up to 1 KiB, 1 beyond).
fn grown_capacity(n: usize, size: usize) -> usize {
    if n == 0 || size == 0 {
        return 0;
    }
    let min = if size == 1 {
        8
    } else if size <= 1024 {
        4
    } else {
        1
    };
    n.checked_next_power_of_two().unwrap_or(usize::MAX).max(min)
}

/// A seed that deserialises a `T` with every allocation charged to `budget`.
pub(crate) struct Charge<'b, T> {
    pub budget: &'b Budget,
    pub kind: PhantomData<T>,
}

impl<'b, T> Charge<'b, T> {
    pub fn new(budget: &'b Budget) -> Self {
        Charge {
            budget,
            kind: PhantomData,
        }
    }
}

impl<'de, T: de::Deserialize<'de>> DeserializeSeed<'de> for Charge<'_, T> {
    type Value = T;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<T, D::Error> {
        T::deserialize(Charged {
            inner: d,
            budget: self.budget,
        })
    }
}

/// A deserializer whose values charge `budget` (see the module docs).
pub(crate) struct Charged<'b, D> {
    inner: D,
    budget: &'b Budget,
}

/// What a wrapped visitor charges.
#[derive(Clone, Copy)]
struct Mode {
    /// Owned strings (not identifiers or skipped values).
    strings: bool,
    /// Sequence elements and map entries (not struct fields, tuples or arrays).
    elements: bool,
}

const VALUE: Mode = Mode {
    strings: true,
    elements: true,
};
const INLINE: Mode = Mode {
    strings: true,
    elements: false,
};
const IDENT: Mode = Mode {
    strings: false,
    elements: false,
};

struct Wrap<'b, V> {
    inner: V,
    budget: &'b Budget,
    mode: Mode,
}

impl<'b, D> Charged<'b, D> {
    fn wrap<V>(&self, inner: V, mode: Mode) -> Wrap<'b, V> {
        Wrap {
            inner,
            budget: self.budget,
            mode,
        }
    }
}

macro_rules! forward {
    ($($method:ident),* $(,)?) => {
        $(
            fn $method<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
                let w = self.wrap(v, VALUE);
                self.inner.$method(w)
            }
        )*
    };
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Charged<'_, D> {
    type Error = D::Error;

    forward!(
        deserialize_any,
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_option,
        deserialize_unit,
        deserialize_seq,
        deserialize_map,
    );

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value, D::Error> {
        let w = self.wrap(v, VALUE);
        self.inner.deserialize_unit_struct(name, w)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value, D::Error> {
        let w = self.wrap(v, VALUE);
        self.inner.deserialize_newtype_struct(name, w)
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, D::Error> {
        let w = self.wrap(v, INLINE);
        self.inner.deserialize_tuple(len, w)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        v: V,
    ) -> Result<V::Value, D::Error> {
        let w = self.wrap(v, INLINE);
        self.inner.deserialize_tuple_struct(name, len, w)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, D::Error> {
        let w = self.wrap(v, INLINE);
        self.inner.deserialize_struct(name, fields, w)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, D::Error> {
        let w = self.wrap(v, VALUE);
        self.inner.deserialize_enum(name, variants, w)
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let w = self.wrap(v, IDENT);
        self.inner.deserialize_identifier(w)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, D::Error> {
        let w = self.wrap(v, IDENT);
        self.inner.deserialize_ignored_any(w)
    }

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

macro_rules! pass {
    ($($method:ident: $ty:ty),* $(,)?) => {
        $(
            fn $method<E: de::Error>(self, x: $ty) -> Result<V::Value, E> {
                self.inner.$method(x)
            }
        )*
    };
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Wrap<'_, V> {
    type Value = V::Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(f)
    }

    pass!(
        visit_bool: bool,
        visit_i8: i8,
        visit_i16: i16,
        visit_i32: i32,
        visit_i64: i64,
        visit_i128: i128,
        visit_u8: u8,
        visit_u16: u16,
        visit_u32: u32,
        visit_u64: u64,
        visit_u128: u128,
        visit_f32: f32,
        visit_f64: f64,
        visit_char: char,
    );

    fn visit_str<E: de::Error>(self, x: &str) -> Result<V::Value, E> {
        if self.mode.strings {
            self.budget.charge::<E>(alloc_bytes(x.len()))?;
        }
        self.inner.visit_str(x)
    }

    fn visit_borrowed_str<E: de::Error>(self, x: &'de str) -> Result<V::Value, E> {
        if self.mode.strings {
            self.budget.charge::<E>(alloc_bytes(x.len()))?;
        }
        self.inner.visit_borrowed_str(x)
    }

    fn visit_string<E: de::Error>(self, x: String) -> Result<V::Value, E> {
        if self.mode.strings {
            self.budget.charge::<E>(alloc_bytes(x.len()))?;
        }
        self.inner.visit_string(x)
    }

    fn visit_bytes<E: de::Error>(self, x: &[u8]) -> Result<V::Value, E> {
        if self.mode.strings {
            self.budget.charge::<E>(alloc_bytes(x.len()))?;
        }
        self.inner.visit_bytes(x)
    }

    fn visit_borrowed_bytes<E: de::Error>(self, x: &'de [u8]) -> Result<V::Value, E> {
        if self.mode.strings {
            self.budget.charge::<E>(alloc_bytes(x.len()))?;
        }
        self.inner.visit_borrowed_bytes(x)
    }

    fn visit_byte_buf<E: de::Error>(self, x: Vec<u8>) -> Result<V::Value, E> {
        if self.mode.strings {
            self.budget.charge::<E>(alloc_bytes(x.len()))?;
        }
        self.inner.visit_byte_buf(x)
    }

    fn visit_none<E: de::Error>(self) -> Result<V::Value, E> {
        self.inner.visit_none()
    }

    fn visit_unit<E: de::Error>(self) -> Result<V::Value, E> {
        self.inner.visit_unit()
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<V::Value, D::Error> {
        self.inner.visit_some(Charged {
            inner: d,
            budget: self.budget,
        })
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<V::Value, D::Error> {
        self.inner.visit_newtype_struct(Charged {
            inner: d,
            budget: self.budget,
        })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<V::Value, A::Error> {
        self.inner.visit_seq(Seq {
            inner: seq,
            budget: self.budget,
            charge: self.mode.elements,
            n: 0,
            size: 0,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<V::Value, A::Error> {
        self.inner.visit_map(Map {
            inner: map,
            budget: self.budget,
            charge: self.mode.elements,
        })
    }

    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<V::Value, A::Error> {
        self.inner.visit_enum(Enum {
            inner: data,
            budget: self.budget,
        })
    }
}

/// A sequence whose elements (and the `Vec` capacity they grow) are charged.
struct Seq<'b, A> {
    inner: A,
    budget: &'b Budget,
    charge: bool,
    n: usize,
    size: usize,
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Seq<'_, A> {
    type Error = A::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, A::Error> {
        let got = self.inner.next_element_seed(ChargedSeed {
            inner: seed,
            budget: self.budget,
        })?;
        if self.charge {
            match &got {
                Some(_) => {
                    self.size = std::mem::size_of::<T::Value>();
                    self.n = self.n.saturating_add(1);
                    self.budget.charge::<A::Error>(self.size)?;
                }
                None => {
                    // The buffer as the allocator takes it, past the elements charged one by one.
                    let cap = grown_capacity(self.n, self.size);
                    let buffer = alloc_bytes(cap.saturating_mul(self.size));
                    self.budget
                        .charge::<A::Error>(buffer.saturating_sub(self.n.saturating_mul(self.size)))?;
                }
            }
        }
        Ok(got)
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

/// A map whose entries are charged (a map, not a struct's fields).
struct Map<'b, A> {
    inner: A,
    budget: &'b Budget,
    charge: bool,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Map<'_, A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, A::Error> {
        let got = self.inner.next_key_seed(ChargedSeed {
            inner: seed,
            budget: self.budget,
        })?;
        if self.charge && got.is_some() {
            // The key, and a share of the table or tree node holding the entry.
            self.budget
                .charge::<A::Error>(std::mem::size_of::<K::Value>().saturating_add(16))?;
        }
        Ok(got)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, A::Error> {
        let v = self.inner.next_value_seed(ChargedSeed {
            inner: seed,
            budget: self.budget,
        })?;
        if self.charge {
            self.budget.charge::<A::Error>(std::mem::size_of::<V::Value>())?;
        }
        Ok(v)
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct Enum<'b, A> {
    inner: A,
    budget: &'b Budget,
}

impl<'de, 'b, A: EnumAccess<'de>> EnumAccess<'de> for Enum<'b, A> {
    type Error = A::Error;
    type Variant = Variant<'b, A::Variant>;

    fn variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<(T::Value, Self::Variant), A::Error> {
        let (v, rest) = self.inner.variant_seed(ChargedSeed {
            inner: seed,
            budget: self.budget,
        })?;
        Ok((
            v,
            Variant {
                inner: rest,
                budget: self.budget,
            },
        ))
    }
}

struct Variant<'b, A> {
    inner: A,
    budget: &'b Budget,
}

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Variant<'_, A> {
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), A::Error> {
        self.inner.unit_variant()
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, A::Error> {
        self.inner.newtype_variant_seed(ChargedSeed {
            inner: seed,
            budget: self.budget,
        })
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, A::Error> {
        self.inner.tuple_variant(
            len,
            Wrap {
                inner: v,
                budget: self.budget,
                mode: INLINE,
            },
        )
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, A::Error> {
        self.inner.struct_variant(
            fields,
            Wrap {
                inner: v,
                budget: self.budget,
                mode: INLINE,
            },
        )
    }
}

/// Any seed, its deserializer wrapped so the value it builds is charged.
struct ChargedSeed<'b, T> {
    inner: T,
    budget: &'b Budget,
}

impl<'de, T: DeserializeSeed<'de>> DeserializeSeed<'de> for ChargedSeed<'_, T> {
    type Value = T::Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<T::Value, D::Error> {
        self.inner.deserialize(Charged {
            inner: d,
            budget: self.budget,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn charged<T: for<'de> de::Deserialize<'de>>(json: &str, limit: usize) -> (Result<T, String>, usize) {
        let b = Budget::new(limit);
        let mut d = serde_json::Deserializer::from_str(json);
        let r = Charge::<T>::new(&b)
            .deserialize(&mut d)
            .map_err(|e| e.to_string());
        (r, b.used())
    }

    #[test]
    fn charges_elements_strings_and_capacity() {
        // Three u32s: a 4-element buffer (std's minimum), 16 bytes → one 32-byte allocation.
        let (r, used) = charged::<Vec<u32>>("[1,2,3]", 1 << 20);
        assert_eq!(r.unwrap(), vec![1, 2, 3]);
        assert_eq!(used, 32);
        // Two strings: two 24-byte slots in a 4-slot buffer (112 bytes) plus each buffer.
        let (r, used) = charged::<Vec<String>>(r#"["a","bcd"]"#, 1 << 20);
        assert_eq!(r.unwrap().len(), 2);
        assert_eq!(used, alloc_bytes(96) + 32 + 32);
        // Struct fields and tuples sit in their parent; identifiers aren't kept.
        #[derive(serde::Deserialize)]
        #[expect(dead_code, reason = "only deserialized, to measure its charge")]
        struct S {
            a: u64,
            b: (u8, u8),
        }
        let (r, used) = charged::<S>(r#"{"a":1,"b":[1,2],"ignored":"long text here"}"#, 1 << 20);
        assert!(r.is_ok());
        assert_eq!(used, 0);
        // Past the limit: stops while parsing.
        let (r, used) = charged::<Vec<String>>(r#"["a","b","c","d","e"]"#, 100);
        assert!(r.unwrap_err().starts_with(LIMITS));
        assert!(used <= 100);
    }

    #[test]
    fn std_vec_growth_matches() {
        for n in [0usize, 1, 3, 4, 5, 8, 9, 100, 1000] {
            let mut v: Vec<u32> = Vec::new();
            for i in 0..n {
                v.push(i as u32);
            }
            assert_eq!(v.capacity(), grown_capacity(n, 4), "{n}");
            let mut v: Vec<u8> = Vec::new();
            for i in 0..n {
                v.push(i as u8);
            }
            assert_eq!(v.capacity(), grown_capacity(n, 1), "{n}");
        }
    }
}

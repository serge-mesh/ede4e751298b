//! Allocation-bounded socket decoding for `apply`. Validate strings while borrowed from the
//! JSON decoder, count input entries while streaming, and retain only normalised networks.
//! In particular, duplicate CIDRs and invalid empty strings never build a `Vec<String>`.

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;

use ipnet::IpNet;
use picket_api::edge_config::FwMode;
use picket_api::helper::{ApplyRequest, InterfaceMode, RedirectCheck};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::rules::{Desired, MAX_INPUT_NETS, MAX_INTERFACES, STATIC_MAX, expand, parse_cidr, valid_ifname};

/// Each string is checked before making an owned copy. serde_json may use a scratch buffer
/// for escaped strings; that buffer is bounded by the 1 MiB wire limit, independently of count.
struct Text<T>(T);

impl<'de> Deserialize<'de> for Text<IpNet> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Cidr;
        impl Visitor<'_> for Cidr {
            type Value = Text<IpNet>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a CIDR or IP address")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                parse_cidr(s).map(Text).ok_or_else(|| E::custom("invalid CIDR"))
            }
        }
        d.deserialize_str(Cidr)
    }
}

impl<'de> Deserialize<'de> for Text<String> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Ifname;
        impl Visitor<'_> for Ifname {
            type Value = Text<String>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an interface name")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                if !valid_ifname(s) {
                    return Err(E::custom("invalid interface name"));
                }
                Ok(Text(s.to_owned()))
            }
        }
        d.deserialize_str(Ifname)
    }
}

#[derive(Default)]
struct Nets {
    v4: Vec<IpNet>,
    v6: Vec<IpNet>,
}

impl<'de> Deserialize<'de> for Nets {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Networks;
        impl<'de> Visitor<'de> for Networks {
            type Value = Nets;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded CIDR list")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Nets, A::Error> {
                let (mut v4, mut v6) = (BTreeSet::new(), BTreeSet::new());
                let mut count = 0;
                while let Some(Text(net)) = seq.next_element::<Text<IpNet>>()? {
                    count += 1;
                    if count > MAX_INPUT_NETS {
                        return Err(de::Error::custom("too many CIDRs"));
                    }
                    for n in expand(net) {
                        let set = if n.addr().is_ipv4() { &mut v4 } else { &mut v6 };
                        set.insert(n);
                        if set.len() > STATIC_MAX as usize {
                            return Err(de::Error::custom("too many CIDRs per family"));
                        }
                    }
                }
                Ok(Nets {
                    v4: v4.into_iter().collect(),
                    v6: v6.into_iter().collect(),
                })
            }
        }
        d.deserialize_seq(Networks)
    }
}

/// Unlike Vec's deserializer, do not trust size_hint or grow past the supported count.
fn interfaces<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct List<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for List<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded interface list")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut out = Vec::new();
            while let Some(item) = seq.next_element()? {
                if out.len() == MAX_INTERFACES {
                    return Err(de::Error::custom("too many interfaces"));
                }
                out.push(item);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(List(PhantomData))
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Interface {
    name: Option<Text<String>>,
    mode: FwMode,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Redirect {
    #[serde(deserialize_with = "interfaces")]
    interfaces: Vec<Text<String>>,
    port: u16,
    ipv6: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct Apply {
    #[serde(deserialize_with = "interfaces")]
    interfaces: Vec<Interface>,
    #[serde(rename = "static")]
    static_allow: Nets,
    exempt: Nets,
    redirect: Option<Redirect>,
}

impl Apply {
    pub(crate) fn desired(self) -> Result<Desired, String> {
        // Reuse the interface conflict and redirect-port checks used by persisted rules and
        // in-process callers. CIDR lists have already passed exactly the same normalisation.
        let r = ApplyRequest {
            interfaces: self
                .interfaces
                .into_iter()
                .map(|i| InterfaceMode {
                    name: i.name.map(|Text(s)| s).unwrap_or_default(),
                    mode: i.mode,
                })
                .collect(),
            redirect: self.redirect.map(|r| RedirectCheck {
                interfaces: r.interfaces.into_iter().map(|Text(s)| s).collect(),
                port: r.port,
                ipv6: r.ipv6,
            }),
            ..ApplyRequest::default()
        };
        let mut d = Desired::from_request(&r)?;
        d.static4 = self.static_allow.v4;
        d.static6 = self.static_allow.v6;
        d.exempt4 = self.exempt.v4;
        d.exempt6 = self.exempt.v6;
        Ok(d)
    }
}

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

use crate::rules::{
    Desired, MAX_INPUT_NETS, MAX_INTERFACES, STATIC_MAX, expand, parse_cidr, truncate, valid_ifname,
};

/// One CIDR list entry: the network, or the (truncated) text that isn't one. The list reports
/// the first bad entry with its field name, as the engine-side validation did.
struct Entry(Result<IpNet, String>);

impl<'de> Deserialize<'de> for Entry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Cidr;
        impl Visitor<'_> for Cidr {
            type Value = Entry;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a CIDR or IP address")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(Entry(parse_cidr(s).ok_or_else(|| truncate(s))))
            }
        }
        d.deserialize_str(Cidr)
    }
}

/// An interface name, checked before making an owned copy. serde_json may use a scratch buffer
/// for escaped strings; that buffer is bounded by the 1 MiB wire limit, independently of count.
struct Ifname(String);

impl<'de> Deserialize<'de> for Ifname {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Name;
        impl Visitor<'_> for Name {
            type Value = Ifname;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an interface name")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                if !valid_ifname(s) {
                    return Err(E::custom(format!("invalid interface name {:?}", truncate(s))));
                }
                Ok(Ifname(s.to_owned()))
            }
        }
        d.deserialize_str(Name)
    }
}

#[derive(Default)]
struct Nets {
    v4: Vec<IpNet>,
    v6: Vec<IpNet>,
}

fn nets<'de, D: Deserializer<'de>>(d: D, what: &'static str) -> Result<Nets, D::Error> {
    struct Networks(&'static str);
    impl<'de> Visitor<'de> for Networks {
        type Value = Nets;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded CIDR list")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Nets, A::Error> {
            let what = self.0;
            let (mut v4, mut v6) = (BTreeSet::new(), BTreeSet::new());
            let mut count = 0;
            while let Some(Entry(net)) = seq.next_element::<Entry>()? {
                count += 1;
                if count > MAX_INPUT_NETS {
                    return Err(de::Error::custom(format!("{what}: too many entries")));
                }
                let net = net.map_err(|s| de::Error::custom(format!("{what}: invalid CIDR {s:?}")))?;
                for n in expand(net) {
                    let set = if n.addr().is_ipv4() { &mut v4 } else { &mut v6 };
                    set.insert(n);
                    if set.len() > STATIC_MAX as usize {
                        return Err(de::Error::custom(format!(
                            "{what}: more than {STATIC_MAX} entries per family"
                        )));
                    }
                }
            }
            Ok(Nets {
                v4: v4.into_iter().collect(),
                v6: v6.into_iter().collect(),
            })
        }
    }
    d.deserialize_seq(Networks(what))
}

fn static_nets<'de, D: Deserializer<'de>>(d: D) -> Result<Nets, D::Error> {
    nets(d, "static")
}

fn exempt_nets<'de, D: Deserializer<'de>>(d: D) -> Result<Nets, D::Error> {
    nets(d, "exempt")
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
    name: Option<Ifname>,
    mode: FwMode,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Redirect {
    #[serde(deserialize_with = "interfaces")]
    interfaces: Vec<Ifname>,
    port: u16,
    ipv6: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct Apply {
    #[serde(deserialize_with = "interfaces")]
    interfaces: Vec<Interface>,
    #[serde(rename = "static", deserialize_with = "static_nets")]
    static_allow: Nets,
    #[serde(deserialize_with = "exempt_nets")]
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
                    name: i.name.map(|Ifname(s)| s).unwrap_or_default(),
                    mode: i.mode,
                })
                .collect(),
            redirect: self.redirect.map(|r| RedirectCheck {
                interfaces: r.interfaces.into_iter().map(|Ifname(s)| s).collect(),
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

#[cfg(test)]
mod tests {
    use crate::server::parse_request;

    fn error(data: &str) -> String {
        let f = format!(r#"{{"type":"apply","id":1,"data":{data}}}"#);
        match parse_request(f.as_bytes()) {
            Err((Some(1), e)) => e.message,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn errors_name_the_field_and_the_entry() {
        assert!(error(r#"{"static":["10.0.0.0/8","nope"]}"#).contains(r#"static: invalid CIDR "nope""#));
        assert!(error(r#"{"exempt":[""]}"#).contains(r#"exempt: invalid CIDR """#));
        let many = format!(
            r#"{{"exempt":[{}]}}"#,
            vec![r#""::""#; super::MAX_INPUT_NETS + 1].join(",")
        );
        assert!(error(&many).contains("exempt: too many entries"));
        assert!(error(r#"{"interfaces":[{"name":"-x"}]}"#).contains(r#"invalid interface name "-x""#));
    }
}

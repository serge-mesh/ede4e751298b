//! Signed test zones for the DNSSEC tests (build-and-test.md §5 "DNSSEC": known-bad test zones,
//! denial proofs, unsigned zones), generated in the test: no network.
//!
//! A [`World`] holds zones under a test root, each signed with its own Ed25519 key (or unsigned),
//! delegated by DS records in the parent. [`World::answer`] answers a query as a validating
//! resolver asked with DO=1 and CD=1 would: the RRset with its RRSIGs, or a negative answer with
//! the SOA and the NSEC records that prove it. [`ZoneResolver`] serves the world to core's
//! validator; [`doh_server`] serves it over DoH (TLS) for the end-to-end path.

#![allow(
    dead_code,
    reason = "shared test helpers: each test binary that includes them uses only part"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use hickory_proto::dnssec::crypto::Ed25519SigningKey;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC, RRSIG, SigInput};
use hickory_proto::dnssec::{Algorithm, DigestType, PublicKey, PublicKeyBuf, SigningKey, TBS, TrustAnchors};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, NS, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};
use jiff::Timestamp;
use picket_core::dnssec::validator::{ChainResolver, ResolveError};

pub fn name(s: &str) -> Name {
    let mut n = Name::from_ascii(s).unwrap();
    n.set_fqdn(true);
    n
}

pub fn now() -> u32 {
    u32::try_from(Timestamp::now().as_second()).unwrap()
}

/// A zone key.
pub struct Key {
    pub signing: Box<dyn SigningKey>,
    pub public: PublicKeyBuf,
    pub dnskey: DNSKEY,
    pub tag: u16,
}

impl Key {
    pub fn generate() -> Arc<Key> {
        Self::generate_with(true)
    }

    /// A key whose DNSKEY has the Zone Key bit set or not (RFC 4034 §2.1.1).
    pub fn generate_with(zone_key: bool) -> Arc<Key> {
        let der = Ed25519SigningKey::generate_pkcs8().unwrap();
        let signing = Ed25519SigningKey::from_pkcs8(&der).unwrap();
        let public = signing.to_public_key().unwrap();
        let dnskey = DNSKEY::new(zone_key, true, false, public.clone());
        let tag = dnskey.calculate_key_tag().unwrap();
        Arc::new(Key {
            signing: Box::new(signing),
            public,
            dnskey,
            tag,
        })
    }
}

/// One zone.
pub struct Zone {
    pub apex: Name,
    /// The key that signs its records (None: an unsigned zone).
    pub key: Option<Arc<Key>>,
    /// The keys its DNSKEY RRset publishes (default: its signing key).
    pub published: Option<Vec<Arc<Key>>>,
    /// The key the parent's DS names (default: its signing key; none for an unsigned zone).
    pub ds_key: Option<Arc<Key>>,
    /// (inception, expiration) of its signatures.
    pub window: (u32, u32),
    /// (inception, expiration) of the signatures over its data (every RRset but its DNSKEY,
    /// SOA, NS and its delegations' DS), when they differ from `window`.
    pub data_window: Option<(u32, u32)>,
    pub records: Vec<Record>,
}

/// The zones under a test root.
pub struct World {
    pub zones: Vec<Zone>,
    pub root_key: Arc<Key>,
    /// Queries answered: (qname, qtype).
    pub asked: Mutex<Vec<(String, String)>>,
    /// Names answered SERVFAIL.
    pub servfail: Mutex<BTreeSet<String>>,
    /// Answer every query as unreachable.
    pub unreachable: std::sync::atomic::AtomicBool,
}

pub const TTL: u32 = 300;

fn rec(n: &Name, data: RData) -> Record {
    Record::from_rdata(n.clone(), TTL, data)
}

impl World {
    /// The standard world:
    /// - `test.` signed (DS in the root): `www.test.` A 192.0.2.1, `mail.test.` A 192.0.2.3;
    /// - `unsigned.test.` unsigned (no DS): `www.unsigned.test.` A 192.0.2.2;
    /// - `expired.test.` signed with signatures that expired 10 days ago;
    /// - `nokey.test.` whose DS names a key its DNSKEY RRset doesn't hold;
    /// - `past.test.` whose data signatures expired an hour ago (its keys are signed now);
    /// - `nozone.test.` signed by a key without the Zone Key bit.
    pub fn standard() -> Arc<World> {
        let t = now();
        let good = (t - 86_400, t + 30 * 86_400);
        let root_key = Key::generate();
        let test_key = Key::generate();
        let mut zones = vec![Zone {
            apex: Name::root(),
            key: Some(root_key.clone()),
            published: None,
            ds_key: None,
            window: good,
            data_window: None,
            records: vec![],
        }];
        let test = Zone {
            apex: name("test."),
            key: Some(test_key),
            published: None,
            ds_key: None,
            window: good,
            data_window: None,
            records: vec![
                rec(&name("www.test."), RData::A(A(Ipv4Addr::new(192, 0, 2, 1)))),
                rec(&name("mail.test."), RData::A(A(Ipv4Addr::new(192, 0, 2, 3)))),
            ],
        };
        zones.push(test);
        zones.push(Zone {
            apex: name("unsigned.test."),
            key: None,
            published: None,
            ds_key: None,
            window: good,
            data_window: None,
            records: vec![rec(
                &name("www.unsigned.test."),
                RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
            )],
        });
        zones.push(Zone {
            apex: name("expired.test."),
            key: Some(Key::generate()),
            published: None,
            ds_key: None,
            window: (t - 30 * 86_400, t - 10 * 86_400),
            data_window: None,
            records: vec![rec(
                &name("www.expired.test."),
                RData::A(A(Ipv4Addr::new(192, 0, 2, 4))),
            )],
        });
        let nokey_signer = Key::generate();
        zones.push(Zone {
            apex: name("nokey.test."),
            key: Some(nokey_signer.clone()),
            published: Some(vec![nokey_signer]),
            ds_key: Some(Key::generate()),
            window: good,
            data_window: None,
            records: vec![rec(
                &name("www.nokey.test."),
                RData::A(A(Ipv4Addr::new(192, 0, 2, 5))),
            )],
        });
        // The zone re-signs its keys; www's signature (as an answer logged earlier carries it)
        // expired an hour ago.
        zones.push(Zone {
            apex: name("past.test."),
            key: Some(Key::generate()),
            published: None,
            ds_key: None,
            window: good,
            data_window: Some((t - 10 * 86_400, t - 3600)),
            records: vec![rec(
                &name("www.past.test."),
                RData::A(A(Ipv4Addr::new(192, 0, 2, 6))),
            )],
        });
        zones.push(Zone {
            apex: name("nozone.test."),
            key: Some(Key::generate_with(false)),
            published: None,
            ds_key: None,
            window: good,
            data_window: None,
            records: vec![rec(
                &name("www.nozone.test."),
                RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
            )],
        });
        Arc::new(World {
            zones,
            root_key,
            asked: Mutex::new(vec![]),
            servfail: Mutex::new(BTreeSet::new()),
            unreachable: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn anchors(&self) -> TrustAnchors {
        let mut a = TrustAnchors::empty();
        a.insert(&self.root_key.public);
        a
    }

    fn zone_for(&self, qname: &Name, qtype: RecordType) -> &Zone {
        let mut best: Option<&Zone> = None;
        for z in &self.zones {
            let under = z.apex.zone_of(qname);
            let ds_at_apex = qtype == RecordType::DS && z.apex == *qname && !z.apex.is_root();
            if under && !ds_at_apex && best.is_none_or(|b| z.apex.num_labels() > b.apex.num_labels()) {
                best = Some(z);
            }
        }
        best.unwrap_or(&self.zones[0])
    }

    fn children(&self, z: &Zone) -> Vec<&Zone> {
        self.zones
            .iter()
            .filter(|c| {
                c.apex != z.apex && z.apex.zone_of(&c.apex) && c.apex.num_labels() == z.apex.num_labels() + 1
            })
            .collect()
    }

    /// Every authoritative record of `z`, unsigned: apex SOA, NS and DNSKEY, its data, and the
    /// NS and DS records of its delegations.
    fn rrs(&self, z: &Zone) -> Vec<Record> {
        let ns_name = if z.apex.is_root() {
            name("ns.root.")
        } else {
            name(&format!("ns.{}", z.apex))
        };
        let mut out = vec![
            rec(
                &z.apex,
                RData::SOA(SOA::new(
                    ns_name.clone(),
                    name("hostmaster.test."),
                    1,
                    3600,
                    600,
                    86_400,
                    60,
                )),
            ),
            rec(&z.apex, RData::NS(NS(ns_name.clone()))),
        ];
        if z.key.is_some() {
            let keys = z
                .published
                .clone()
                .unwrap_or_else(|| z.key.clone().into_iter().collect());
            for k in keys {
                out.push(rec(&z.apex, RData::DNSSEC(DNSSECRData::DNSKEY(k.dnskey.clone()))));
            }
        }
        out.extend(z.records.iter().cloned());
        for c in self.children(z) {
            out.push(rec(&c.apex, RData::NS(NS(name(&format!("ns.{}", c.apex))))));
            if let Some(k) = c.ds_key.clone().or_else(|| c.key.clone()) {
                // The digest of the DNSKEY as published (its flags included).
                let ds = DS::new(
                    k.tag,
                    k.public.algorithm(),
                    DigestType::SHA256,
                    k.dnskey
                        .to_digest(&c.apex, DigestType::SHA256)
                        .unwrap()
                        .as_ref()
                        .to_owned(),
                );
                out.push(rec(&c.apex, RData::DNSSEC(DNSSECRData::DS(ds))));
            }
        }
        out
    }

    fn sign(z: &Zone, owner: &Name, records: &[Record]) -> Option<Record> {
        let key = z.key.as_ref()?;
        let first = records.first()?;
        let chain = matches!(
            first.record_type(),
            RecordType::DNSKEY | RecordType::SOA | RecordType::NS | RecordType::DS
        );
        let window = if chain {
            z.window
        } else {
            z.data_window.unwrap_or(z.window)
        };
        let input = SigInput {
            type_covered: first.record_type(),
            algorithm: Algorithm::ED25519,
            num_labels: owner.num_labels(),
            original_ttl: first.ttl,
            sig_expiration: SerialNumber::new(window.1),
            sig_inception: SerialNumber::new(window.0),
            key_tag: key.tag,
            signer_name: z.apex.clone(),
        };
        let tbs = TBS::from_input(owner, DNSClass::IN, &input, records.iter()).unwrap();
        let sig = key.signing.sign(&tbs).unwrap();
        Some(rec(
            owner,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))),
        ))
    }

    /// The RRset of (owner, type) in `z` with its RRSIG.
    fn rrset(z: &Zone, all: &[Record], owner: &Name, t: RecordType) -> Vec<Record> {
        let set: Vec<Record> = all
            .iter()
            .filter(|r| r.name == *owner && r.record_type() == t)
            .cloned()
            .collect();
        let mut out = set.clone();
        if !set.is_empty()
            && let Some(sig) = Self::sign(z, owner, &set)
        {
            out.push(sig);
        }
        out
    }

    /// The zone's NSEC chain: owner → (next, types).
    fn nsec_chain(z: &Zone, all: &[Record]) -> BTreeMap<Name, (Name, Vec<RecordType>)> {
        let mut owners: BTreeMap<Name, BTreeSet<RecordType>> = BTreeMap::new();
        for r in all {
            owners.entry(r.name.clone()).or_default().insert(r.record_type());
        }
        let names: Vec<Name> = owners.keys().cloned().collect();
        let mut chain = BTreeMap::new();
        for (i, n) in names.iter().enumerate() {
            let next = names.get(i + 1).cloned().unwrap_or_else(|| z.apex.clone());
            let mut types: Vec<RecordType> = owners[n].iter().copied().collect();
            types.push(RecordType::NSEC);
            types.push(RecordType::RRSIG);
            chain.insert(n.clone(), (next, types));
        }
        chain
    }

    fn nsec_rrset(z: &Zone, owner: &Name, next: &Name, types: &[RecordType]) -> Vec<Record> {
        let r = Record::from_rdata(
            owner.clone(),
            TTL,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(next.clone(), types.iter().copied()))),
        );
        let mut out = vec![r.clone()];
        if let Some(sig) = Self::sign(z, owner, &[r]) {
            out.push(sig);
        }
        out
    }

    /// The NSEC covering `n` (the greatest owner before it).
    fn covering(
        chain: &BTreeMap<Name, (Name, Vec<RecordType>)>,
        n: &Name,
    ) -> Option<(Name, Name, Vec<RecordType>)> {
        chain
            .range(..n.clone())
            .next_back()
            .or_else(|| chain.iter().next_back())
            .map(|(o, (next, t))| (o.clone(), next.clone(), t.clone()))
    }

    /// The answer a validating resolver asked with DO=1, CD=1 gives (module docs).
    pub fn answer_message(&self, qname: &Name, qtype: RecordType) -> Message {
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.metadata.recursion_available = true;
        m.metadata.checking_disabled = true;
        m.add_query(Query::query(qname.clone(), qtype));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(4096);
        m.edns = Some(edns);
        let z = self.zone_for(qname, qtype);
        let all = self.rrs(z);
        let ans = Self::rrset(z, &all, qname, qtype);
        if !ans.is_empty() {
            m.answers = ans;
            return m;
        }
        // Negative: the SOA, and for a signed zone the NSEC proof.
        m.authorities = Self::rrset(z, &all, &z.apex, RecordType::SOA);
        let exists = all.iter().any(|r| r.name == *qname);
        if z.key.is_some() {
            let chain = Self::nsec_chain(z, &all);
            if exists {
                if let Some((next, types)) = chain.get(qname) {
                    m.authorities.extend(Self::nsec_rrset(z, qname, next, types));
                }
            } else {
                let mut proofs: Vec<(Name, Name, Vec<RecordType>)> = Vec::new();
                if let Some(c) = Self::covering(&chain, qname) {
                    proofs.push(c);
                }
                let wild = z.apex.prepend_label("*").unwrap();
                if let Some(c) = Self::covering(&chain, &wild)
                    && !proofs.iter().any(|p| p.0 == c.0)
                {
                    proofs.push(c);
                }
                for (o, next, types) in proofs {
                    m.authorities.extend(Self::nsec_rrset(z, &o, &next, &types));
                }
            }
        }
        if !exists {
            m.metadata.response_code = ResponseCode::NXDomain;
        }
        m
    }

    pub fn answer(&self, qname: &Name, qtype: RecordType) -> Vec<u8> {
        self.answer_message(qname, qtype).to_vec().unwrap()
    }

    /// An answer with its RRSIG records taken out (a signed zone's answer stripped).
    pub fn stripped(&self, qname: &Name, qtype: RecordType) -> Vec<u8> {
        let mut m = self.answer_message(qname, qtype);
        m.answers.retain(|r| r.record_type() != RecordType::RRSIG);
        m.authorities.retain(|r| r.record_type() != RecordType::RRSIG);
        m.to_vec().unwrap()
    }

    /// A NODATA answer whose NSEC claims the type exists at the name (a bogus denial).
    pub fn bogus_nodata(&self, qname: &Name, qtype: RecordType) -> Vec<u8> {
        let mut m = self.answer_message(qname, qtype);
        for r in m.authorities.iter_mut() {
            if let RData::DNSSEC(DNSSECRData::NSEC(n)) = &r.data {
                let mut types: Vec<RecordType> = n.type_bit_maps().collect();
                types.push(qtype);
                r.data = RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(n.next_domain_name().clone(), types)));
            }
        }
        m.to_vec().unwrap()
    }

    pub fn asked(&self, qname: &str, qtype: &str) -> usize {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, t)| n.trim_end_matches('.') == qname.trim_end_matches('.') && t == qtype)
            .count()
    }

    pub fn total_asked(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

/// The world as core's chain resolver (DO=1, CD=1 answers, no network).
pub struct ZoneResolver(pub Arc<World>);

#[async_trait::async_trait]
impl ChainResolver for ZoneResolver {
    async fn query(&self, qname: &Name, qtype: RecordType) -> Result<Vec<u8>, ResolveError> {
        if self.0.unreachable.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ResolveError::Unreachable("connection refused".into()));
        }
        self.0
            .asked
            .lock()
            .unwrap()
            .push((qname.to_string(), qtype.to_string()));
        if self.0.servfail.lock().unwrap().contains(&qname.to_string()) {
            let mut m = Message::new(0, MessageType::Response, OpCode::Query);
            m.add_query(Query::query(qname.clone(), qtype));
            m.metadata.response_code = ResponseCode::ServFail;
            return Ok(m.to_vec().unwrap());
        }
        Ok(self.0.answer(qname, qtype))
    }
}

/// Serves the world over DoH (POST `application/dns-message`) with a certificate for `tls_name`
/// from `ca`'s LAN CA, on 127.0.0.1; returns the address and the paths requested.
pub async fn doh_server(
    world: Arc<World>,
    lanca: &picket_core::lanca::LanCa,
    tls_name: &str,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    use rustls_pki_types::pem::PemObject;
    let (issued, key_pem) = lanca
        .issue_with_new_key(
            &[tls_name.to_string()],
            &[],
            std::time::Duration::from_secs(86_400),
        )
        .unwrap();
    let chain: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_slice_iter(
            format!("{}{}", issued.cert_pem, issued.chain_pem).as_bytes(),
        )
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let mut cfg =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let p2 = paths.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let world = world.clone();
            let paths = p2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let world = world.clone();
                    let paths = paths.clone();
                    async move {
                        use http_body_util::BodyExt;
                        let path = req.uri().path().to_string();
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        let q = Message::from_vec(&body).unwrap();
                        paths.lock().unwrap().push(format!(
                            "{path} cd={} do={}",
                            q.metadata.checking_disabled,
                            q.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
                        ));
                        let query = q.queries.first().unwrap().clone();
                        world
                            .asked
                            .lock()
                            .unwrap()
                            .push((query.name().to_string(), query.query_type().to_string()));
                        let mut a = world.answer_message(query.name(), query.query_type());
                        a.metadata.id = q.metadata.id;
                        let out = a.to_vec().unwrap();
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .header("content-type", "application/dns-message")
                                .body(http_body_util::Full::new(bytes::Bytes::from(out)))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (addr, paths)
}

/// Unused-key helper so the test can also check a public key's algorithm.
pub fn algorithm(k: &Key) -> Algorithm {
    k.public.algorithm()
}

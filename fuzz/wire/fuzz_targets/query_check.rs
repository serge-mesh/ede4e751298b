//! The query check (edge.md §4 "Parsing") on arbitrary bytes: it never panics; an accepted query
//! has a question `domain` reads the same way and a qname that is that question lowercased; every
//! reply written for it echoes its ID, clears AD, keeps to its limit, is padded to 468-byte
//! blocks over DoT/DoH when the query carried Padding, and decodes; and the upstream query
//! written for it reads back with the same question.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use picket_api::edge_config::{BlockResponse, BlockResponseType};
use picket_wire::ede::EdeOption;
use picket_wire::query::{check_query, write_query_error};
use picket_wire::reply::{
    NegativeKind, REPLY_PAD_BLOCK, Reply, ReplyTo, Transport, write_any_minimal, write_block,
    write_host_mapping, write_local_answer, write_negative, write_rcode,
};
use picket_wire::upstream::{PAD_BLOCK, QueryParams, write_query};
use picket_wire::{EDGE_UDP_PAYLOAD, WriteError};
use picket_wire_fuzz::oracle::domain_decode;

fuzz_target!(|data: &[u8]| {
    let mut out = vec![0u8; 65_535];
    let q = match check_query(data) {
        Ok(q) => q,
        Err(e) => {
            // A reply echoes the ID with QR set; header-unreadable queries and responses get none.
            for transport in [Transport::Udp, Transport::Encrypted] {
                if let Some(n) = write_query_error(&mut out, data, &e, transport, EDGE_UDP_PAYLOAD).unwrap() {
                    assert!(n <= 512);
                    assert_eq!(&out[..2], &data[..2]);
                    assert_ne!(out[2] & 0x80, 0);
                }
            }
            return;
        }
    };
    let (qname, qtype, _) = domain_decode(data).expect("domain rejects an accepted query");
    assert_eq!(qname, q.qname().wire());
    assert_eq!(qtype, q.qtype);
    // The qname is the question's name, ASCII-lowercased; the question is kept as sent.
    let question = q.question();
    let name_len = q.qname().wire().len();
    assert_eq!(question.len(), name_len + 4);
    assert!(question[..name_len].eq_ignore_ascii_case(q.qname().wire()));
    assert!(!q.qname().wire().iter().any(u8::is_ascii_uppercase));
    // Labels, the reversed form, both text forms and the reverse-name tests are total.
    let _ = q.qname().reversed().suffixes().count();
    let _ = q.qname().log_text();
    let _ = q.qname().adguard_text();
    let _ = picket_wire::reverse::is_private_reverse(q.qname().as_name());
    let _ = q.client_options(data).count();

    let long = "x".repeat(data.len() % 200);
    let block = EdeOption::blocked_by_bundle(&long, "c02f7a9e1b4d6e83", "k3j9q2");
    let only_v4 = BlockResponse {
        kind: BlockResponseType::CustomIp,
        ipv4: Some(Ipv4Addr::new(192, 0, 2, 7)),
        ipv6: None,
        ttl: 10,
    };
    let nx = BlockResponse {
        kind: BlockResponseType::Nxdomain,
        ..BlockResponse::default()
    };
    let local: [IpAddr; 2] = [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)];
    let payload = 512u16.saturating_add(u16::from(data.first().copied().unwrap_or(0)).saturating_mul(8));
    let check = |out: &[u8], r: Result<Reply, WriteError>, to: &ReplyTo<'_>, what: &str| {
        let r = r.unwrap_or_else(|e| panic!("{what}: {e}"));
        // Only the TC form may pass a limit too small for the header, question and OPT.
        assert!(r.len <= to.limit || r.tc, "{what}");
        assert!(r.len <= to.limit.max(12 + question.len() + 11), "{what}");
        // A padded reply ends on a 468-byte block, unless the limit cut it short or left no room
        // for the Padding option's 4 bytes (RFC 8467 §4.1, RFC 7830 §4).
        if to.pad && q.has_opt() {
            assert!(
                r.len % REPLY_PAD_BLOCK == 0 || r.len == to.limit || r.len + 4 > to.limit,
                "{what}: padding {} within {}",
                r.len,
                to.limit
            );
        }
        let bytes = &out[..r.len];
        assert_eq!(&bytes[..2], &data[..2], "{what}: ID");
        assert_eq!(bytes[3] & 0x20, 0, "{what}: AD set");
        domain_decode(bytes).unwrap_or_else(|e| panic!("domain rejects {what}: {e}"));
    };
    let tos = [
        q.reply_to(Transport::Udp, EDGE_UDP_PAYLOAD),
        q.reply_to(Transport::Udp, payload),
        q.reply_to(Transport::Stream, EDGE_UDP_PAYLOAD),
        q.reply_to(Transport::Encrypted, EDGE_UDP_PAYLOAD),
        ReplyTo {
            limit: 64,
            ..q.reply_to(Transport::Udp, EDGE_UDP_PAYLOAD)
        },
        // A padded reply squeezed by a small limit (RFC 7830 §4: never past it).
        ReplyTo {
            limit: 64 + usize::from(payload % 512),
            pad: true,
            ..q.reply_to(Transport::Encrypted, EDGE_UDP_PAYLOAD)
        },
    ];
    for to in &tos {
        let r = write_block(&mut out, to, &BlockResponse::default(), block);
        check(&out, r, to, "null_ip block");
        let r = write_block(&mut out, to, &only_v4, block);
        check(&out, r, to, "custom_ip block");
        let r = write_block(
            &mut out,
            to,
            &nx,
            EdeOption::blocked_by_lookup("q9", "timeout", "k3j9q2"),
        );
        check(&out, r, to, "nxdomain block");
        let r = write_rcode(&mut out, to, 5, &[EdeOption::not_permitted()]);
        check(&out, r, to, "REFUSED");
        let r = write_rcode(&mut out, to, 2, &[EdeOption::no_upstream("timeout")]);
        check(&out, r, to, "SERVFAIL");
        let r = write_negative(&mut out, to, NegativeKind::Nxdomain, 10, &[EdeOption::firewall()]);
        check(&out, r, to, "NXDOMAIN");
        let r = write_any_minimal(&mut out, to, 3600);
        check(&out, r, to, "ANY");
        let r = write_host_mapping(&mut out, to, &[Ipv4Addr::LOCALHOST], &[], 10, block).map(|(r, _)| r);
        check(&out, r, to, "host mapping");
        let r = write_local_answer(&mut out, to, &local, 60);
        check(&out, r, to, "local answer");
    }

    // The upstream query reads back with the same question, RD set, the client's CD, our DO and
    // no option but Padding.
    for pad in [false, true] {
        let p = QueryParams {
            id: 0xBEEF,
            cd: q.cd,
            do_bit: true,
            pad,
        };
        let n = write_query(&mut out, q.qname().as_name(), q.qtype, q.qclass, &p).expect("upstream query");
        let up = check_query(&out[..n]).expect("our upstream query doesn't pass the check");
        assert_eq!(up.qname(), q.qname());
        assert_eq!((up.qtype, up.qclass, up.id), (q.qtype, q.qclass, 0xBEEF));
        assert!(up.rd && up.do_bit());
        assert_eq!(up.cd, q.cd);
        assert_eq!(up.client_options(&out[..n]).count(), usize::from(pad));
        if pad {
            assert_eq!(n % PAD_BLOCK, 0);
        }
    }
});

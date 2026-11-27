//! Netlink datagrams from the kernel: message splitting, ack/error/done decoding and the ipset
//! attribute decoders (LIST header and members, TYPE, PROTOCOL).
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_edge_helper::ipset::proto::{Reply, SetHeader, decode_datagram, decode_list, decode_protocol, decode_type};

fuzz_target!(|data: &[u8]| {
    let Ok(replies) = decode_datagram(data) else { return };
    for r in replies {
        if let Reply::Ipset { attrs, .. } = r {
            let mut h = SetHeader::default();
            let _ = decode_list(&attrs, &mut h, &mut |m| {
                let max = if m.elem.ip.is_ipv4() { 32 } else { 128 };
                assert!(m.elem.cidr.is_none_or(|c| c <= max));
            });
            let _ = decode_type(&attrs);
            let _ = decode_protocol(&attrs);
        }
    }
});

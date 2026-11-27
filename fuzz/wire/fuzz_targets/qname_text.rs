//! `QName::from_text` on arbitrary text (build-and-test.md §4 "Fuzzing"): core decodes the names
//! edges log (`qname`, `cname`, `targets`, api.md §5) with it, so it reads untrusted input. It
//! never panics; an accepted name is a valid lowercase wire name (labels of 1 to 63 bytes, at most
//! 255 bytes in all) that its log text, `WireName::from_text` and hickory's decoder all read back
//! as the same name.

#![no_main]

use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use libfuzzer_sys::fuzz_target;
use picket_wire::name::{QName, WireName};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let q = QName::from_text(text);
    let w = WireName::from_text(text);
    assert_eq!(q.is_ok(), w.is_ok(), "QName and WireName disagree on {text:?}");
    let Ok(q) = q else {
        return;
    };
    let wire = q.wire();
    assert_eq!(w.map(|w| w.wire().to_vec()).ok().as_deref(), Some(wire));
    assert!(wire.len() <= 255);
    assert!(!wire.iter().any(u8::is_ascii_uppercase));
    // Labels of 1 to 63 bytes, ending in the root.
    let mut at = 0usize;
    let mut labels = 0usize;
    loop {
        let len = usize::from(wire[at]);
        if len == 0 {
            assert_eq!(at + 1, wire.len());
            break;
        }
        assert!(len <= 63);
        at += 1 + len;
        labels += 1;
    }
    assert_eq!(labels, q.num_labels());
    // The log text reads back as the same name.
    let back = QName::from_text(&q.log_text()).expect("log text reads back");
    assert_eq!(back.wire(), wire);
    // hickory reads the wire form as the same name.
    let mut d = BinDecoder::new(wire);
    let name = Name::read(&mut d).expect("hickory reads the wire form");
    assert!(d.is_empty());
    assert_eq!(QName::from_hickory(&name).expect("from hickory").wire(), wire);
    let _ = q.adguard_text();
    let _ = q.reversed().suffixes().count();
});

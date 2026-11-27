//! Frames from the helper socket: the length-delimited codec, then the typed request decoder,
//! then the checks an `apply` and an `ensure` go through (the edge is untrusted as seen by the
//! helper).
#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use picket_edge_helper::fast::to_op;
use picket_edge_helper::rules::Desired;
use picket_edge_helper::server::{Request, codec, parse_request};
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    // As a raw frame body.
    check(data);
    // As a byte stream through the codec, possibly several frames.
    let mut c = codec();
    let mut buf = BytesMut::from(data);
    while let Ok(Some(f)) = c.decode(&mut buf) {
        check(&f);
    }
});

fn check(f: &[u8]) {
    let Ok((_, req)) = parse_request(f) else { return };
    match req {
        Request::Apply(r) => {
            if let Ok(d) = Desired::from_request(&r) {
                // The persisted form validates again to the same rules.
                assert_eq!(Desired::from_request(&d.to_request()).as_ref(), Ok(&d));
            }
        }
        Request::Ensure(r) => {
            for e in &r.entries {
                if let Ok(op) = to_op(e, true) {
                    let t = op.timeout.unwrap();
                    assert!((1..=picket_api::helper::MAX_TIMEOUT_S).contains(&t));
                }
            }
        }
        Request::Delete(r) => {
            for e in &r.entries {
                let _ = to_op(e, false);
            }
        }
        _ => {}
    }
}

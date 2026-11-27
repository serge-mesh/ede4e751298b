//! `POST /v1/logs` bodies from an edge (api.md §5, core.md §6): the gzip and JSON-lines decoder
//! and the per-record checks. Never panics; whatever passes is within its bounds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::logs::decode::{self, Context, LIMITS, Record};

fuzz_target!(|data: &[u8]| {
    let now: jiff::Timestamp = "2026-11-13T12:00:00Z".parse().unwrap();
    let ctx = Context {
        now,
        oldest: now - jiff::SignedDuration::from_hours(72),
    };
    let small = decode::Limits {
        max_decoded: 1 << 20,
        ..LIMITS
    };
    // As a gzip body, and as the decompressed lines themselves.
    let _ = decode::decode_body(data, true, &ctx, &small);
    if let Ok(batch) = decode::decode_lines(data, &ctx, &small) {
        assert!(batch.lines <= LIMITS.max_records);
        for r in &batch.records {
            let h = r.header();
            assert!(h.ts <= now);
            // An answer goes with the records that reference it, whatever its own time.
            assert!(h.ts >= ctx.oldest || matches!(r, Record::Answer(_)));
            assert!(decode::is_boot_id(&h.boot));
            if let Record::Answer(a) = r {
                assert!(a.wire.len() <= picket_api::logs::MAX_ANSWER_WIRE);
            }
            if let Record::Query(q) = r {
                let row = picket_core::logs::ingest::event_row("e-01", q.clone());
                assert!(row.seq >= 0);
            }
        }
        // The ack names the batch's last record, dropped or not, or nothing.
        let ack = batch.ack();
        assert!(ack.boot.is_empty() || decode::is_boot_id(&ack.boot));
        assert!(ack.seq <= i64::MAX as u64);
    }
});

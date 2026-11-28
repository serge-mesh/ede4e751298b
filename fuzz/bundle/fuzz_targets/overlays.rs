//! Overlays (bundles.md §6; review round 1, B7): IP delta ops staged on a range overlay over
//! several deltas, against a per-address model (values, tombstones, checksums); and the keyed
//! hash overlay with arbitrary (crafted) hashes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_bundle::checksum::SetChecksum;
use picket_bundle::delta::RangeOp;
use picket_bundle::overlay::{Entry, HashOverlay, RangeOverlay, RangeStage};
use picket_bundle::value::Value;

const SPACE: usize = 300;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    // Base: every third address holds value 1.
    let base_of = |a: u32| (a % 3 == 0).then_some(Value(1));
    let base = |a: u32| base_of(a);
    let mut model: Vec<Option<Option<u64>>> = vec![None; SPACE];
    let current = |m: &Vec<Option<Option<u64>>>, a: u32| match m.get(a as usize).copied().flatten() {
        Some(v) => v,
        None => base_of(a).map(|v| v.0),
    };
    let mut prev: RangeOverlay<u32> = RangeOverlay::new();
    let mut cs = SetChecksum::ZERO;
    for (seq, delta) in data.split(|&b| b == 0xff).take(8).enumerate() {
        let mut ops = Vec::new();
        for op in delta.chunks_exact(3) {
            let first = u32::from(op[0]);
            let last = (first + u32::from(op[1] % 32)).min(SPACE as u32 - 1);
            if op[2] & 1 == 0 {
                ops.push(RangeOp::Delete {
                    first: first.into(),
                    last: last.into(),
                });
            } else {
                ops.push(RangeOp::Upsert {
                    first: first.into(),
                    last: last.into(),
                    value: Value(u64::from(op[2] >> 1)),
                });
            }
        }
        // The expected checksum and table, applied the way the spec says: deletes (each run's
        // value read at its first address), then upserts.
        let mut want = cs;
        for op in &ops {
            if let RangeOp::Delete { first, last } = *op {
                if let Some(v) = current(&model, first as u32) {
                    want = want.minus(SetChecksum::ip_entry(true, first, last, v));
                }
                for m in model.iter_mut().take(last as usize + 1).skip(first as usize) {
                    *m = Some(None);
                }
            }
        }
        for op in &ops {
            if let RangeOp::Upsert { first, last, value } = *op {
                want = want.plus(SetChecksum::ip_entry(true, first, last, value.0));
                for m in model.iter_mut().take(last as usize + 1).skip(first as usize) {
                    *m = Some(Some(value.0));
                }
            }
        }
        let mut st = RangeStage::new(&prev, true, cs);
        let seq = seq as u64 + 1;
        st.apply(&ops, seq, cs, want, &base)
            .expect("the model's checksum");
        let (o, got) = st.finish().expect("within limits");
        assert_eq!(got, want);
        for (a, m) in model.iter().enumerate() {
            let e = o.get(a as u32);
            match m {
                None => assert_eq!(e, None, "{a}"),
                Some(None) => assert_eq!(e, Some(Entry::Tombstone), "{a}"),
                Some(Some(v)) => assert_eq!(e, Some(Entry::Upsert(*v)), "{a}"),
            }
        }
        let es: Vec<(u32, u32, Entry<u64>)> = o.entries().collect();
        assert!(es.windows(2).all(|w| w[0].1 < w[1].0), "sorted, disjoint");
        prev = o;
        cs = got;
    }
    // Hash overlay: arbitrary 128-bit hashes (later duplicates win), looked up again.
    let hashes: Vec<u128> = data
        .chunks_exact(16)
        .map(|c| u128::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let entries = hashes.iter().enumerate().map(|(i, h)| {
        (
            *h,
            if i % 5 == 0 {
                Entry::Tombstone
            } else {
                Entry::Upsert(i as u64)
            },
        )
    });
    let o = HashOverlay::from_entries(entries).unwrap();
    let mut last = std::collections::HashMap::new();
    for (i, h) in hashes.iter().enumerate() {
        last.insert(*h, i);
    }
    assert_eq!(o.len(), last.len());
    for (h, i) in &last {
        let want = if i % 5 == 0 {
            Entry::Tombstone
        } else {
            Entry::Upsert(*i as u64)
        };
        assert_eq!(
            o.get(*h).map(|e| match e {
                Entry::Upsert(v) => Entry::Upsert(*v),
                Entry::Tombstone => Entry::Tombstone,
            }),
            Some(want)
        );
    }
});

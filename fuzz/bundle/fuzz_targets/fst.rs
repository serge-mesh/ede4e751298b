//! domains.fst: load (checksum, key count, structural walk), then look keys up and walk it.
//!
//! Three modes: raw bytes; raw bytes with the trailing CRC-32C fixed up (so the structural walk,
//! not the checksum, has to refuse them); and a real FST built from the input's keys with one
//! byte changed and the checksum fixed (near-valid structures). The reader catches panics inside
//! `fst` while it walks a file at load; libFuzzer's panic hook would abort on those caught
//! panics, so this target installs a silent hook (an uncaught panic still aborts through
//! libfuzzer-sys's own catch).
#![no_main]

use std::sync::Once;

use libfuzzer_sys::fuzz_target;
use picket_bundle::domains::{DomainsFst, FstWriter};
use picket_bundle::value::Value;

static HOOK: Once = Once::new();

fn crc32c(buf: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &b in buf {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
        }
    }
    let sum = !crc;
    (sum.wrapping_shr(15) | sum.wrapping_shl(17)).wrapping_add(0xA282_EAD8)
}

fn fix_crc(b: &mut [u8]) {
    if b.len() >= 36 {
        let n = b.len() - 4;
        let c = crc32c(&b[..n]);
        b[n..].copy_from_slice(&c.to_le_bytes());
    }
}

fuzz_target!(|data: &[u8]| {
    HOOK.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    if data.len() < 3 {
        return;
    }
    let (bytes, keys) = match data[0] % 3 {
        0 => (data[2..].to_vec(), u64::from(data[1])),
        1 => {
            let mut b = data[2..].to_vec();
            fix_crc(&mut b);
            (b, u64::from(data[1]))
        }
        _ => {
            let mut ks: Vec<&[u8]> = data[3..].split(|&b| b == b'\n').filter(|k| !k.is_empty() && k.len() <= 253).collect();
            ks.sort_unstable();
            ks.dedup();
            let mut w = FstWriter::new();
            for (i, k) in ks.iter().enumerate() {
                if w.insert(k, Value(i as u64 * 977)).is_err() {
                    return;
                }
            }
            let Ok(mut b) = w.finish() else { return };
            let at = usize::from(data[1]) * 7 % b.len();
            b[at] ^= data[2] | 1;
            fix_crc(&mut b);
            (b, ks.len() as u64)
        }
    };
    let Ok(f) = DomainsFst::from_bytes(bytes, keys) else {
        return;
    };
    for k in [&b"com"[..], b"com.example", b"org.example.ads", b"", b"\xff\xff", &data[2..data.len().min(40)]] {
        let _ = f.get(k);
    }
    for (k, _) in f.entries() {
        assert!(f.get(&k).is_some());
    }
});

//! Page files: the header page, and record pages checked and searched. Modes: raw bytes, and
//! pages sealed with a valid checksum so the header and record parsers see the fuzz input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_bundle::page::{PAGE_SIZE, PageFileHeader, check_page, find_in_page, page_for, seal_header_page, seal_record_page};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let mode = data[0] % 3;
    let body = &data[1..];
    let mut page = [0u8; PAGE_SIZE];
    let n = body.len().min(PAGE_SIZE);
    page[..n].copy_from_slice(&body[..n]);
    let identity = body.get(n..).map_or(0, |t| t.iter().fold(0u128, |a, &b| a.rotate_left(8) ^ u128::from(b)));
    let p = u32::from(data[0] >> 2);
    match mode {
        1 => seal_header_page(&mut page),
        2 => seal_record_page(&mut page, p, identity),
        _ => {}
    }
    if let Ok(h) = PageFileHeader::parse(&page) {
        let _ = h.file_len();
        assert!(h.page_for(u128::MAX) < h.page_count);
    }
    if let Ok(recs) = check_page(&page, p, identity) {
        let mut last = None;
        for r in recs {
            if let Ok((hash, v)) = r {
                assert!(last.is_none_or(|l| l < hash) && v.len() <= 1024);
                last = Some(hash);
                assert_eq!(find_in_page(&page, p, identity, hash).unwrap(), Some(v));
            }
        }
    }
    let _ = find_in_page(&page, p, identity, identity);
    let _ = find_in_page(&page[..n], p, identity, 0);
    let _ = page_for(identity, u32::try_from(n).unwrap_or(1));
});

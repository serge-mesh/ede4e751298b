//! What the `sqs` trigger reads from SQS (feed-scheduling.md §7): `ReceiveMessage` and
//! `DeleteMessageBatch` replies and error replies (JSON protocol). Never panic; at most 10
//! messages with bounded ids and receipt handles; failed-entry codes and error types are
//! sanitized and short.
#![no_main]

use libfuzzer_sys::fuzz_target;
use picket_core::feeds::sqs;

fuzz_target!(|data: &[u8]| {
    if let Ok(ms) = sqs::parse_receive(data) {
        assert!(ms.len() <= 10);
        for m in &ms {
            assert!(!m.id.is_empty() && m.id.len() <= 1024);
            assert!(!m.receipt.is_empty() && m.receipt.len() <= 8192);
        }
    }
    if let Ok(failed) = sqs::parse_delete(data) {
        assert!(failed.len() <= sqs::DELETE_BATCH);
        for f in &failed {
            assert!(f.id.chars().count() <= 16);
            assert!(!f.code.chars().any(char::is_control), "{:?}", f.code);
            // A sender fault is never retried with the same receipt handle.
            assert!(!f.sender_fault || f.permanent());
        }
    }
    let k = sqs::error_kind(data);
    assert!(!k.chars().any(char::is_control), "{k:?}");
});

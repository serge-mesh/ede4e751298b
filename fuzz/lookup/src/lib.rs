//! Shared pieces of the picket-lookup fuzz targets.

use picket_wire::name::QName;

/// Splits input at the first 0xFF byte (or the middle when there is none).
pub fn split(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|&b| b == 0xFF) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => data.split_at(data.len() / 2),
    }
}

/// The ID and question a message carries, read from its bytes (uncompressed question name), so
/// arbitrary input reaches the checks after the ID and question match.
pub fn sent_of(msg: &[u8]) -> Option<(u16, QName, u16, u16)> {
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let mut i = 12;
    let mut labels: Vec<&[u8]> = Vec::new();
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len > 63 {
            return None;
        }
        labels.push(msg.get(i + 1..i + 1 + len)?);
        i += 1 + len;
    }
    let qtype = u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]);
    let qclass = u16::from_be_bytes([*msg.get(i + 2)?, *msg.get(i + 3)?]);
    let name = QName::from_labels(labels).ok()?;
    Some((id, name, qtype, qclass))
}

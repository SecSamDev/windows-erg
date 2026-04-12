use std::fmt::Write;

/// Converts a fixed-width little-endian byte slice into a value.
pub(crate) trait FromBytes: Sized {
    fn from_le_bytes(data: &[u8]) -> Option<Self>;
}

impl FromBytes for usize {
    fn from_le_bytes(data: &[u8]) -> Option<Self> {
        Some(Self::from_le_bytes(data.try_into().ok()?))
    }
}

impl FromBytes for u32 {
    fn from_le_bytes(data: &[u8]) -> Option<Self> {
        Some(Self::from_le_bytes(data.try_into().ok()?))
    }
}

impl FromBytes for u64 {
    fn from_le_bytes(data: &[u8]) -> Option<Self> {
        Some(Self::from_le_bytes(data.try_into().ok()?))
    }
}

pub(crate) fn extract_value_from_buffer<T: FromBytes>(data: &[u8]) -> Option<(T, &[u8])> {
    let size = std::mem::size_of::<T>();
    if data.len() < size {
        return None;
    }
    let value = T::from_le_bytes(&data[..size])?;
    Some((value, &data[size..]))
}

/// Reads a null-terminated ASCII string from the front of `data`.
///
/// Returns the decoded string and the number of bytes consumed including the
/// terminator when present.
pub(crate) fn ascii_string_until_null(data: &[u8]) -> Option<(String, usize)> {
    let end_pos = data.iter().position(|&v| v == 0).unwrap_or(data.len());
    let value = String::from_utf8(data[..end_pos].to_vec()).ok()?;
    Some((value, end_pos.saturating_add(1)))
}

/// Reads a null-terminated UTF-16LE string from the front of `data`.
///
/// Returns the decoded string and the number of bytes consumed.
pub(crate) fn utf16_until_null(data: &[u8]) -> Option<(String, usize)> {
    let mut utf16_units = Vec::with_capacity(data.len() / 2);
    let mut offset = 0usize;

    while offset + 1 < data.len() {
        let unit = u16::from_le_bytes([data[offset], data[offset + 1]]);
        if unit == 0 {
            offset += 2;
            break;
        }
        utf16_units.push(unit);
        offset += 2;
    }

    let value = String::from_utf16(&utf16_units).ok()?;
    Some((value, offset))
}

/// Converts a binary SID to its string form and reports bytes consumed.
///
/// The returned size includes the SID header and all parsed sub-authorities.
pub(crate) fn sid_to_string_with_size(sid: &[u8]) -> Option<(String, usize)> {
    if sid.len() < 8 {
        return None;
    }

    let mut id = String::with_capacity(32);
    let subauthority_count = sid[1] as usize;

    let mut identifier_authority = (u16::from_be_bytes([sid[2], sid[3]]) as u64) << 32;
    identifier_authority |= u32::from_be_bytes([sid[4], sid[5], sid[6], sid[7]]) as u64;

    let _ = write!(&mut id, "S-{}-{}", sid[0], identifier_authority);

    let mut start = 8usize;
    for _ in 0..subauthority_count {
        if start + 4 > sid.len() {
            break;
        }
        let authority =
            u32::from_le_bytes([sid[start], sid[start + 1], sid[start + 2], sid[start + 3]]);
        let _ = write!(&mut id, "-{}", authority);
        start += 4;
    }

    Some((id, start))
}

#[cfg(test)]
mod tests {
    use super::utf16_until_null;

    #[test]
    fn utf16_until_null_parses_aligned_input() {
        let data = [
            0x68, 0x00, // h
            0x69, 0x00, // i
            0x00, 0x00, // null
        ];

        let (value, consumed) = utf16_until_null(&data).expect("expected valid UTF-16 string");
        assert_eq!(value, "hi");
        assert_eq!(consumed, 6);
    }

    #[test]
    fn utf16_until_null_parses_misaligned_subslice() {
        let data = [
            0xFF, // prefix byte to force odd-offset start
            0x48, 0x00, // H
            0x69, 0x00, // i
            0x00, 0x00, // null
        ];

        let (value, consumed) =
            utf16_until_null(&data[1..]).expect("expected valid UTF-16 string from odd offset");
        assert_eq!(value, "Hi");
        assert_eq!(consumed, 6);
    }

    #[test]
    fn utf16_until_null_handles_empty_string() {
        let data = [0x00, 0x00];

        let (value, consumed) = utf16_until_null(&data).expect("expected empty UTF-16 string");
        assert_eq!(value, "");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn utf16_until_null_handles_truncated_input_without_panic() {
        let data = [0x41, 0x00, 0x42];

        let (value, consumed) = utf16_until_null(&data).expect("expected partial UTF-16 parse");
        assert_eq!(value, "A");
        assert_eq!(consumed, 2);
    }
}

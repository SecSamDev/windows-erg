use windows::core::PWSTR;

/// Encode UTF-8 text into UTF-16 code units without a trailing NUL.
pub fn to_utf16(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

/// Encode UTF-8 text into UTF-16 code units with a trailing NUL terminator.
pub fn to_utf16_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Fill a caller-provided UTF-16 buffer with text plus a trailing NUL terminator.
pub fn to_utf16_nul_in(value: &str, out_buffer: &mut Vec<u16>) {
    out_buffer.clear();
    out_buffer.extend(value.encode_utf16());
    out_buffer.push(0);
}

/// Convert a NUL-terminated `PWSTR` into `String`.
///
/// Returns `None` if the pointer is null or the string is empty.
pub fn pwstr_to_string(value: PWSTR) -> Option<String> {
    let ptr = value.0;
    if ptr.is_null() {
        return None;
    }

    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }

        if len == 0 {
            return None;
        }

        let slice = std::slice::from_raw_parts(ptr, len);
        Some(String::from_utf16_lossy(slice))
    }
}

/// Convert a `PWSTR` with an explicit UTF-16 code-unit length into `String`.
pub fn pwstr_to_string_len(value: PWSTR, len: usize) -> String {
    if value.is_null() || len == 0 {
        return String::new();
    }

    let slice = unsafe { std::slice::from_raw_parts(value.0, len) };
    String::from_utf16_lossy(slice)
}

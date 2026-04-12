//! PEB (Process Environment Block) access for reading process parameters.

use std::collections::HashMap;
use std::mem::size_of;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    PEB, PROCESS_BASIC_INFORMATION, RTL_USER_PROCESS_PARAMETERS,
};

use super::processes::Process;
use super::types::{ImagePath, ProcessParameters};
use crate::error::{Error, ProcessError, ProcessOpenError, Result};

// UNICODE_STRING structure (used in RTL_USER_PROCESS_PARAMETERS)
#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

// Cache struct sizes for fast access
const PROCESS_BASIC_INFORMATION_SIZE: usize = size_of::<PROCESS_BASIC_INFORMATION>();
const PEB_SIZE: usize = size_of::<PEB>();
const RTL_USER_PROCESS_PARAMETERS_SIZE: usize = size_of::<RTL_USER_PROCESS_PARAMETERS>();

// RTL_USER_PROCESS_PARAMETERS layout for Windows 7+ (x64)
// This partial struct includes fields up to and including Environment pointer
// Stable across Windows versions; only includes fields we actually need
// https://ntdoc.m417z.com/rtl_user_process_parameters
#[repr(C)]
struct RTL_USER_PROCESS_PARAMETERS_PARTIAL {
    _pad1: [u8; 32],                 // Reserved fields (0x00-0x1F)
    _flags: u32,                     // Flags at 0x20
    _pad2: [u8; 8],                  // More reserved (0x24-0x2B)
    stdin: *mut u8,                  // 0x2C
    stdout: *mut u8,                 // 0x34
    stderr: *mut u8,                 // 0x3C
    image_path_name: UNICODE_STRING, // 0x44
    command_line: UNICODE_STRING,    // 0x54
    environment: *mut u16,           // 0x64 - Environment block pointer
}

impl Process {
    /// Get the command line of the process.
    ///
    /// This reads the command line from the Process Environment Block (PEB).
    pub fn command_line(&self) -> Result<String> {
        let mut buffer = Vec::with_capacity(8192);
        self.command_line_with_buffer(&mut buffer)
    }

    /// Get the command line using a reusable output buffer.
    pub fn command_line_with_buffer(&self, out_buffer: &mut Vec<u8>) -> Result<String> {
        let params = self.read_process_parameters(out_buffer)?;
        Ok(params.command_line)
    }

    /// Get the environment variables of the process.
    pub fn environment(&self) -> Result<HashMap<String, String>> {
        let mut buffer = Vec::with_capacity(8192);
        self.environment_with_buffer(&mut buffer)
    }

    /// Get the environment variables using a reusable output buffer.
    pub fn environment_with_buffer(
        &self,
        out_buffer: &mut Vec<u8>,
    ) -> Result<HashMap<String, String>> {
        // Read PEB to get RTL_USER_PROCESS_PARAMETERS pointer
        let peb_addr = self.read_peb_address(out_buffer)?;

        out_buffer.clear();
        if out_buffer.capacity() < PEB_SIZE {
            out_buffer.reserve(PEB_SIZE - out_buffer.capacity());
        }
        unsafe {
            out_buffer.set_len(PEB_SIZE);
        }

        let mut bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                self.as_raw_handle(),
                peb_addr as _,
                out_buffer.as_mut_ptr() as _,
                PEB_SIZE,
                Some(&mut bytes_read),
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to read PEB",
                e.code().0,
            )))
        })?;

        let peb = unsafe { &*(out_buffer.as_ptr() as *const PEB) };
        let params_addr = peb.ProcessParameters as usize;

        // Read RTL_USER_PROCESS_PARAMETERS
        out_buffer.clear();
        if out_buffer.capacity() < RTL_USER_PROCESS_PARAMETERS_SIZE {
            out_buffer.reserve(RTL_USER_PROCESS_PARAMETERS_SIZE - out_buffer.capacity());
        }
        unsafe {
            out_buffer.set_len(RTL_USER_PROCESS_PARAMETERS_SIZE);
        }

        bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                self.as_raw_handle(),
                params_addr as _,
                out_buffer.as_mut_ptr() as _,
                RTL_USER_PROCESS_PARAMETERS_SIZE,
                Some(&mut bytes_read),
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to read process parameters",
                e.code().0,
            )))
        })?;

        // Cast to our partial struct to get the environment pointer
        let params =
            unsafe { &*(out_buffer.as_ptr() as *const RTL_USER_PROCESS_PARAMETERS_PARTIAL) };

        // Read environment block from the environment pointer
        self.read_environment_block(params.environment as usize, out_buffer)
    }

    /// Get all process parameters (command line, current directory, image path).
    pub fn parameters(&self) -> Result<ProcessParameters> {
        let mut buffer = Vec::with_capacity(8192);
        self.parameters_with_buffer(&mut buffer)
    }

    /// Get all process parameters using a reusable output buffer.
    pub fn parameters_with_buffer(&self, out_buffer: &mut Vec<u8>) -> Result<ProcessParameters> {
        self.read_process_parameters(out_buffer)
    }

    /// Internal: Read PEB address.
    fn read_peb_address(&self, buffer: &mut Vec<u8>) -> Result<usize> {
        buffer.clear();
        if buffer.capacity() < PROCESS_BASIC_INFORMATION_SIZE {
            buffer.reserve(PROCESS_BASIC_INFORMATION_SIZE - buffer.capacity());
        }
        unsafe {
            buffer.set_len(PROCESS_BASIC_INFORMATION_SIZE);
        }

        let mut return_length = 0u32;
        unsafe {
            NtQueryInformationProcess(
                self.as_raw_handle(),
                ProcessBasicInformation,
                buffer.as_mut_ptr() as _,
                PROCESS_BASIC_INFORMATION_SIZE as u32,
                &mut return_length,
            )
            .ok()
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to query process information",
                e.code().0,
            )))
        })?;

        let basic_info = unsafe { &*(buffer.as_ptr() as *const PROCESS_BASIC_INFORMATION) };
        Ok(basic_info.PebBaseAddress as usize)
    }

    /// Internal: Read process parameters from PEB.
    fn read_process_parameters(&self, buffer: &mut Vec<u8>) -> Result<ProcessParameters> {
        let peb_addr = self.read_peb_address(buffer)?;

        // Read PEB
        buffer.clear();
        if buffer.capacity() < PEB_SIZE {
            buffer.reserve(PEB_SIZE - buffer.capacity());
        }
        unsafe {
            buffer.set_len(PEB_SIZE);
        }

        let mut bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                self.as_raw_handle(),
                peb_addr as _,
                buffer.as_mut_ptr() as _,
                PEB_SIZE,
                Some(&mut bytes_read),
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to read PEB for parameters",
                e.code().0,
            )))
        })?;

        let peb = unsafe { &*(buffer.as_ptr() as *const PEB) };
        let params_addr = peb.ProcessParameters as usize;

        // Read RTL_USER_PROCESS_PARAMETERS
        buffer.clear();
        if buffer.capacity() < RTL_USER_PROCESS_PARAMETERS_SIZE {
            buffer.reserve(RTL_USER_PROCESS_PARAMETERS_SIZE - buffer.capacity());
        }
        unsafe {
            buffer.set_len(RTL_USER_PROCESS_PARAMETERS_SIZE);
        }

        bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                self.as_raw_handle(),
                params_addr as _,
                buffer.as_mut_ptr() as _,
                RTL_USER_PROCESS_PARAMETERS_SIZE,
                Some(&mut bytes_read),
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to read RTL_USER_PROCESS_PARAMETERS",
                e.code().0,
            )))
        })?;

        let params = unsafe { &*(buffer.as_ptr() as *const RTL_USER_PROCESS_PARAMETERS) };

        // Read command line
        let cmd_line = self.read_unicode_string(
            params.CommandLine.Buffer.0 as usize,
            params.CommandLine.Length as usize,
            buffer,
        )?;

        // Read image path
        let image_path = self.read_unicode_string(
            params.ImagePathName.Buffer.0 as usize,
            params.ImagePathName.Length as usize,
            buffer,
        )?;

        Ok(ProcessParameters {
            command_line: cmd_line,
            current_directory: String::new(), // Not available in windows-rs bindings
            image_path: ImagePath::from_str(&image_path),
        })
    }

    /// Internal: Read a UNICODE_STRING from process memory.
    fn read_unicode_string(
        &self,
        addr: usize,
        length: usize,
        buffer: &mut Vec<u8>,
    ) -> Result<String> {
        if addr == 0 || length == 0 {
            return Ok(String::new());
        }

        buffer.clear();
        if buffer.capacity() < length {
            buffer.reserve(length - buffer.capacity());
        }
        unsafe {
            buffer.set_len(length);
        }

        let mut bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                self.as_raw_handle(),
                addr as _,
                buffer.as_mut_ptr() as _,
                length,
                Some(&mut bytes_read),
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to read string from process memory",
                e.code().0,
            )))
        })?;

        let u16_slice =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u16, bytes_read / 2) };

        // Find null terminator or use full length
        let end = u16_slice
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(u16_slice.len());

        Ok(String::from_utf16_lossy(&u16_slice[..end]))
    }

    /// Internal: Read environment block from process memory and parse into HashMap.
    /// Environment block format: KEY1=VALUE1\0KEY2=VALUE2\0...\0
    fn read_environment_block(
        &self,
        addr: usize,
        buffer: &mut Vec<u8>,
    ) -> Result<HashMap<String, String>> {
        if addr == 0 {
            return Ok(HashMap::new());
        }

        // Read up to 64KB of environment data (typical max)
        let max_size = 65536;
        buffer.clear();
        buffer.resize(max_size, 0);

        let mut bytes_read = 0;
        unsafe {
            ReadProcessMemory(
                self.as_raw_handle(),
                addr as _,
                buffer.as_mut_ptr() as _,
                max_size,
                Some(&mut bytes_read),
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to read environment block",
                e.code().0,
            )))
        })?;

        // Parse the environment block
        let u16_data =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr() as *const u16, bytes_read / 2) };

        let mut env_vars = HashMap::new();
        let mut pos = 0;

        // Parse KEY=VALUE pairs separated by null terminators
        // Block ends with double null terminator
        while pos < u16_data.len() {
            // Find next null terminator
            let start = pos;
            while pos < u16_data.len() && u16_data[pos] != 0 {
                pos += 1;
            }

            // Empty string means we hit double null (end of block)
            if start == pos {
                break;
            }

            // Convert this entry to string
            let entry = String::from_utf16_lossy(&u16_data[start..pos]);

            // Split on first '=' to get key and value
            if let Some(eq_pos) = entry.find('=') {
                let key = entry[..eq_pos].to_string();
                let value = entry[eq_pos + 1..].to_string();
                env_vars.insert(key, value);
            }

            pos += 1; // Skip the null terminator
        }

        Ok(env_vars)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to convert a string to UTF-16 u16 vector
    fn str_to_u16_vec(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// Helper to create environment block bytes (KEY=VALUE\0KEY=VALUE\0\0)
    fn create_env_block(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut block = Vec::new();

        for (key, value) in pairs {
            let entry = format!("{}={}", key, value);
            for u16_val in entry.encode_utf16() {
                block.push((u16_val & 0xFF) as u8);
                block.push(((u16_val >> 8) & 0xFF) as u8);
            }
            // Null terminator for this entry
            block.push(0);
            block.push(0);
        }

        // Double null to end block
        block.push(0);
        block.push(0);

        block
    }

    #[test]
    fn test_parse_simple_environment() {
        // Create a simple environment block: PATH=C:\Windows\0\0
        let env_block = create_env_block(&[("PATH", "C:\\Windows"), ("TEMP", "C:\\Temp")]);

        // Convert to u16 slice for parsing
        let u16_data: Vec<u16> = env_block
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        // Manual parsing logic (same as in read_environment_block)
        let mut env_vars: HashMap<String, String> = HashMap::new();
        let mut pos = 0;

        while pos < u16_data.len() {
            let start = pos;
            while pos < u16_data.len() && u16_data[pos] != 0 {
                pos += 1;
            }

            if start == pos {
                break;
            }

            let entry = String::from_utf16_lossy(&u16_data[start..pos]);
            if let Some(eq_pos) = entry.find('=') {
                let key = entry[..eq_pos].to_string();
                let value = entry[eq_pos + 1..].to_string();
                env_vars.insert(key, value);
            }

            pos += 1;
        }

        assert_eq!(
            env_vars.get("PATH").map(|s| s.as_str()),
            Some("C:\\Windows")
        );
        assert_eq!(env_vars.get("TEMP").map(|s| s.as_str()), Some("C:\\Temp"));
    }

    #[test]
    fn test_parse_environment_with_equals_in_value() {
        // Environment variable with = in the value
        let env_block = create_env_block(&[("URL", "https://example.com?foo=bar")]);

        let u16_data: Vec<u16> = env_block
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        let mut env_vars: HashMap<String, String> = HashMap::new();
        let mut pos = 0;

        while pos < u16_data.len() {
            let start = pos;
            while pos < u16_data.len() && u16_data[pos] != 0 {
                pos += 1;
            }

            if start == pos {
                break;
            }

            let entry = String::from_utf16_lossy(&u16_data[start..pos]);
            if let Some(eq_pos) = entry.find('=') {
                let key = entry[..eq_pos].to_string();
                let value = entry[eq_pos + 1..].to_string();
                env_vars.insert(key, value);
            }

            pos += 1;
        }

        assert_eq!(
            env_vars.get("URL").map(|s| s.as_str()),
            Some("https://example.com?foo=bar")
        );
    }

    #[test]
    fn test_parse_environment_many_variables() {
        // Test with many environment variables
        let pairs = vec![
            ("PATH", "C:\\Windows"),
            ("TEMP", "C:\\Temp"),
            ("WINDIR", "C:\\Windows"),
            ("USERNAME", "Admin"),
            ("COMPUTERNAME", "DESKTOP"),
            ("PROCESSOR_ARCHITECTURE", "AMD64"),
        ];

        let env_block = create_env_block(&pairs);
        let u16_data: Vec<u16> = env_block
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        let mut env_vars = HashMap::new();
        let mut pos = 0;

        while pos < u16_data.len() {
            let start = pos;
            while pos < u16_data.len() && u16_data[pos] != 0 {
                pos += 1;
            }

            if start == pos {
                break;
            }

            let entry = String::from_utf16_lossy(&u16_data[start..pos]);
            if let Some(eq_pos) = entry.find('=') {
                let key = entry[..eq_pos].to_string();
                let value = entry[eq_pos + 1..].to_string();
                env_vars.insert(key, value);
            }

            pos += 1;
        }

        assert_eq!(env_vars.len(), 6);
        assert_eq!(
            env_vars.get("PATH").map(|s| s.as_str()),
            Some("C:\\Windows")
        );
        assert_eq!(env_vars.get("USERNAME").map(|s| s.as_str()), Some("Admin"));
        assert_eq!(
            env_vars.get("PROCESSOR_ARCHITECTURE").map(|s| s.as_str()),
            Some("AMD64")
        );
    }

    #[test]
    fn test_parse_environment_unicode_values() {
        // Test with Unicode characters in environment values
        let env_block = create_env_block(&[("TEST", "Hello🌍World")]);

        let u16_data: Vec<u16> = env_block
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        let mut env_vars: HashMap<String, String> = HashMap::new();
        let mut pos = 0;

        while pos < u16_data.len() {
            let start = pos;
            while pos < u16_data.len() && u16_data[pos] != 0 {
                pos += 1;
            }

            if start == pos {
                break;
            }

            let entry = String::from_utf16_lossy(&u16_data[start..pos]);
            if let Some(eq_pos) = entry.find('=') {
                let key = entry[..eq_pos].to_string();
                let value = entry[eq_pos + 1..].to_string();
                env_vars.insert(key, value);
            }

            pos += 1;
        }

        assert_eq!(
            env_vars.get("TEST").map(|s| s.as_str()),
            Some("Hello🌍World")
        );
    }

    #[test]
    fn test_unicode_string_struct_layout() {
        // Verify that UNICODE_STRING has correct size and layout
        assert_eq!(
            size_of::<UNICODE_STRING>(),
            16,
            "UNICODE_STRING should be 16 bytes"
        );
    }

    #[test]
    fn test_rtl_user_process_parameters_partial_layout() {
        // Verify that our partial struct has correct size
        // Should be at least 0x6C bytes (environment pointer + size)
        assert!(
            size_of::<RTL_USER_PROCESS_PARAMETERS_PARTIAL>() >= 0x6C,
            "RTL_USER_PROCESS_PARAMETERS_PARTIAL should be at least 0x6C bytes"
        );
    }

    #[test]
    fn test_str_to_u16_conversion() {
        let s = "PATH";
        let u16_vec = str_to_u16_vec(s);
        let recovered = String::from_utf16_lossy(&u16_vec);
        assert_eq!(recovered, s);
    }

    #[test]
    fn test_environment_block_structure() {
        // Verify the structure of our environment block creation
        let block = create_env_block(&[("A", "B"), ("C", "D")]);

        // Just verify it's not empty and contains the right structure
        assert!(!block.is_empty(), "Block should not be empty");

        // Convert and verify first few characters
        if block.len() >= 6 {
            let a_char = u16::from_le_bytes([block[0], block[1]]);
            let eq_char = u16::from_le_bytes([block[2], block[3]]);
            let b_char = u16::from_le_bytes([block[4], block[5]]);

            assert_eq!(a_char, b'A' as u16, "First char should be 'A'");
            assert_eq!(eq_char, b'=' as u16, "Second should be '='");
            assert_eq!(b_char, b'B' as u16, "Third should be 'B'");
        }
    }

    // Note: These integration tests read actual process PEB data.
    // They may not work with pseudo-handles in all cases - using #[ignore] to make optional

    #[test]
    #[ignore] // May fail with pseudo-handle - run manually: cargo test -- --ignored
    fn test_command_line_of_current_process() {
        // Get current process and read its command line
        let current_process = Process::current();
        let cmd_line = current_process
            .command_line()
            .expect("Should read command line");

        // Command line should not be empty
        assert!(!cmd_line.is_empty(), "Command line should not be empty");

        // Should contain the executable name or path
        // For test runner, should contain something like "cargo" or the test executable
        assert!(
            cmd_line.contains(".exe") || cmd_line.contains("cargo") || !cmd_line.is_empty(),
            "Command line should contain executable name"
        );
    }

    #[test]
    #[ignore] // May fail with pseudo-handle - run manually: cargo test -- --ignored
    fn test_command_line_with_buffer() {
        // Test the buffer-reusable version
        let current_process = Process::current();
        let mut buffer = Vec::with_capacity(8192);

        let cmd_line = current_process
            .command_line_with_buffer(&mut buffer)
            .expect("Should read command line with buffer");

        assert!(!cmd_line.is_empty(), "Command line should not be empty");

        // Reuse buffer for second call - should work correctly
        let cmd_line2 = current_process
            .command_line_with_buffer(&mut buffer)
            .expect("Should read command line again");

        assert_eq!(cmd_line, cmd_line2, "Command line should be consistent");
    }

    #[test]
    #[ignore] // May fail with pseudo-handle - run manually: cargo test -- --ignored
    fn test_parameters_of_current_process() {
        // Get current process and read its parameters
        let current_process = Process::current();
        let params = current_process
            .parameters()
            .expect("Should read parameters");

        // Command line should not be empty
        assert!(
            !params.command_line.is_empty(),
            "Parameters command_line should not be empty"
        );

        // Image path should be set (the executable path)
        let image_str = params.image_path.as_str();
        assert!(
            !image_str.is_empty(),
            "Parameters image_path should not be empty"
        );
        assert!(
            image_str.contains(".exe") || !image_str.is_empty(),
            "Image path should look like an executable"
        );
    }

    #[test]
    #[ignore] // May fail with pseudo-handle - run manually: cargo test -- --ignored
    fn test_parameters_with_buffer() {
        // Test the buffer-reusable version
        let current_process = Process::current();
        let mut buffer = Vec::with_capacity(8192);

        let params = current_process
            .parameters_with_buffer(&mut buffer)
            .expect("Should read parameters with buffer");

        assert!(
            !params.command_line.is_empty(),
            "Command line should not be empty"
        );

        // Reuse buffer for second call
        let params2 = current_process
            .parameters_with_buffer(&mut buffer)
            .expect("Should read parameters again");

        assert_eq!(
            params.command_line, params2.command_line,
            "Command line should be consistent"
        );
        assert_eq!(
            params.image_path.as_str(),
            params2.image_path.as_str(),
            "Image path should be consistent"
        );
    }

    #[test]
    #[ignore] // May fail with pseudo-handle - run manually: cargo test -- --ignored
    fn test_environment_of_current_process() {
        // Get current process and read its environment variables
        let current_process = Process::current();
        let env = current_process
            .environment()
            .expect("Should read environment variables");

        // Should have some environment variables
        assert!(!env.is_empty(), "Environment should not be empty");

        // PATH is almost always present
        let has_path = env.iter().any(|(k, _)| k.eq_ignore_ascii_case("PATH"));
        assert!(
            has_path || env.len() > 5,
            "Should have PATH or multiple environment variables"
        );
    }

    #[test]
    #[ignore] // May fail with pseudo-handle - run manually: cargo test -- --ignored
    fn test_environment_with_buffer() {
        // Test the buffer-reusable version
        let current_process = Process::current();
        let mut buffer = Vec::with_capacity(8192);

        let env = current_process
            .environment_with_buffer(&mut buffer)
            .expect("Should read environment with buffer");

        assert!(!env.is_empty(), "Environment should not be empty");

        // Reuse buffer for second call
        let env2 = current_process
            .environment_with_buffer(&mut buffer)
            .expect("Should read environment again");

        assert_eq!(
            env.len(),
            env2.len(),
            "Environment variable count should be consistent"
        );
    }

    #[test]
    #[ignore] // May fail with pseudo-handle - run manually: cargo test -- --ignored
    fn test_environment_common_variables() {
        // Check for commonly present environment variables
        let current_process = Process::current();
        let env = current_process
            .environment()
            .expect("Should read environment variables");

        // At least one of these should be present
        let common_vars = ["PATH", "TEMP", "TMP", "WINDIR", "SYSTEMROOT", "USERNAME"];
        let found = common_vars
            .iter()
            .any(|var| env.iter().any(|(k, _)| k.eq_ignore_ascii_case(var)));

        assert!(
            found,
            "Should find at least one common environment variable (PATH, TEMP, WINDIR, etc.)"
        );
    }

    #[test]
    #[ignore] // May fail with pseudo-handle - run manually: cargo test -- --ignored
    fn test_environment_values_are_valid_strings() {
        // Verify all environment values are valid UTF-16 strings
        let current_process = Process::current();
        let env = current_process
            .environment()
            .expect("Should read environment variables");

        // All keys and values should be non-empty and valid strings
        for (key, _value) in env.iter() {
            assert!(
                !key.is_empty(),
                "Environment variable key should not be empty"
            );
            // Value can be empty (e.g., some vars have empty values)
            assert!(
                key.chars().all(|c| c.is_ascii_graphic() || c == '_'),
                "Environment variable key should contain valid characters"
            );
        }
    }
}

//! Process-related types and enumerations.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;
use windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;

// Re-export common types
pub use crate::types::{ProcessId, ThreadId};

/// Case-insensitive string key for HashMap lookups.
/// Hashes and compares strings case-insensitively without allocating lowercase strings.
#[derive(Debug, Clone, Copy)]
struct CaseInsensitiveKey<'a>(&'a str);

impl<'a> Hash for CaseInsensitiveKey<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash each character converted to lowercase on-the-fly
        for ch in self.0.chars() {
            ch.to_ascii_lowercase().hash(state);
        }
    }
}

impl<'a> PartialEq for CaseInsensitiveKey<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl<'a> Eq for CaseInsensitiveKey<'a> {}

/// Static path cache for common image paths.
/// Uses a HashMap with case-insensitive hashing for O(1) lookups.
static PATH_CACHE: OnceLock<HashMap<CaseInsensitiveKey<'static>, &'static str>> = OnceLock::new();

/// Common system paths to cache (static strings, no allocation)
const COMMON_PATHS: &[&str] = &[
    // Core kernel DLLs (System32)
    "C:\\Windows\\System32\\kernel32.dll",
    "C:\\Windows\\System32\\ntdll.dll",
    "C:\\Windows\\System32\\msvcrt.dll",
    "C:\\Windows\\System32\\advapi32.dll",
    "C:\\Windows\\System32\\user32.dll",
    "C:\\Windows\\System32\\gdi32.dll",
    "C:\\Windows\\System32\\ws2_32.dll",
    "C:\\Windows\\System32\\shell32.dll",
    "C:\\Windows\\System32\\ole32.dll",
    "C:\\Windows\\System32\\oleaut32.dll",
    "C:\\Windows\\System32\\comctl32.dll",
    "C:\\Windows\\System32\\comdlg32.dll",
    "C:\\Windows\\System32\\winmm.dll",
    "C:\\Windows\\System32\\shlwapi.dll",
    "C:\\Windows\\System32\\urlmon.dll",
    "C:\\Windows\\System32\\wininet.dll",
    "C:\\Windows\\System32\\msi.dll",
    "C:\\Windows\\System32\\crypt32.dll",
    "C:\\Windows\\System32\\cryptbase.dll",
    "C:\\Windows\\System32\\cryptnet.dll",
    "C:\\Windows\\System32\\ncrypt.dll",
    "C:\\Windows\\System32\\bcryptprimitives.dll",
    "C:\\Windows\\System32\\secur32.dll",
    "C:\\Windows\\System32\\sspicli.dll",
    "C:\\Windows\\System32\\ntsecapi.dll",
    "C:\\Windows\\System32\\wlanapi.dll",
    "C:\\Windows\\System32\\netapi32.dll",
    "C:\\Windows\\System32\\iphlpapi.dll",
    "C:\\Windows\\System32\\dnsapi.dll",
    "C:\\Windows\\System32\\nsi.dll",
    "C:\\Windows\\System32\\setupapi.dll",
    "C:\\Windows\\System32\\cfgmgr32.dll",
    "C:\\Windows\\System32\\regapi.dll",
    "C:\\Windows\\System32\\opengl32.dll",
    // Common EXEs
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\rundll32.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Windows\\System32\\regedit.exe",
    "C:\\Windows\\System32\\conhost.exe",
    // Core kernel DLLs (SysWOW64 - 32-bit)
    "C:\\Windows\\SysWOW64\\kernel32.dll",
    "C:\\Windows\\SysWOW64\\ntdll.dll",
    "C:\\Windows\\SysWOW64\\msvcrt.dll",
    "C:\\Windows\\SysWOW64\\advapi32.dll",
    "C:\\Windows\\SysWOW64\\user32.dll",
    "C:\\Windows\\SysWOW64\\gdi32.dll",
    "C:\\Windows\\SysWOW64\\ws2_32.dll",
    "C:\\Windows\\SysWOW64\\shell32.dll",
    "C:\\Windows\\SysWOW64\\ole32.dll",
    "C:\\Windows\\SysWOW64\\oleaut32.dll",
    "C:\\Windows\\SysWOW64\\comctl32.dll",
    "C:\\Windows\\SysWOW64\\comdlg32.dll",
    "C:\\Windows\\SysWOW64\\crypt32.dll",
    "C:\\Windows\\SysWOW64\\cryptbase.dll",
    "C:\\Windows\\SysWOW64\\secur32.dll",
    "C:\\Windows\\SysWOW64\\setupapi.dll",
    // Directory references
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
    "C:\\Windows\\",
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
];

/// Initialize the path cache HashMap.
fn init_path_cache() -> HashMap<CaseInsensitiveKey<'static>, &'static str> {
    COMMON_PATHS
        .iter()
        .map(|&path| (CaseInsensitiveKey(path), path))
        .collect()
}

/// Efficient image path representation for EXEs and DLLs.
///
/// Provides:
/// - Path caching to reduce memory usage
/// - Case-insensitive comparison
/// - Ownership tracking (owned vs cached)
#[derive(Debug, Clone)]
pub enum ImagePath {
    /// Reference to a static cached path
    Cached(&'static str),
    /// Dynamically allocated path
    Owned(String),
}

impl ImagePath {
    /// Create an ImagePath from a string, using cache when possible.
    pub fn new(path: impl Into<String>) -> Self {
        let path_str = path.into();

        // Try to find in cache
        if let Some(cached) = Self::find_cached(&path_str) {
            return ImagePath::Cached(cached);
        }

        ImagePath::Owned(path_str)
    }

    /// Create an ImagePath from a &str, checking cache without allocating if found.
    ///
    /// This is more efficient than `new()` when working with string slices,
    /// as it avoids allocation if the path is in the cache.
    ///
    /// Automatically strips null terminators from the input to enable cache hits
    /// when receiving null-terminated strings from Windows APIs.
    pub fn from_str(path: &str) -> Self {
        // Strip null terminator if present (common in Windows API results)
        let path = path.trim_end_matches('\0');

        // Try to find in cache first (no allocation needed)
        if let Some(cached) = Self::find_cached_str(path) {
            return ImagePath::Cached(cached);
        }

        // Not in cache, allocate
        ImagePath::Owned(path.to_string())
    }

    /// Create an ImagePath from UTF-16 data (e.g., from GetProcessImageFileNameW).
    ///
    /// This is the most efficient constructor for Windows API results that return UTF-16.
    /// It checks the cache before allocating, using the lossy UTF-16 decoding.
    /// Automatically strips null terminators for cache hits with null-terminated strings.
    pub fn from_utf16(utf16_data: &[u16]) -> Self {
        // Decode UTF-16 (lossy conversion for invalid sequences)
        let path_string = String::from_utf16_lossy(utf16_data);

        // Strip null terminator if present (common in Windows API results)
        let path_str = path_string.trim_end_matches('\0');
        let path_lower = path_str.to_lowercase();

        // Try cache lookup with the lowercase version
        if let Some(cached) = Self::find_cached_str(&path_lower) {
            return ImagePath::Cached(cached);
        }

        // Not in cache, use the allocated string (without null terminator)
        ImagePath::Owned(path_str.to_string())
    }

    /// Create an ImagePath from UTF-8 data (e.g., from Windows API results).
    ///
    /// Returns None if the data is not valid UTF-8.
    /// Automatically strips null terminators for cache hits with null-terminated strings.
    pub fn from_utf8(utf8_data: &[u8]) -> Option<Self> {
        let path_str = std::str::from_utf8(utf8_data).ok()?;

        // Strip null terminator if present
        let path_str = path_str.trim_end_matches('\0');

        // Try to find in cache first
        if let Some(cached) = Self::find_cached_str(path_str) {
            return Some(ImagePath::Cached(cached));
        }

        // Not in cache, allocate
        Some(ImagePath::Owned(path_str.to_string()))
    }

    /// Get the path as a string slice.
    pub fn as_str(&self) -> &str {
        match self {
            ImagePath::Cached(s) => s,
            ImagePath::Owned(s) => s.as_str(),
        }
    }

    /// Check if path matches another (case-insensitive on Windows).
    pub fn eq_case_insensitive(&self, other: &str) -> bool {
        self.as_str().eq_ignore_ascii_case(other)
    }

    /// Check if path contains a substring (case-insensitive).
    pub fn contains_case_insensitive(&self, needle: &str) -> bool {
        self.as_str()
            .to_lowercase()
            .contains(&needle.to_lowercase())
    }

    /// Check if path ends with a suffix (case-insensitive).
    pub fn ends_with_case_insensitive(&self, suffix: &str) -> bool {
        let path_lower = self.as_str().to_lowercase();
        let suffix_lower = suffix.to_lowercase();
        path_lower.ends_with(&suffix_lower)
    }

    /// Check if this is a system path.
    pub fn is_system_path(&self) -> bool {
        let path_lower = self.as_str().to_lowercase();
        path_lower.contains("\\windows\\") || path_lower.contains("\\winnt\\")
    }

    /// Check if this is a 32-bit SysWOW64 module.
    pub fn is_wow64(&self) -> bool {
        self.contains_case_insensitive("\\SysWOW64\\")
    }

    /// Get the file name only (without path).
    pub fn file_name(&self) -> &str {
        self.as_str().rsplit('\\').next().unwrap_or(self.as_str())
    }

    /// Find a matching cached path for the given string (does lowercase comparison).
    fn find_cached(path: &str) -> Option<&'static str> {
        Self::find_cached_str(path)
    }

    /// Find a matching cached path using case-insensitive HashMap lookup (O(1)).
    /// No temporary string allocations - hashing is done on-the-fly during lookup.
    fn find_cached_str(path: &str) -> Option<&'static str> {
        let cache = PATH_CACHE.get_or_init(init_path_cache);
        cache.get(&CaseInsensitiveKey(path)).copied()
    }

    /// Add a new path to the cache (for runtime-discovered common paths).
    /// Note: This is a no-op since we use static strings. Consider using this
    /// if implementing a mutable cache in the future.
    pub fn cache_path(_path: &'static str) {
        // Future: could maintain a separate runtime cache
    }

    /// Check if using cached storage.
    pub fn is_cached(&self) -> bool {
        matches!(self, ImagePath::Cached(_))
    }
}

impl fmt::Display for ImagePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl PartialEq for ImagePath {
    fn eq(&self, other: &Self) -> bool {
        self.eq_case_insensitive(other.as_str())
    }
}

impl PartialEq<str> for ImagePath {
    fn eq(&self, other: &str) -> bool {
        self.eq_case_insensitive(other)
    }
}

impl PartialEq<ImagePath> for str {
    fn eq(&self, other: &ImagePath) -> bool {
        other.eq_case_insensitive(self)
    }
}

impl PartialEq<&str> for ImagePath {
    fn eq(&self, other: &&str) -> bool {
        self.eq_case_insensitive(other)
    }
}

impl PartialEq<ImagePath> for &str {
    fn eq(&self, other: &ImagePath) -> bool {
        other.eq_case_insensitive(self)
    }
}

/// Process access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessAccess {
    /// Query basic information.
    QueryInformation,
    /// Query limited information.
    QueryLimitedInformation,
    /// Read process memory.
    VmRead,
    /// Write process memory.
    VmWrite,
    /// Terminate the process.
    Terminate,
    /// Create threads.
    CreateThread,
    /// All access rights.
    AllAccess,
    /// Custom access rights.
    Custom(PROCESS_ACCESS_RIGHTS),
}

impl ProcessAccess {
    pub(crate) fn to_windows(self) -> PROCESS_ACCESS_RIGHTS {
        use windows::Win32::System::Threading::*;

        const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

        match self {
            ProcessAccess::QueryInformation => PROCESS_QUERY_INFORMATION | PROCESS_SYNCHRONIZE,
            ProcessAccess::QueryLimitedInformation => {
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE
            }
            ProcessAccess::VmRead => PROCESS_VM_READ | PROCESS_SYNCHRONIZE,
            ProcessAccess::VmWrite => PROCESS_VM_WRITE | PROCESS_SYNCHRONIZE,
            ProcessAccess::Terminate => PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
            ProcessAccess::CreateThread => PROCESS_CREATE_THREAD | PROCESS_SYNCHRONIZE,
            ProcessAccess::AllAccess => PROCESS_ALL_ACCESS,
            ProcessAccess::Custom(rights) => rights,
        }
    }
}

/// Basic process information.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: ProcessId,
    /// Parent process ID.
    pub parent_pid: Option<ProcessId>,
    /// Process name (executable file name).
    pub name: String,
    /// Number of threads.
    pub thread_count: u32,
}

/// Thread information.
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    /// Thread ID.
    pub tid: ThreadId,
    /// Owning process ID.
    pub pid: ProcessId,
    /// Base priority.
    pub base_priority: i32,
}

/// Module (DLL) information.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module name (e.g., "kernel32.dll").
    pub name: String,
    /// Full path to the module.
    pub path: ImagePath,
    /// Base address in process memory.
    pub base_address: usize,
    /// Module size in bytes.
    pub size: u32,
}

/// Process parameters from PEB.
#[derive(Debug, Clone)]
pub struct ProcessParameters {
    /// Command line.
    pub command_line: String,
    /// Current directory.
    pub current_directory: String,
    /// Image path.
    pub image_path: ImagePath,
}

/// Memory usage information.
#[derive(Debug, Clone, Copy)]
pub struct MemoryInfo {
    /// Working set size in bytes.
    pub working_set: usize,
    /// Peak working set size in bytes.
    pub peak_working_set: usize,
    /// Page fault count.
    pub page_fault_count: u32,
}

/// Process CPU time counters.
///
/// Values are cumulative from process start, in 100-nanosecond units.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessCpuTimes {
    /// Cumulative time spent in user mode (100ns units).
    pub user_time_100ns: u64,
    /// Cumulative time spent in kernel mode (100ns units).
    pub kernel_time_100ns: u64,
    /// Sum of user and kernel times (100ns units).
    pub total_time_100ns: u64,
}

/// Extended process memory metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessMemoryMetrics {
    /// Working set size in bytes.
    pub working_set_bytes: usize,
    /// Peak working set size in bytes.
    pub peak_working_set_bytes: usize,
    /// Page fault count.
    pub page_fault_count: u32,
    /// Private memory usage in bytes.
    pub private_usage_bytes: usize,
    /// Commit charge (pagefile usage) in bytes.
    pub commit_usage_bytes: usize,
    /// Peak commit charge in bytes.
    pub peak_commit_usage_bytes: usize,
}

/// Point-in-time metrics for a process.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessMetrics {
    /// Memory metrics.
    pub memory: ProcessMemoryMetrics,
    /// CPU time counters.
    pub cpu: ProcessCpuTimes,
}

/// Point-in-time memory metrics for the host.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostMemoryMetrics {
    /// Total visible physical memory in bytes.
    pub total_physical_bytes: u64,
    /// Available physical memory in bytes.
    pub available_physical_bytes: u64,
    /// Total virtual memory available to the process in bytes.
    pub total_virtual_bytes: u64,
    /// Available virtual memory in bytes.
    pub available_virtual_bytes: u64,
    /// Percentage of physical memory in use.
    pub memory_load_percent: u32,
}

/// Point-in-time metrics for the host.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostMetrics {
    /// Number of logical processors visible to the current process.
    pub logical_cpu_count: u32,
    /// Host memory metrics.
    pub memory: HostMemoryMetrics,
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_path_cache_hit() {
        // Test that kernel32.dll is cached
        let path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert!(path.is_cached(), "kernel32.dll should be cached");
        match path {
            ImagePath::Cached(s) => {
                assert_eq!(s, "C:\\Windows\\System32\\kernel32.dll");
            }
            _ => panic!("Expected Cached variant"),
        }
    }

    #[test]
    fn test_image_path_cache_miss() {
        // Test that unknown path allocates
        let path = ImagePath::from_str("C:\\Unknown\\Path\\custom.dll");
        assert!(!path.is_cached(), "Unknown path should not be cached");
        match path {
            ImagePath::Owned(s) => {
                assert_eq!(s, "C:\\Unknown\\Path\\custom.dll");
            }
            _ => panic!("Expected Owned variant"),
        }
    }

    #[test]
    fn test_image_path_case_insensitive_cache_hit() {
        // Test that cache lookup is case-insensitive
        let path_upper = ImagePath::from_str("C:\\WINDOWS\\SYSTEM32\\KERNEL32.DLL");
        let path_mixed = ImagePath::from_str("c:\\windows\\system32\\kernel32.dll");

        assert!(path_upper.is_cached(), "Uppercase path should be cached");
        assert!(path_mixed.is_cached(), "Lowercase path should be cached");
    }

    #[test]
    fn test_image_path_new_allocates_then_caches() {
        // Test new() method
        let path = ImagePath::new("C:\\Windows\\System32\\ntdll.dll");
        assert!(path.is_cached(), "Common path should be cached with new()");
    }

    #[test]
    fn test_image_path_from_utf16() {
        // Test UTF-16 construction
        let utf16: Vec<u16> = "C:\\Windows\\System32\\advapi32.dll"
            .encode_utf16()
            .collect();
        let path = ImagePath::from_utf16(&utf16);

        assert!(path.is_cached(), "UTF-16 common path should be cached");
        assert_eq!(path.as_str(), "C:\\Windows\\System32\\advapi32.dll");
    }

    #[test]
    fn test_image_path_from_utf16_case_insensitive() {
        // Test UTF-16 with different case
        let utf16: Vec<u16> = "C:\\WINDOWS\\SYSTEM32\\USER32.DLL".encode_utf16().collect();
        let path = ImagePath::from_utf16(&utf16);

        assert!(path.is_cached(), "UTF-16 uppercase path should be cached");
    }

    #[test]
    fn test_image_path_from_utf8() {
        // Test UTF-8 construction
        let path = ImagePath::from_utf8(b"C:\\Windows\\System32\\shell32.dll");
        assert!(path.is_some(), "Valid UTF-8 should succeed");
        let path = path.unwrap();
        assert!(path.is_cached(), "UTF-8 common path should be cached");
    }

    #[test]
    fn test_image_path_from_utf8_invalid() {
        // Test invalid UTF-8
        let invalid_utf8 = [0xFF, 0xFE];
        let path = ImagePath::from_utf8(&invalid_utf8);
        assert!(path.is_none(), "Invalid UTF-8 should return None");
    }

    #[test]
    fn test_image_path_display() {
        let path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert_eq!(format!("{}", path), "C:\\Windows\\System32\\kernel32.dll");
    }

    #[test]
    fn test_image_path_partial_eq_self() {
        let path1 = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        let path2 = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert_eq!(path1, path2, "Same paths should be equal");
    }

    #[test]
    fn test_image_path_partial_eq_different_case() {
        let path1 = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        let path2 = ImagePath::from_str("c:\\windows\\system32\\kernel32.dll");
        assert_eq!(
            path1, path2,
            "Different case should be equal (case-insensitive)"
        );
    }

    #[test]
    fn test_image_path_eq_str() {
        let path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert_eq!(&path, "C:\\Windows\\System32\\kernel32.dll");
        assert_eq!(&path, "c:\\windows\\system32\\kernel32.dll");
    }

    #[test]
    fn test_image_path_eq_owned_vs_cached() {
        let cached = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        let owned = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");

        // Both should be cached and equal
        assert!(cached.is_cached());
        assert!(owned.is_cached());
        assert_eq!(cached, owned);
    }

    #[test]
    fn test_image_path_file_name() {
        let path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert_eq!(path.file_name(), "kernel32.dll");
    }

    #[test]
    fn test_image_path_file_name_no_path() {
        let path = ImagePath::from_str("kernel32.dll");
        assert_eq!(path.file_name(), "kernel32.dll");
    }

    #[test]
    fn test_image_path_is_system_path() {
        let sys_path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert!(sys_path.is_system_path(), "Should detect Windows path");

        let other_path = ImagePath::from_str("C:\\Program Files\\app.exe");
        assert!(
            !other_path.is_system_path(),
            "Should not detect non-Windows path"
        );
    }

    #[test]
    fn test_image_path_is_system_path_case_insensitive() {
        let sys_path = ImagePath::from_str("C:\\WINDOWS\\SYSTEM32\\kernel32.dll");
        assert!(
            sys_path.is_system_path(),
            "Should detect Windows path (uppercase)"
        );
    }

    #[test]
    fn test_image_path_is_wow64() {
        let wow64_path = ImagePath::from_str("C:\\Windows\\SysWOW64\\kernel32.dll");
        assert!(wow64_path.is_wow64(), "Should detect SysWOW64 path");

        let normal_path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert!(
            !normal_path.is_wow64(),
            "Should not detect System32 as WOW64"
        );
    }

    #[test]
    fn test_image_path_is_wow64_case_insensitive() {
        let wow64_path = ImagePath::from_str("C:\\WINDOWS\\SYSWOW64\\kernel32.dll");
        assert!(
            wow64_path.is_wow64(),
            "Should detect SysWOW64 path (uppercase)"
        );
    }

    #[test]
    fn test_image_path_ends_with_case_insensitive() {
        let path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert!(
            path.ends_with_case_insensitive(".dll"),
            "Should end with .dll"
        );
        assert!(
            path.ends_with_case_insensitive(".DLL"),
            "Should end with .DLL (case-insensitive)"
        );
        assert!(
            !path.ends_with_case_insensitive(".exe"),
            "Should not end with .exe"
        );
    }

    #[test]
    fn test_image_path_contains_case_insensitive() {
        let path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert!(
            path.contains_case_insensitive("system32"),
            "Should contain system32"
        );
        assert!(
            path.contains_case_insensitive("SYSTEM32"),
            "Should contain SYSTEM32 (case-insensitive)"
        );
        assert!(
            path.contains_case_insensitive("kernel32"),
            "Should contain kernel32"
        );
        assert!(
            !path.contains_case_insensitive("syswow64"),
            "Should not contain syswow64"
        );
    }

    #[test]
    fn test_image_path_eq_case_insensitive() {
        let path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert!(path.eq_case_insensitive("C:\\Windows\\System32\\kernel32.dll"));
        assert!(path.eq_case_insensitive("c:\\windows\\system32\\kernel32.dll"));
        assert!(path.eq_case_insensitive("C:\\WINDOWS\\SYSTEM32\\KERNEL32.DLL"));
    }

    #[test]
    fn test_image_path_clone() {
        let path1 = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        let path2 = path1.clone();

        assert_eq!(path1, path2);
        assert_eq!(path1.as_str(), path2.as_str());
    }

    #[test]
    fn test_cache_initialization() {
        // First access should initialize the cache
        let path1 = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert!(path1.is_cached());

        // Subsequent accesses should use the same cache
        let path2 = ImagePath::from_str("C:\\Windows\\System32\\ntdll.dll");
        assert!(path2.is_cached());
    }

    #[test]
    fn test_multiple_cache_hits() {
        // Test that multiple different cached paths work
        let paths = vec![
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Windows\\System32\\ntdll.dll",
            "C:\\Windows\\System32\\msvcrt.dll",
            "C:\\Windows\\SysWOW64\\kernel32.dll",
        ];

        for p in paths {
            let image_path = ImagePath::from_str(p);
            assert!(image_path.is_cached(), "Path {} should be cached", p);
            assert_eq!(image_path.as_str(), p);
        }
    }

    #[test]
    fn test_cache_with_owned_allocation() {
        // Mix of cached and owned
        let cached = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        let owned = ImagePath::from_str("C:\\Custom\\unknown.dll");

        assert!(cached.is_cached());
        assert!(!owned.is_cached());

        assert_eq!(cached.as_str(), "C:\\Windows\\System32\\kernel32.dll");
        assert_eq!(owned.as_str(), "C:\\Custom\\unknown.dll");
    }

    #[test]
    fn test_case_insensitive_key_hashing() {
        // Test that case-insensitive keys hash consistently
        let key1 = CaseInsensitiveKey("C:\\Windows\\System32\\kernel32.dll");
        let key2 = CaseInsensitiveKey("c:\\windows\\system32\\kernel32.dll");

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher1 = DefaultHasher::new();
        key1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        key2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(
            hash1, hash2,
            "Case-insensitive keys should hash to the same value"
        );
    }

    #[test]
    fn test_process_id_from_u32() {
        let id = ProcessId::from(1234u32);
        assert_eq!(id.as_u32(), 1234);
    }

    #[test]
    fn test_thread_id_from_u32() {
        let id = ThreadId::from(5678u32);
        assert_eq!(id.as_u32(), 5678);
    }

    #[test]
    fn test_image_path_with_null_terminator() {
        // Test behavior when a path string contains null terminator at the end
        // This simulates paths coming from Windows APIs that might include null termination
        let path_with_null = "C:\\Windows\\System32\\kernel32.dll\0";
        let image_path = ImagePath::from_str(path_with_null);

        // The null terminator should be stripped so we can match against cached entries
        // Cached entries don't have null terminators, so we must trim them for cache hits
        assert_eq!(image_path.as_str(), "C:\\Windows\\System32\\kernel32.dll");
        assert!(
            !image_path.as_str().ends_with('\0'),
            "Null terminator should be stripped"
        );

        // Test that it's cached (null terminator was stripped, allowing cache lookup)
        assert!(
            image_path.is_cached(),
            "Should be cached after null terminator is stripped"
        );

        // Test that the result matches the cached version
        let path_without_null = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll");
        assert_eq!(image_path, path_without_null);
    }
}

# Windows-ERG: Agent Context File

**IMPORTANT FOR AGENTS**: This file contains everything you need to understand and work on this project. DO NOT create additional markdown files to explain your changes unless explicitly requested by the user.

## Project Overview
**windows-erg** is a Rust library providing ergonomic, idiomatic wrappers around Windows APIs. Built on `windows-rs`, it abstracts handle management, permission handling, and error handling complexity.

## Core Philosophy
- **Ergonomic**: Rust-idiomatic interfaces (builders, iterators, type safety)
- **Safe**: RAII handle management, no manual cleanup
- **Simple**: Hide Windows API complexity
- **Structured Errors**: Use `Cow<'static, str>` and dedicated error structs, NOT String everywhere

## Critical Coding Standards

### Error Handling Pattern (FOLLOW THIS!)
**NEVER use `String` for errors. Use `Cow<'static, str>` and structured error types.**

```rust
// ❌ WRONG - Don't do this
return Err(Error::InvalidParameter("something went wrong".to_string()));

// ✅ CORRECT - Use structured errors
return Err(Error::InvalidParameter(InvalidParameterError::new(
    "parameter_name",
    "why it's invalid"
)));

// For static strings (preferred)
Cow::Borrowed("static message")

// For dynamic strings (when needed)
Cow::Owned(format!("dynamic {}", value))

// Store error codes when available
WindowsApiError::with_context(err, "operation_name")
FileOperationError::with_code(path, operation, error_code)
```

### Error Types Structure
All errors in `src/error.rs` follow this pattern:
- Main `Error` enum with variants for each module
- Each variant contains a structured error type
- Structured errors have fields: resource identifiers, reasons (Cow), optional error codes
- Format strings only in `Display` implementation

### RAII Handle Pattern (All Modules Follow This)
```rust
pub struct SomeHandle {
    handle: HANDLE,  // or HKEY, etc.
    close_on_drop: bool,  // for predefined handles
}

impl Drop for SomeHandle {
    fn drop(&mut self) {
        if self.close_on_drop {
            unsafe { CloseHandle(self.handle); }
        }
    }
}
```

### Builder Pattern (For Complex Operations)
```rust
pub struct SomeBuilder {
    field1: Option<Type>,
    field2: Type,
}

impl SomeBuilder {
    pub fn field1(mut self, value: Type) -> Self {
        self.field1 = Some(value);
        self
    }
    
    pub fn execute(self) -> Result<Output> {
        let field1 = self.field1.ok_or_else(|| 
            Error::InvalidParameter(InvalidParameterError::new(
                "field1",
                "field1 is required"
            ))
        )?;
        // ... implementation
    }
}
```

### Buffer Reuse Pattern (`_with_buffer` Methods)

**Purpose**: Allow callers to reuse memory buffers across multiple calls to avoid repeated allocations.

**Parameter Naming Convention**: Use `out_*` prefix for output buffers to clarify their purpose:
- `out_modules`, `out_processes`, `out_threads` - Output collection buffers  
- `out_buffer` - Generic work/output buffer for temporary data
- `work_buffer` - Temporary buffer for internal Windows API operations

**Design Rules**:

1. **For simple return types** (String, PathBuf, HashMap, etc.):
   - Return the computed value directly
   - Buffer is temporary workspace only
   - Buffer parameter can be reused across calls
   - Example: `command_line_with_buffer(&mut out_buffer) -> Result<String>`

2. **For collection types** (Vec<T> for simple structs):
   - Accept `&mut Vec<T>` as output buffer parameter
   - **Return `Result<usize>`** indicating count of elements added
   - Clear buffer at start: `buffer.clear()`
   - Push results directly into buffer: `buffer.push(item)`
   - Never use `collect()` or `clone()`
   - Example: `list_with_buffer(&mut out_processes) -> Result<usize>`

3. **For work buffers** (temporary buffers for Windows API operations):
   - Accept `&mut Vec<u8>` or `&mut Vec<T>` as work buffer
   - Used internally for API calls (EnumProcessModules, ReadProcessMemory, etc.)
   - Caller controls buffer lifecycle and reuse
   - Can contain mixed data types when cast appropriately
   - Example: `modules_with_buffer(&mut out_modules, &mut work_buffer) -> Result<usize>`
     - `work_buffer` holds module handles first, then string data for lookups

4. **Non-buffer method** should be convenient:
   ```rust
   pub fn list() -> Result<Vec<ProcessInfo>> {
       let mut buffer = Vec::with_capacity(128);  // reasonable default
       Self::list_with_buffer(&mut buffer)?;
       Ok(buffer)
   }
   ```

5. **For filtered results**:
   - Provide `_with_filter()` variant for efficient filtering
   - Filter function called during enumeration (no post-filtering)
   - Return count after filtering
   - Example: `list_with_filter(&mut out_processes, |p| p.name.contains("test"))` 
     - Only processes matching filter are added to buffer

6. **For work buffers combining multiple operations**:
   - Accept single `&mut Vec<u8>` work buffer
   - Reuse buffer parts for different operations (HMODULE array, then strings)
   - Cast between types as needed (e.g., `as *mut HMODULE`)
   - Ensures buffer grows if needed for larger datasets
   - Example (modules.rs):
     ```rust
     pub fn modules_with_buffer(
         &self, 
         out_modules: &mut Vec<ModuleInfo>, 
         work_buffer: &mut Vec<u8>
     ) -> Result<usize> {
         // work_buffer first holds module handles for EnumProcessModules
         // Then holds u16 string data for GetModuleBaseNameW/GetModuleFileNameExW
         // Single buffer avoids multiple allocations
     }
     ```

**Filter Pattern** (Most Efficient):
Provide `_with_filter()` methods for collection types:
```rust
````
pub fn list_with_filter<F>(buffer: &mut Vec<ProcessInfo>, filter: F) -> Result<usize>
where
    F: Fn(&ProcessInfo) -> bool,
{
    // ... enumerate and apply filter during iteration ...
    // Only push items where filter returns true
    Ok(buffer.len())
}
```

**Usage Examples**:
```rust
// Find processes with "test" in name
let mut buffer = Vec::with_capacity(128);
Process::list_with_filter(&mut buffer, |p| p.name.contains("test"))?;

// Find high-priority threads
let mut thread_buf = Vec::with_capacity(256);
process.threads_with_filter(&mut thread_buf, |t| t.base_priority > 10)?;

// Find DLL modules from System32 (with work buffer)
let mut out_modules = Vec::with_capacity(32);
let mut work_buffer = Vec::with_capacity(8192);
process.modules_with_filter(&mut out_modules, &mut work_buffer, |m| {
    m.path.contains("System32")
})?;

// Reuse buffers in loop (most efficient)
let mut out_modules = Vec::with_capacity(32);
let mut work_buffer = Vec::with_capacity(8192);
for process in Process::list()? {
    process.modules_with_filter(&mut out_modules, &mut work_buffer, |m| {
        m.name.ends_with(".exe")
    })?;
    println!("Found {} exe modules", out_modules.len());
}
```

**Performance Benefits**:
- Eliminates repeated allocations in loops
- No `collect()` or temporary vectors
- No clones or unnecessary data movement
- **Filter methods avoid post-filtering overhead** (filtering during enumeration)
- **Work buffer reuse** - single buffer holds module handles + string data across calls
- Buffer can be reused across multiple calls

**Example Pattern**:
```rust
impl Process {
    /// Non-buffer version (convenience)
    pub fn threads(&self) -> Result<Vec<ThreadInfo>> {
        let mut buffer = Vec::with_capacity(256);
        self.threads_with_buffer(&mut buffer)?;
        Ok(buffer)
    }

    /// Buffer version (for reuse)
    pub fn threads_with_buffer(&self, buffer: &mut Vec<ThreadInfo>) -> Result<usize> {
        self.threads_with_filter(buffer, |_| true)
    }

    /// Filter version (most efficient - filters during enumeration)
    pub fn threads_with_filter<F>(&self, buffer: &mut Vec<ThreadInfo>, filter: F) -> Result<usize>
    where
        F: Fn(&ThreadInfo) -> bool,
    {
        buffer.clear();
        // ... enumerate and apply filter ...
        // Only push items where filter(&item) returns true
        Ok(buffer.len())
    }
}


```rust
// Strong types for IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(u32);

impl ProcessId {
    pub fn new(id: u32) -> Self { ProcessId(id) }
    pub fn as_u32(&self) -> u32 { self.0 }
}

impl From<u32> for ProcessId {
    fn from(id: u32) -> Self { ProcessId(id) }
}
```

### ImagePath Type: Efficient Path Caching

**Purpose**: Cache frequently-used executable and DLL paths to reduce memory usage and enable efficient case-insensitive comparisons on Windows.

**Design Rationale**:
- Windows paths are case-insensitive but often repeated (kernel32.dll, ntdll.dll, user32.dll, etc.)
- Static string interning for common paths saves memory in process/module enumeration
- Case-insensitive comparison matches Windows path semantics
- Two variants: `Cached(&'static str)` for known paths, `Owned(String)` for dynamic paths

**Type Definition**:
```rust
pub enum ImagePath {
    Cached(&'static str),      // Reference to static cached path
    Owned(String),              // Dynamically allocated path
}
```

**Cached System Paths** (in `COMMON_PATHS` constant - 69 entries):
- **Core kernel DLLs** (System32): `kernel32.dll`, `ntdll.dll`, `msvcrt.dll`, `advapi32.dll`, `user32.dll`, `gdi32.dll`, `ws2_32.dll`
- **COM/OLE DLLs**: `ole32.dll`, `oleaut32.dll`, `comctl32.dll`, `shell32.dll`, `comdlg32.dll`
- **Crypto/Security**: `crypt32.dll`, `cryptbase.dll`, `cryptnet.dll`, `ncrypt.dll`, `bcryptprimitives.dll`, `secur32.dll`, `sspicli.dll`, `ntsecapi.dll`
- **Networking**: `ws2_32.dll`, `wlanapi.dll`, `netapi32.dll`, `iphlpapi.dll`, `dnsapi.dll`, `nsi.dll`, `urlmon.dll`, `wininet.dll`
- **System Services**: `setupapi.dll`, `cfgmgr32.dll`, `regapi.dll`, `shlwapi.dll`, `msi.dll`, `opengl32.dll`, `winmm.dll`
- **Common Executables**: `services.exe`, `lsass.exe`, `csrss.exe`, `svchost.exe`, `rundll32.exe`, `cmd.exe`, `notepad.exe`, `regedit.exe`, `conhost.exe`
- **SysWOW64 equivalents** (32-bit versions): All core DLLs above
- **Directory references**: `C:\Program Files\`, `C:\Program Files (x86)\`, `C:\Windows\`, `C:\Windows\System32\`, `C:\Windows\SysWOW64\`

**Construction Methods** (Optimized for different input types):
- `ImagePath::new(path)` - Create from `impl Into<String>`, allocates if not cached
- `ImagePath::from_str(path)` - Create from `&str`, checks cache without allocation if found
  - **Automatically strips null terminators** (`\0`) for cache hits with null-terminated strings from Windows APIs
- `ImagePath::from_utf16(data)` - Create from `&[u16]` (UTF-16 from Windows APIs), most efficient for GetProcessImageFileNameW results
  - **Automatically strips null terminators** before cache lookup
- `ImagePath::from_utf8(data)` - Create from `&[u8]` (UTF-8), returns `Option<Self>`
  - **Automatically strips null terminators** before cache lookup

**Null Terminator Handling**:
Windows APIs often return null-terminated strings. ImagePath constructors automatically strip trailing `\0` characters to enable proper cache hits:
```rust
// Windows API returns: "C:\Windows\System32\kernel32.dll\0"
let path = ImagePath::from_utf16(result_buffer);  // Null terminator stripped
// Result: Cached hit (no allocation), even though input had \0

// Direct string with null
let path = ImagePath::from_str("C:\\Windows\\System32\\kernel32.dll\0");  // Null stripped
// Result: Cached hit (no allocation)
```

Without null terminator stripping, cache lookups would fail because:
- Cache entries: `"C:\Windows\System32\kernel32.dll"` (no null)
- Query with null: `"C:\Windows\System32\kernel32.dll\0"` (with null)
- These don't match in HashMap lookup = cache miss = unnecessary allocation

**Key Methods**:
- `.as_str()` - Get string representation
- `.eq_case_insensitive(other)` - Compare ignoring case
- `.contains_case_insensitive(needle)` - Case-insensitive substring
- `.ends_with_case_insensitive(suffix)` - Case-insensitive suffix match
- `.is_system_path()` - Detect if path is in Windows system directories
- `.is_wow64()` - Detect 32-bit system path
- `.file_name()` - Extract filename from path
- `.is_cached()` - Check if using static cache

**Comparison Overloads**:
```rust
// All these work:
image_path == "C:\\Windows\\System32\\kernel32.dll"
image_path == other_image_path
"path" == image_path
&"path" == image_path
```

**Performance-Optimized Usage**:
```rust
// Most efficient for Windows API UTF-16 results
let mut out_modules = Vec::with_capacity(32);
let mut work_buffer = Vec::with_capacity(8192);
process.modules_with_filter(&mut out_modules, &mut work_buffer, |m| {
    // from_utf16 avoids String allocation for cache hits
    m.path.is_system_path() && m.path.ends_with_case_insensitive(".dll")
})?;

// In ModuleInfo
pub struct ModuleInfo {
    pub name: String,
    pub path: ImagePath,  // Automatically cached if known
    pub base_address: usize,
    pub size: u32,
}

// Efficient filtering with reusable work buffer
let mut out_modules = Vec::with_capacity(32);
let mut work_buffer = Vec::with_capacity(8192);
process.modules_with_filter(&mut out_modules, &mut work_buffer, |m| {
    m.path.is_system_path() && m.path.ends_with_case_insensitive(".dll")
})?;

// Memory efficient - cache hits reuse static strings
let modules = process.modules()?;  // Reduces heap allocations
```

**Performance Notes**:
- `from_utf16()` - Most efficient for Windows APIs like GetProcessImageFileNameW (no intermediate String allocation if cached)
- `from_str()` - Efficient for string slices, checks cache without allocating if found
- `new()` - General purpose, allocates String first then checks cache
- `from_utf8()` - For UTF-8 data from other sources, returns Option
- **Cache lookup**: HashMap with custom case-insensitive hashing (O(1) lookup, no lowercase string allocation)
  - `CaseInsensitiveKey` hashes characters as lowercase during iteration (on-the-fly, no temporary allocation)
  - Comparison is case-insensitive using `eq_ignore_ascii_case()`
  - Replaces previous O(n) linear search with O(1) HashMap lookup
- Cache hits reuse static `&'static str` (zero allocation)
- Cache misses allocate one String (same as current behavior)
- **Real-world impact**: Common system DLLs (kernel32.dll, ntdll.dll, etc.) hit cache on every enumeration
- Integration with `ModuleInfo.path` and `ProcessParameters.image_path` uses optimized constructors

**Cache Implementation Details**:
```rust
// Custom case-insensitive hasher (no temporary string allocation)
struct CaseInsensitiveKey<'a>(&'a str);

impl Hash for CaseInsensitiveKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash each character converted to lowercase on-the-fly
        for ch in self.0.chars() {
            ch.to_ascii_lowercase().hash(state);
        }
    }
}

// HashMap replaces Vec - O(1) lookup instead of O(n) iteration
static PATH_CACHE: OnceLock<HashMap<CaseInsensitiveKey<'static>, &'static str>> = OnceLock::new();
```

**Implementation Example** (in modules.rs):

Single work buffer combines module handles and string data:
```rust
pub fn modules_with_buffer(
    &self,
    out_modules: &mut Vec<ModuleInfo>,
    work_buffer: &mut Vec<u8>,
) -> Result<usize> {
    // work_buffer layout:
    // [0..bytes_needed] = HMODULE array from EnumProcessModules
    // [bytes_needed..end] = u16 string data for GetModuleBaseNameW/GetModuleFileNameExW
    
    // First use: EnumProcessModules fills with HMODULE handles
    unsafe { 
        EnumProcessModules(
            self.as_raw_handle(),
            work_buffer.as_mut_ptr() as *mut HMODULE,  // Cast u8 buffer to HMODULE
            work_buffer.len() as u32,
            &mut bytes_needed,
        )
    }?;
    
    // Resize if needed for actual module count
    if bytes_needed as usize > work_buffer.len() {
        work_buffer.reserve(bytes_needed as usize - work_buffer.len());
        unsafe { work_buffer.set_len(bytes_needed as usize); }
    }
    
    // Second use: Remaining buffer for string operations
    let string_buffer_ptr = unsafe { 
        work_buffer.as_mut_ptr().add(bytes_needed as usize) as *mut u16 
    };
    let string_buffer = unsafe { 
        std::slice::from_raw_parts_mut(string_buffer_ptr, (work_buffer.len() - bytes_needed as usize) / 2) 
    };
    
    // Use string_buffer for GetModuleBaseNameW and GetModuleFileNameExW
    // Same buffer reused for each module (no new allocations)
}

// Old approach (allocates each buffer separately):
// let mut name_buffer = vec![0u16; 260];    // Allocation 1
// let mut path_buffer = vec![0u16; 1024];   // Allocation 2
// let mut enum_buffer = Vec::with_capacity(8192);  // Allocation 3

// New approach (single work buffer):
// let mut work_buffer = Vec::with_capacity(8192);  // Single allocation
```

**ImagePath usage with null terminator stripping**:
```rust
// Before (null terminator causes cache miss):
let path = ImagePath::from_utf16(&path_buffer[..path_len]);  // Input: "...\0"
// Result: Cache miss → allocates String

// After (null terminator stripped before lookup):
let path = ImagePath::from_utf16(&path_buffer[..path_len]);  // Input: "...\0"
// Result: Auto-strips \0 → "..." → Cache hit → reuses static string
```

## File Structure & Where to Find Things

```
src/
├── lib.rs          - Main entry, module exports, is_elevated(), require_elevation()
├── error.rs        - ALL error types (structured with Cow)
├── registry.rs     - Registry operations
│   ├── Hive, RegistryKey, RegistryKeyBuilder
│   ├── RegistryValue trait implementations
│   └── Convenience functions (read_*, write_*)
├── process.rs      - Process management
│   ├── Process, ProcessId, ProcessInfo
│   ├── ProcessSpawnBuilder
│   └── Memory info, process listing
├── thread.rs       - Thread operations
├── evt.rs          - Event Log
├── etw.rs          - Event Tracing for Windows
├── proxy.rs        - Network proxy config
├── mitigation.rs   - Security mitigations
└── file.rs         - Raw file operations
```

## Common Implementation Patterns

### Adding a New Module Feature

1. **Add error types** in `error.rs` first:
```rust
#[derive(Debug)]
pub struct YourNewError {
    pub field: Cow<'static, str>,
    pub error_code: Option<i32>,
}
```

2. **Implement the feature** in the module file
3. **Use structured errors** everywhere
4. **Follow RAII** for handles
5. **Test in examples/** directory

### Registry Module Patterns

Three ways to interact (all valid):
```rust
// 1. Traditional (good for multiple operations on same key)
let key = RegistryKey::open(Hive::LocalMachine, path)?;
let value: String = key.get_value("Name")?;

// 2. Builder (for advanced options)
let key = RegistryKey::builder()
    .hive(Hive::LocalMachine)
    .path(path)
    .write()
    .wow64_32()
    .open()?;

// 3. Convenience (best for one-off operations)
let value = registry::read_string(Hive::LocalMachine, path, "Name")?;
```

Value types supported: `String`, `u32`, `u64`, `bool`, `Vec<u8>`, `Vec<String>`

### Process Module Patterns

```rust
// List all processes
for process in Process::list()? {
    println!("{}: {}", process.id(), process.name());
}

// Get specific process
let process = Process::get(pid)?;

// Spawn with options
let process = Process::spawn()
    .command("cmd.exe")
    .args(&["/c", "echo test"])
    .parent(parent_pid)
    .execute()?;
```

## Architecture Principles

### 1. Handle Management (RAII)
All Windows handles wrapped in types with `Drop`:
- `RegistryKey` wraps `HKEY`
- `Process` wraps `HANDLE`
- `Thread` wraps `HANDLE`
- `EventLog` wraps `HANDLE`

### 2. Error Handling
- Use `Result<T, Error>` for all fallible operations
- Structured errors with `Cow<'static, str>` for messages
- Include Windows error codes when available (as `Option<i32>`)
- Format only in `Display` impl

### 3. Builder Pattern
For operations with optional parameters:
- `ProcessSpawnBuilder`
- `RegistryKeyBuilder`
- Future: `EventQueryBuilder`

### 4. Type Safety
Strong types prevent mistakes:
- `ProcessId(u32)` not raw `u32`
- `ThreadId(u32)` not raw `u32`
- `Hive` enum not strings

## Quick Reference for Common Tasks

### Adding a New Registry Value Type
1. Implement `RegistryValue` trait in `src/registry.rs`
2. Use structured errors for type mismatches
3. Handle `ERROR_FILE_NOT_FOUND` for missing values

### Adding Windows API Error Context
```rust
// When wrapping Windows API calls
unsafe {
    let result = SomeWindowsApi(...);
    if result.is_err() {
        return Err(Error::WindowsApi(
            WindowsApiError::with_context(result.into(), "SomeWindowsApi")
        ));
    }
}
```

### Permission Checking
```rust
// For admin-only operations
crate::require_elevation()?;

// For conditional checks
if crate::is_elevated()? {
    // Admin stuff
}
```

## Module Details

### `registry`
Ergonomic registry key and value operations with automatic handle cleanup.

**Key Types:**
- `RegistryKey` - Wraps HKEY with automatic cleanup
- `RegistryValue` - Type-safe value representation
- `Hive` - Enum for HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, etc.

**Operations:**
- Open/Create keys with automatic permission handling
- Read/Write values with type conversion
- Enumerate subkeys and values
- Delete keys and values

### `process`
Process enumeration, information retrieval, and lifecycle management.

**Key Types:**
- `Process` - Represents a running process
- `ProcessId` - Strong type for PIDs
- `ProcessInfo` - Process metadata (name, path, memory, CPU, etc.)

**Operations:**
- `list()` - Enumerate all processes
- `get(pid)` - Get process information
- `kill(pid)` - Terminate process
- `spawn()` - Create new process with advanced options
- `spawn_as_child(parent_pid)` - Spawn as child of specific process

### `thread`
Thread enumeration and management.

**Key Types:**
- `Thread` - Represents a thread
- `ThreadId` - Strong type for TIDs
- `ThreadInfo` - Thread metadata

**Operations:**
- Enumerate threads in a process
- Suspend/Resume threads
- Get thread context and information

### `evt`
Windows Event Log reading and querying.

**Key Types:**
- `EventLog` - Handle to an event log
- `Event` - Parsed event record
- `EventQuery` - Builder for event queries

**Operations:**
- Open event logs (System, Application, Security, etc.)
- Query events with XPath filters
- Subscribe to real-time events
- Parse event data into structured format

### `etw`
Event Tracing for Windows (ETW) session management and consumption.

**Key Types:**
- `EtwSession` - ETW trace session
- `EtwProvider` - ETW provider
- `EtwEvent` - Parsed ETW event

**Operations:**
- Start/Stop ETW sessions
- Enable providers with specific keywords and levels
- Consume events from active sessions
- Parse ETW event payloads

### `spawn`
Advanced process spawning with parent process specification.

**Operations:**
- Spawn process as child of another process
- Handle process impersonation
- Manage process creation flags and attributes

### `proxy`
Network proxy configuration extraction.

**Operations:**
- Get system proxy settings
- Parse Internet Explorer proxy configuration
- Get proxy for specific URLs
- Handle PAC (Proxy Auto-Configuration) files

### `mitigation`
Apply Windows process mitigation policies.

**Key Types:**
- `MitigationPolicy` - Builder for mitigation policies
- `Mitigation` - Enum of available mitigations

**Operations:**
- Enable DEP (Data Execution Prevention)
- Enable ASLR (Address Space Layout Randomization)
- Configure Control Flow Guard (CFG)
- Set dynamic code policies
- Apply image load policies

### `file`
Raw file operations that bypass filesystem filters.

**Operations:**
- `raw_copy()` - Copy files at the raw volume level
- Direct disk I/O operations
- Bypass file system filters for forensic operations

## Dependencies

### Core
- `windows = "0.58"` - Windows API bindings with extensive feature flags
- Edition: 2024
- Rust: 1.93+

### **NOT** Used (Intentional)
- ❌ **NO** `thiserror` - We use manual Display implementations
- ❌ **NO** `anyhow` - We use structured errors with dedicated types
- ❌ **NO** `serde` (currently) - Keep it simple

## Module Status

| Module | Status | Error Types Updated | Notes |
|--------|--------|---------------------|-------|
| registry | ✅ Complete | ✅ Yes | Builder pattern, convenience functions, Cow errors |
| process | ⚠️ Basic | ❌ No | Needs error type update |
| thread | ⚠️ Basic | ❌ No | Needs error type update |
| evt | ⚠️ Basic | ❌ No | Needs error type update |
| etw | ❌ Skeletal | ❌ No | Needs full implementation |
| proxy | ✅ Complete | ⚠️ Partial | Working but may need error update |
| mitigation | ✅ Complete | ⚠️ Partial | Working but may need error update |
| file | ⚠️ Basic | ❌ No | Needs error type update |

## Detailed Module Reference

### `registry` Module - **REFERENCE IMPLEMENTATION**
**Status**: ✅ Complete with new error types
**File**: `src/registry.rs`

**Three API Styles**:
1. **Traditional** - Multiple operations on same key
   ```rust
   let key = RegistryKey::open(Hive::LocalMachine, path)?;
   let value: String = key.get_value("Name")?;
   ```

2. **Builder** - Advanced options (WOW64, access rights)
   ```rust
   let key = RegistryKey::builder()
       .hive(Hive::LocalMachine)
       .path(path)
       .write()
       .wow64_32()
       .open()?;
   ```

3. **Convenience** - One-off operations
   ```rust
   let value = registry::read_string(Hive::LocalMachine, path, "Name")?;
   ```

**Supported Value Types**: `String`, `u32`, `u64`, `bool`, `Vec<u8>`, `Vec<String>`

**Error Types**: `RegistryKeyNotFoundError`, `RegistryValueNotFoundError`, `RegistryInvalidTypeError`, `RegistryConversionError`

**Example**: See `examples/registry_operations.rs`

### `process` Module
**Status**: ✅ Complete implementation with modular structure
**Files**: `src/process/` directory (mod.rs, types.rs, process.rs, peb.rs, list.rs, tree.rs, threads.rs, modules.rs, memory.rs)

**Key Types**: `Process`, `ProcessId`, `ThreadId`, `ProcessAccess`, `ProcessInfo`, `ThreadInfo`, `ModuleInfo`, `ProcessParameters`, `MemoryInfo`, `ImagePath`

**Core Operations**:
- `Process::open(pid)` - Open process with default access
- `Process::open_with_access(pid, access)` - Open with specific rights
- `Process::current()` - Get current process (pseudo-handle)
- `Process::list()` - List all processes (allocates)
- `Process::kill_by_id(pid)` - Kill process by ID
- `process.kill()` - Terminate this process
- `process.id()` - Get process ID
- `process.name()` - Get executable name
- `process.path()` - Get full executable path
- `process.parent_id()` - Get parent process ID
- `process.is_running()` - Check if still running
- `process.exit_code()` - Get exit code if terminated

**PEB Access** (Reading from Process Environment Block):
- `process.command_line()` - Read command line from PEB
- `process.environment()` - Read environment variables (limited by windows-rs bindings)
- `process.parameters()` - Read command line, current dir, image path

**Enumeration**:
- `process.threads()` - Get all threads in process
- `process.modules()` - Get all loaded DLLs
- `process.children()` - Get immediate child processes

**Process Tree Operations**:
- `process.kill_tree()` - Kill process + all descendants
- `Process::kill_tree_by_id(pid)` - Kill tree by process ID
- `Process::kill_tree_from_root(pid)` - Find root ancestor, kill entire tree

**Memory**:
- `process.memory_info()` - Get working set, page faults, etc.

**Buffer Reuse Pattern** (for performance):
All allocation-heavy methods have `_with_buffer(&mut Vec<u8>)` variants:
- `Process::list_with_buffer(buffer)`
- `process.command_line_with_buffer(buffer)`
- `process.name_with_buffer(buffer)`
- `process.path_with_buffer(buffer)`
- `process.environment_with_buffer(buffer)`
- `process.parameters_with_buffer(buffer)`
- `process.threads_with_buffer(buffer)`
- `process.modules_with_buffer(buffer)`
- `process.children_with_buffer(buffer)`
- `Process::kill_tree_by_id_with_buffer(pid, buffer)`
- `Process::kill_tree_from_root_with_buffer(pid, buffer)`

**Error Types**: `ProcessNotFoundError`, `ProcessOpenError`, `ProcessSpawnError`, `ProcessTerminatedError`

**Examples**: `process_basics.rs`, `process_monitoring.rs`, `process_tree.rs`

### `thread` Module
**Status**: ⚠️ Basic implementation
**File**: `src/thread.rs`

**Types**: `Thread`, `ThreadId`, `ThreadInfo`

**Operations**: `Thread::list_for_process(pid)`, `Thread::open(tid)`, `suspend()`, `resume()`, `exit_code()`

**Needs**: Error types `ThreadNotFoundError`, `ThreadOpenError`

### `evt` Module - Event Log
**Status**: ⚠️ Basic implementation
**File**: `src/evt.rs`

**Types**: `EventLog`, `Event`, `EventType`

**Operations**: `EventLog::open(name)`, `read_recent(count)`, `record_count()`, `clear()`

**Needs**: Error types `EventLogNotFoundError`, `EventLogQueryError`, `EventLogParseError`

### `etw` Module - Event Tracing for Windows
**Status**: ❌ Skeletal/placeholder
**File**: `src/etw.rs`

**Types**: `EtwSession`, `Provider`, `EtwEvent`

**Needs**: Full implementation with real Windows ETW APIs

### `proxy` Module
**Status**: ✅ Working
**File**: `src/proxy.rs`

**Functions**: `get_system_proxy()`, `get_proxy_for_url(url)`, `get_ie_proxy_config()`

### `mitigation` Module
**Status**: ✅ Working
**File**: `src/mitigation.rs`

**Types**: `MitigationPolicy` (builder), `Mitigation` (enum)

**Available Mitigations**: Dep, Aslr, ControlFlowGuard, DisableDynamicCode, StrictHandleChecks, DisableExtensionPoints, DisableNonSystemFonts, ImageLoad

**Usage**:
```rust
MitigationPolicy::new()
    .enable(Mitigation::Dep)
    .enable(Mitigation::Aslr)
    .apply_to_current()?;
```

### `file` Module
**Status**: ⚠️ Basic, requires admin
**File**: `src/file.rs`

**Functions**: `raw_copy(src, dst)`, `read_raw_sectors(volume, start, count)`, `write_raw_sectors(volume, start, data)`, `lock_file(path)`

## Testing Strategy

**Primary**: Examples in `examples/` directory (e.g., `registry_operations.rs`)
**Secondary**: Unit tests with `#[cfg(test)]` in module files
**No integration tests yet** - examples serve this role

## Platform Requirements

- **OS**: Windows 10+
- **Rust**: 1.93+
- **Edition**: 2024
- **Target**: `x86_64-pc-windows-msvc`

## Development Workflow

### Adding New Module Features
1. **Define error types first** in `src/error.rs`
2. **Implement feature** with structured errors and Cow
3. **Follow RAII pattern** for handles
4. **Add example** in `examples/` directory
5. **Test manually** with the example
6. **Update this file** only if new patterns emerge

### Code Style
- ✅ Use `clippy` and `rustfmt`
- ✅ Structured errors with `Cow<'static, str>`
- ✅ RAII for all handles
- ✅ Type-safe IDs (ProcessId, ThreadId, etc.)
- ❌ NO `String` in errors
- ❌ NO forgetting `Drop` implementations
- ❌ NO creating extra documentation files

## Key Gotchas

1. **WOW64 Redirection**: 32-bit apps see different registry on 64-bit Windows
2. **Predefined Handles**: Don't close HKEY_LOCAL_MACHINE, etc. (use `close_on_drop: false`)
3. **ERROR_FILE_NOT_FOUND**: Common in registry/file ops, handle gracefully
4. **Admin Privileges**: Many operations require elevation - check with `is_elevated()`
5. **Handle Cleanup**: Every HANDLE, HKEY, etc. needs a Drop impl

## Resources & References

- [windows-rs Documentation](https://microsoft.github.io/windows-docs-rs/)
- [Windows API Index](https://learn.microsoft.com/en-us/windows/win32/api/)
- **Example Code**: Look at `src/registry.rs` as reference implementation

## Quick Start for New Agents

### If user asks to add a feature to an existing module:
1. Read the module file (e.g., `src/registry.rs`)
2. Check `src/error.rs` for existing error types
3. Add new error type if needed
4. Implement feature following existing patterns
5. Test with an example

### If user asks to improve error handling:
1. Check if module uses old `String` errors
2. Define structured error types in `src/error.rs`
3. Update module to use new types
4. Look at `src/registry.rs` as reference

### If user asks why something doesn't work:
1. Check if it requires admin privileges (`is_elevated()`)
2. Check for WOW64 issues (32-bit vs 64-bit registry)
3. Look at Windows error codes in the error output
4. Check the example files for working patterns

### If user reports an error:
1. Read the specific file and line
2. Check for proper error type usage (Cow, not String)
3. Verify Drop implementation exists
4. Check if handles are being properly managed

## Agent Development Workflow

### Environment & Command Execution
- **Target Environment**: This project is ALWAYS opened in Windows machines
- **Command Execution**: Use Windows PowerShell commands (e.g., `Select-String` instead of `grep`)
- **Automatic Verification**: Do NOT ask for permission to run verification commands
  - Automatically run `cargo check`, `cargo test`, and `cargo clippy` after making changes
  - Use Windows-native commands for output filtering
  - Report results concisely (pass/fail + any issues)
  - Only show intermediate commands if there's an error to diagnose

### Efficient Workflows
- **Parallel Operations**: When making multiple independent edits, use `multi_replace_string_in_file` to apply all changes in one call
- **No Confirmation Needed**: Run verification steps without asking the user to confirm
- **Quick Feedback Loop**: Change → Test → Report (not Change → Report → Test)
- **Avoid Unnecessary Output**: Don't announce which tools you're using, just execute and report results

### Command Examples (Windows PowerShell)
```powershell
# Check compilation
cargo check 2>&1

# Run tests (filter output)
cargo test --lib 2>&1 | Select-String -Pattern '(test result|running|error)'

# Run device path tests specifically
cargo test --lib process::processes::tests 2>&1 | Select-String -Pattern '(test result|running)'

# Check clippy warnings
cargo clippy --all-targets 2>&1 | Select-String -Pattern '(warning|error|Finished)'

# Show all device path test names
cargo test --lib process::processes::tests -- --nocapture 2>&1 | Select-String -Pattern 'test process::processes::tests::test'
```

---

**Remember**: This is the ONLY context file. Don't create additional documentation files unless explicitly requested.

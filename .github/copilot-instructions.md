# GitHub Copilot Instructions for windows-erg

**windows-erg** is an ergonomic, idiomatic Rust wrapper library around Windows APIs built on `windows-rs`. Before any code changes, **read [CONTEXT.md](./CONTEXT.md) for critical coding standards** - it contains definitive patterns for this project.

## Project Overview
- **Purpose**: Safe, ergonomic abstractions over Windows system APIs (process management, registry, threads, event logs, ETW)
- **Core Philosophy**: Ergonomic + Safe (RAII) + Simple + Structured errors
- **Target**: Windows system programming with zero manual handle cleanup
- **Key Idiom**: Builder patterns, iterators, type-safe operations via newtype wrappers

## Critical Patterns (Non-Negotiable)

### 1. Error Handling - NEVER Use `String`
**Always use `Cow<'static, str>` for error messages and structured error types:**

```rust
// ❌ WRONG
Error::InvalidParameter("invalid value".to_string())

// ✅ CORRECT
Error::InvalidParameter(InvalidParameterError::new(
    "parameter_name",
    "why it's invalid"
))

// For static strings (preferred when possible)
Cow::Borrowed("static message")

// For dynamic strings (when necessary)
Cow::Owned(format!("dynamic value: {}", val))
```

**Check [src/error.rs](../src/error.rs) for all error types before implementing new errors.**

### 2. RAII Handle Management
All Windows handles must auto-cleanup on drop:

```rust
pub struct MyHandle {
    handle: HANDLE,
    close_on_drop: bool,  // For predefined handles (e.g., INVALID_HANDLE_VALUE)
}

impl Drop for MyHandle {
    fn drop(&mut self) {
        if self.close_on_drop {
            unsafe { CloseHandle(self.handle); }
        }
    }
}
```

### 3. Type Safety - Newtype Wrappers
Use newtype wrappers for IDs instead of raw primitives:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(u32);

impl ProcessId {
    pub fn new(id: u32) -> Self { ProcessId(id) }
    pub fn as_u32(&self) -> u32 { self.0 }
}
```

### 4. Buffer Reuse Pattern (`_with_buffer` methods)
Provide three variants for collection operations to balance convenience and efficiency:

```rust
impl Process {
    // Convenience (allocates buffer internally)
    pub fn threads(&self) -> Result<Vec<ThreadInfo>> {
        let mut buffer = Vec::with_capacity(256);
        self.threads_with_buffer(&mut buffer)?;
        Ok(buffer)
    }

    // For reusable buffers
    pub fn threads_with_buffer(&self, buffer: &mut Vec<ThreadInfo>) -> Result<usize> {
        self.threads_with_filter(buffer, |_| true)
    }

    // Most efficient - filters during enumeration (not post-filtering)
    pub fn threads_with_filter<F>(&self, buffer: &mut Vec<ThreadInfo>, filter: F) -> Result<usize>
    where
        F: Fn(&ThreadInfo) -> bool,
    {
        buffer.clear();
        // ... enumerate and filter during iteration, push only matching items ...
        Ok(buffer.len())  // Return count
    }
}
```

**Buffer naming convention:**
- `out_*` prefix for output buffers (out_processes, out_modules, out_buffer)
- `work_buffer` for temporary workspace buffers for Windows API operations

**Key rules:**
- Collection methods clear buffer at start
- Return `Result<usize>` (count of items added) not `Result<Vec<T>>`
- Filter methods avoid post-filtering (filter during enumeration)
- Single `work_buffer` can combine multiple operations (e.g., HMODULE array + string data)

### 5. Builder Pattern
Use builders for complex operations:

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
            Error::InvalidParameter(InvalidParameterError::new("field1", "required"))
        )?;
        // ... implementation ...
    }
}
```

**Reference**: [src/registry/builder.rs](../src/registry/builder.rs)

## Before Writing Code

1. **Check error types** in [src/error.rs](../src/error.rs) - reuse existing types
2. **Look at [src/registry/mod.rs](../src/registry/mod.rs)** - complete reference implementation
3. **Check [src/process/processes.rs](../src/process/processes.rs)** - patterns for enumeration and handle management
4. **Verify RAII patterns** - all handles must have Drop implementations with cleanup
5. **Consider buffer patterns** - if returning collections, provide `_with_buffer` and `_with_filter` variants

## Performance Patterns

### ImagePath - Efficient Path Caching
The `ImagePath` type caches common Windows paths (kernel32.dll, ntdll.dll, etc.) to reduce allocations:
- `ImagePath::Cached(&'static str)` for known paths
- `ImagePath::Owned(String)` for dynamic paths
- Methods: `.as_str()`, `.eq_case_insensitive()`, `.contains_case_insensitive()`, `.is_system_path()`, `.ends_with_case_insensitive()`

**Automatically strips null terminators** from Windows API results during construction for proper cache hits.

### Device Path Cache
Process module uses `OnceLock<HashMap>` to cache device path to drive letter mappings (e.g., `\Device\HarddiskVolume1` → `C:`). Computed once, used throughout process lifetime.

## Common Implementation Examples

### Registry - Three Interaction Patterns
```rust
// 1. Traditional (multiple operations on same key)
let key = RegistryKey::open(Hive::LocalMachine, r"SOFTWARE\MyApp")?;
let value: String = key.get_value("Name")?;

// 2. Builder (advanced options: write access, WOW64)
let key = RegistryKey::builder()
    .hive(Hive::LocalMachine)
    .path(r"SOFTWARE\MyApp")
    .write()
    .wow64_32()
    .open()?;

// 3. Convenience (one-off operations)
let value = registry::read_string(Hive::LocalMachine, r"SOFTWARE\MyApp", "Name")?;
```

### Process Operations
```rust
// List all processes (convenient)
for proc in Process::list()? { ... }

// List with buffer reuse (efficient loop)
let mut buffer = Vec::with_capacity(256);
for frame in frames {
    Process::list_with_buffer(&mut buffer)?;
    // ... process buffer.len() items ...
}

// List with filtering (most efficient - filters during enumeration)
let mut buffer = Vec::with_capacity(256);
Process::list_with_filter(&mut buffer, |p| p.name.contains("test"))?;
```

## Module Status

- ✅ `registry` - Complete reference implementation with all patterns
- ✅ `process` - Full implementation with buffer patterns and ImagePath caching
- ⚠️ `thread` - Needs buffer pattern variants
- ⚠️ `evt` - Windows Event Log operations
- ❌ `etw` - Event Tracing for Windows (needs full implementation)

## No Extra Documentation
Do **NOT** create additional markdown files to explain changes unless explicitly requested. CONTEXT.md is the source of truth.

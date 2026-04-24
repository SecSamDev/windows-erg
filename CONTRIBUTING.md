# Contributing to windows-erg

Thank you for contributing! This guide covers code standards, the CI/CD pipeline all changes must pass, and the submission workflow.

## Before You Start

1. **Read [CONTEXT.md](CONTEXT.md)** — Contains critical coding standards, error handling patterns, buffer management conventions, and RAII handle rules. This is non-negotiable.
2. **Check existing patterns** — Review [src/registry/mod.rs](src/registry/mod.rs) and [src/process/processes.rs](src/process/processes.rs) as complete reference implementations before building new features.
3. **Understand module structure** — Each module follows a consistent pattern: public API in `mod.rs`, internal utilities in submodules, tests alongside implementations.

## CI/CD Pipeline — All Checks Must Pass

**Before you push, run these locally to expedite CI:**

```powershell
cargo fmt --all -- --check           # Code formatting
cargo check --all-targets            # Compile check (default features)
cargo check --all-targets --features full  # Compile check (all features)
cargo clippy --all-targets -- -D warnings  # Lint (default features)
cargo clippy --all-targets --features full -- -D warnings  # Lint (all features)
cargo test --lib                     # Unit tests (default features)
cargo test --lib --features full     # Unit tests (all features)
cargo test --tests                   # Integration tests
```

### Stage 1: Build & Lint (GATES ALL OTHERS)

This stage validates code quality and must pass before any other checks run.

- **cargo fmt --check**: Code must follow [rustfmt.toml](rustfmt.toml) formatting rules.
- **cargo check (default features)**: All targets compile with default feature set.
- **cargo check --all-targets --features full**: All targets compile with all features.
- **cargo clippy (default + all features, -D warnings)**: No clippy warnings allowed (warnings = errors).

**If this stage fails, the entire pipeline stops.**

### Stage 2: ARM64 Cross-Compile (depends on Stage 1)

Validates compilation for `aarch64-pc-windows-msvc` without runtime execution (compile-only).

- **cargo check --target aarch64-pc-windows-msvc** (default + all features)
- **cargo build --examples --target aarch64-pc-windows-msvc** (default + all features)

Note: Runtime validation requires native ARM64 hardware. CI validates **compile-only** correctness.

### Stage 3: Unit & Integration Tests (depends on Stage 1)

- **cargo test --lib** (default + all features): All unit tests.
- **cargo test --tests**: Integration tests, excluding:
  - `etw_integration.rs` (admin-required, #[ignore])
  - `raw_file_integration.rs` (admin-required, #[ignore])
  - Timing-dependent `wait_any_*` assertions (non-deterministic CI scheduling)

Includes: `pipes_integration.rs`, `service_integration.rs`, `security_permissions_integration.rs`.

**If this stage fails, examples stages do not run.**

### Stage 4: Example Compilation (depends on Stage 1)

Validates all 35 examples compile without errors (no execution).

- **cargo build --examples** (default + all features)

### Stage 5: Examples Phase 1 — Safe Auto-Run (depends on Stage 3)

18 non-admin, side-effect-free, self-terminating examples with 1-minute timeout each. Built once in release mode.

- system_snapshot
- process_basics, process_metrics, process_mitigation, process_monitoring
- desktop_windows, wait_multi_object, security_permissions
- registry_basics, registry_convenience, registry_enumerate, registry_operations, registry_safe_access, registry_write
- proxy_system, proxy_for_url
- service_enumerate
- pipes_list

All must exit cleanly (no panics, no timeouts).

### Stage 6: Examples Phase 2 — Event Log (best-effort, depends on Stage 5)

Event log examples with machine-state variability. Failures surface as CI warnings but **do not block merge** (continue-on-error: true).

- evt_custom_parsing
- evt_filter
- evt_streaming
- evt_serde --features serde

Empty logs are acceptable; 0 events is a valid result on restricted runners.

### Stage 7: MSRV Check (depends on Stage 1)

Validates Minimum Supported Rust Version (currently **Rust 1.90**) from [Cargo.toml](Cargo.toml).

- **cargo check --all-targets** on Rust 1.90

## What Blocks Publication

**ANY** of these failures prevents merge to main:

- ❌ Code formatting
- ❌ Compilation
- ❌ Clippy lints
- ❌ ARM64 compilation
- ❌ Unit tests
- ❌ Integration tests
- ❌ Example compilation
- ❌ Phase 1 examples (safe auto-run)
- ❌ MSRV check

Phase 2 examples allow best-effort failures and **do not block** merge.

## Making Changes

Keep changes minimal and focused. One feature or fix per PR.

Match existing module patterns:

- Use `Cow<'static, str>` for error messages — never plain `String`
- Implement RAII with `Drop` for all Windows handles
- Provide `_with_buffer` and `_with_filter` variants for collection APIs
- Use structured error types from [src/error.rs](src/error.rs), not ad-hoc errors

## Validation Before Submitting

```powershell
cargo check
cargo test --lib
# Run Phase 1 sanity pass
cargo run --example process_basics
cargo run --example registry_write
```

## Code Review Checklist

- Follows patterns in [CONTEXT.md](CONTEXT.md)?
- All Windows handles are RAII-protected?
- Error messages use `Cow<'static, str>`, not `String`?
- Collection APIs provide `_with_buffer` and `_with_filter` variants?
- Phase 1 examples still pass?
- All local pre-push checks pass?

## Post-Merge Release Publication

After code is merged to main, the crate maintainer must manually:

1. Update version in [Cargo.toml](Cargo.toml) (semver discipline).
2. Update [CHANGELOG.md](CHANGELOG.md) with the release date, version, and notable changes.
3. Run `cargo publish --dry-run` locally to validate publishing metadata.
4. Run `cargo publish` to push to crates.io.
5. Create a git tag for the release version.

No automatic publication occurs. All CI stages must pass before merge; publication is a manual gate.

## Questions or Design Discussions?

Open an issue before submitting code.

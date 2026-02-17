# Roadmap

## Supervised Execution Mode

Intercept syscalls before execution for AI CLI tools and interactive approval.

**How it works:**
- Uses `SECCOMP_RET_USER_NOTIF` to pause syscalls
- Parent process receives notification with syscall details
- User/AI decides: Allow, Deny, or Kill
- Policy system for automatic decisions

**Use case:** AI coding assistants that need user approval before file deletion or network access.

```rust
executor.spawn(plan.supervised(policy))?;

// In event loop:
Event::Syscall { context: SyscallContext::Delete { path }, .. } => {
    println!("Code wants to delete: {}", path);
    executor.respond(id, Decision::Deny)?;
}
```

---

## macOS Support

Run Linux sandboxes on macOS via lightweight VM.

**How it works:**
- Uses Apple's Hypervisor.framework
- Boots minimal Linux kernel (~5MB) + initramfs (~10MB)
- Runs evalbox-daemon inside VM
- Communication via vsock

**Experience:**
- First call: ~1-2s (VM boot)
- Subsequent calls: ~10ms (VM reused)
- API identical to Linux

```rust
// Same code works on both platforms
let output = evalbox::python::run("print('hello')", &config)?;
```

---

## Node.js Runtime

Execute JavaScript/TypeScript with auto-detection.

- ESM and CommonJS auto-detection
- Dependency caching
- TypeScript via ts-node/esbuild

```rust
let output = node::run("console.log('hello')", &config)?;
```

---

## Rust Runtime

Execute Rust code with inline dependencies.

- Auto-wrap expressions in `fn main()`
- Inline `Cargo.toml` via doc comments
- Compilation caching by code hash

```rust
let output = rust::run(r#"
//! [dependencies]
//! serde = "1"
println!("hello");
"#, &config)?;
```

---

## Fuzzing Infrastructure

Continuous fuzzing with cargo-fuzz to find edge cases and vulnerabilities.

**Fuzz targets:**
- `fuzz_seccomp_filter` - BPF filter generation with arbitrary syscall lists
- `fuzz_seccomp_whitelist` - Edge cases (empty, duplicates, max size)
- `fuzz_plan` - Plan configuration with arbitrary inputs
- `fuzz_validate` - Command/path validation and traversal prevention

**How it works:**
- Uses libFuzzer via cargo-fuzz
- Arbitrary crate for structured fuzzing
- CI integration with OSS-Fuzz

```rust
// Example fuzz target
fuzz_target!(|input: FuzzInput| {
    let filter = build_whitelist_filter(&input.syscalls);
    assert!(!filter.is_empty());
});
```

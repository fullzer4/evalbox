# Contributing

## Development Setup

evalbox uses Nix for a reproducible dev environment:

```bash
nix develop
```

This provides the Rust toolchain, GCC (for test payloads), Python, and Go.

## Building

```bash
cargo build
```

## Testing

### Fast checks (CI)

```bash
# Runs via nix: clippy, fmt, unit tests, docs
nix flake check
```

Or manually:

```bash
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test --lib
cargo doc --no-deps
```

### Full test suite (requires user namespaces)

```bash
nix run .#test-all
```

Or manually:

```bash
cargo build -p evalbox-sandbox
cargo test -p evalbox-sandbox --test security_tests --ignored -- --test-threads=1
```

The security tests require Linux with user namespaces enabled. They compile C payloads that attempt real exploit techniques (CVEs, syscall abuse, escape vectors) and verify the sandbox blocks them.

### Running specific test categories

```bash
cargo test -p evalbox-sandbox --test security_tests seccomp -- --ignored
cargo test -p evalbox-sandbox --test security_tests filesystem -- --ignored
cargo test -p evalbox-sandbox --test security_tests network -- --ignored
cargo test -p evalbox-sandbox --test security_tests cve -- --ignored
cargo test -p evalbox-sandbox --test security_tests resources -- --ignored
```

## Project Structure

```
evalbox/                  # Public API, language runtimes
evalbox-sandbox/          # Sandbox orchestration, isolation
evalbox-sys/              # Low-level Linux syscall wrappers
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Pull Requests

- Run `nix flake check` before submitting
- Security-related changes should include tests in `crates/evalbox-sandbox/tests/security/`
- Keep the seccomp whitelist minimal: don't add syscalls without justification

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for reporting instructions.

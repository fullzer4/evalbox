# evalbox

Execute code like `eval()`, but safe. No containers, no VMs, no root.

[![CI](https://github.com/fullzer4/evalbox/actions/workflows/ci.yml/badge.svg)](https://github.com/fullzer4/evalbox/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/evalbox.svg)](https://crates.io/crates/evalbox)
[![Documentation](https://docs.rs/evalbox/badge.svg)](https://docs.rs/evalbox)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

## Features

- **Simple** - One function call, security handled for you
- **Multi-language** - Python, Go, and shell/terminal commands
- **Fast** - Millisecond startup, no containers or VMs
- **Secure** - 7 layers of isolation (namespaces, Landlock, seccomp, rlimits)

## Quick Start

```rust
use evalbox::{shell, python, go};
use std::time::Duration;

// Terminal commands
let output = shell::run("echo hello").exec()?;

// Python
let output = python::run("print(2 + 2)").exec()?;

// Go (auto-wraps into main())
let output = go::run(r#"fmt.Println("hello")"#).exec()?;

// With options
let output = shell::run("curl https://example.com")
    .timeout(Duration::from_secs(10))
    .network(true)
    .exec()?;
```

## Requirements

- Linux kernel 5.13+ (Landlock ABI 1+)
- User namespaces enabled

## Installation

```toml
[dependencies]
evalbox = { version = "0.1", features = ["python", "go", "shell"] }
```

## Security

7 layers of isolation: user namespaces, PID namespace, network namespace, mount namespace + pivot_root, Landlock LSM, seccomp BPF, rlimits.

See [SECURITY.md](docs/SECURITY.md) for threat model and CVE protections.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## License

MIT OR Apache-2.0

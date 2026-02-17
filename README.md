# evalbox

Execute code like `eval()`, but safe. No containers, no VMs, no root.

[![CI](https://github.com/fullzer4/evalbox/actions/workflows/ci.yml/badge.svg)](https://github.com/fullzer4/evalbox/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/evalbox.svg)](https://crates.io/crates/evalbox)
[![Documentation](https://docs.rs/evalbox/badge.svg)](https://docs.rs/evalbox)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://www.rust-lang.org)

## Features

- **Simple** - One function call, security handled for you
- **Multi-language** - Python, Go, Shell (Node and Rust planned)
- **Fast** - Millisecond startup, no containers or VMs
- **Embeddable** - Library with FFI bindings

## Quick Start

```rust
use evalbox::Sandbox;
use std::time::Duration;

// Simple command
let output = Sandbox::run(&["echo", "hello"])?;
assert_eq!(output.stdout, b"hello\n");

// Shell script
let output = Sandbox::shell("echo hello && pwd")?;

// With files and options
let output = Sandbox::builder()
    .cmd(["python3", "main.py"])
    .file("main.py", b"print('hello')")
    .timeout(Duration::from_secs(10))
    .memory(256 * 1024 * 1024)
    .run()?;
```

### Language Runtimes (feature-gated)

```rust
// Python (feature = "python")
use evalbox::python;
let output = python::run("print(2 + 2)")?;

// Go with auto-wrap (feature = "go")
use evalbox::go;
let output = go::run(r#"fmt.Println("hello")"#)?;
```

## Concurrent Execution

```rust
use evalbox::{Sandbox, Executor, Event};
use std::time::Duration;

let mut executor = Executor::new()?;

// Spawn multiple sandboxes
let plan1 = Sandbox::builder().cmd(["sleep", "1"]).build()?;
let plan2 = Sandbox::builder().cmd(["echo", "fast"]).build()?;

executor.spawn(plan1)?;
executor.spawn(plan2)?;

// Event-driven processing
loop {
    for event in executor.poll(Some(Duration::from_secs(1)))? {
        match event {
            Event::Completed { id, output } => {
                println!("{}: {}", id, output.stdout_str());
            }
            Event::Stdout { id, data } => {
                print!("[{}] {}", id, String::from_utf8_lossy(&data));
            }
            _ => {}
        }
    }
    if executor.active_count() == 0 {
        break;
    }
}
```

## Requirements

- Linux kernel 5.13+ (Landlock ABI 1+)
- User namespaces enabled

## Non-Goals

- Windows support
- GUI/GPU sandboxing
- Persistent containers (use Docker)

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## License

MIT OR Apache-2.0

# leeward

> Linux-native sandbox for running untrusted code. No containers. No VMs. Fast.

⚠️ **Work in progress** — Core isolation primitives are being implemented.

## Why

AI agents need to execute code. Current options suck:

| Solution | Problem |
|----------|---------|
| Docker | 300-500ms startup, heavy |
| E2B/Modal | Cloud-only, expensive |
| WASM | No native libs, limited |
| Firecracker | Overkill for most cases |

leeward gives you **~3ms** execution latency using native Linux primitives.

## How

```
┌──────────────┐     unix socket     ┌─────────────────────┐
│    Client    │ ◄─────────────────► │   leeward daemon    │
│   (any lang) │      msgpack        │                     │
└──────────────┘                     │   ┌─────────────┐   │
                                     │   │ Worker Pool │   │
    Python, Go,                      │   │ [W1][W2][W3]│   │
    Node, Rust                       │   └─────────────┘   │
    via C FFI                        └─────────────────────┘
```

Each worker is isolated with:
- Linux namespaces (user, pid, mount, net, ipc)
- seccomp-bpf syscall filtering
- Landlock filesystem restrictions
- cgroups v2 resource limits

## Usage

```python
from leeward import Leeward

with Leeward() as sandbox:
    result = sandbox.execute("print(sum(range(100)))")
    print(result.stdout)  # "4950"
```

```bash
# Or via CLI
leeward exec "print('hello')"
```

## Requirements

- Linux >= 5.13 (Landlock support)
- User namespaces enabled
- No root required

## Status

Building the core. Not ready for production.
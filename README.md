# isolex

Linux-native sandbox for running untrusted code with ~0.5ms latency.

## Usage

```python
from isolex import isolex

with Isolex() as sandbox:
    result = sandbox.execute("print('Hello, World!')")
    print(result.stdout)  # "Hello, World!"
```

## Features

- **Fast**: ~0.5ms execution latency (vs Docker's 300-500ms)
- **Secure**: Linux namespaces + seccomp + Landlock
- **Simple**: No containers or VMs needed
- **Lightweight**: Pre-forked Python workers

## Requirements

- Linux >= 5.13
- User namespaces enabled
- No root required

## Documentation

- [Installation](INSTALL.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

Apache-2.0

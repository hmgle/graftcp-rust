# graftcp-rust

Rust implementation of [graftcp](https://github.com/hmgle/graftcp) - a flexible tool that redirects TCP connections made by any given program to SOCKS5 or HTTP proxy.

## Status

🚧 **Work in Progress** - This is an early stage Rust port of the original C/Go implementation. Many core features are not yet implemented.

## Architecture

This project consists of four main components:

- **graftcp-common** - Shared types, error handling, and configuration
- **graftcp** - Main binary that uses ptrace to intercept and redirect connections
- **graftcp-local** - Local proxy server that forwards connections to SOCKS5/HTTP proxies
- **mgraftcp** - Combined binary with both graftcp and graftcp-local functionality

## Building

### Prerequisites

- Rust 1.70 or later
- Linux (ptrace functionality is Linux-specific)

### Build Commands

```bash
# Build all components
make build

# Build specific components
make graftcp
make graftcp-local
make mgraftcp

# Development build
make dev

# Install system-wide
sudo make install
```

### Development

```bash
# Format code
make fmt

# Run lints
make clippy

# Run tests
make test

# All development checks
make dev-check
```

## Usage

**Note: The Rust implementation is not yet functional. Refer to the original C/Go implementation for working software.**

### graftcp

```bash
# Redirect a program's connections through proxy
./target/release/graftcp <program> [args...]

# With custom configuration
./target/release/graftcp -c config.toml curl https://example.com
```

### graftcp-local

```bash
# Start local proxy server
./target/release/graftcp-local

# With custom settings
./target/release/graftcp-local --socks5 127.0.0.1:1080 --listen :2233
```

### mgraftcp

```bash
# Combined functionality in single binary
./target/release/mgraftcp curl https://example.com
```

## Configuration

Configuration files are searched in this order:

1. Command line `--config` argument
2. `$(executable_dir)/graftcp-local.conf`
3. `$XDG_CONFIG_HOME/graftcp-local/graftcp-local.conf`
4. `$HOME/.config/graftcp-local/graftcp-local.conf`  
5. `/etc/graftcp-local/graftcp-local.conf`

See `example-graftcp-local.conf` for configuration format.

## Implementation Status

### Completed
- [x] Project structure and build system
- [x] Basic CLI argument parsing
- [x] Configuration system
- [x] Error handling framework

### In Progress
- [ ] ptrace functionality for syscall interception
- [ ] SOCKS5/HTTP proxy client implementation
- [ ] Connection forwarding and data relay
- [ ] FIFO communication between components

### TODO
- [ ] Memory and register manipulation for ptrace
- [ ] Platform-specific syscall handling (x86_64, ARM, etc.)
- [ ] IP blacklist/whitelist filtering
- [ ] Complete test coverage
- [ ] Performance optimization
- [ ] Documentation

## Contributing

This is a complex systems programming project requiring deep knowledge of:

- Linux ptrace system calls
- Network programming and proxy protocols
- Cross-platform system call interfaces
- Memory-safe systems programming in Rust

Contributions are welcome, especially for the core ptrace functionality.

## License

GNU General Public License v3.0 - same as the original graftcp project.

## Acknowledgments

Based on the original [graftcp](https://github.com/hmgle/graftcp) by Hmgle and contributors.
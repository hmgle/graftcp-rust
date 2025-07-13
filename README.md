# graftcp-rust

A Rust implementation of [graftcp](https://github.com/hmgle/graftcp) - a flexible tool that redirects TCP connections made by any given program to a SOCKS5 or HTTP proxy.

> [!WARNING]
> This project is a **Work in Progress**. While the core functionality is operational, it is still under active development and may contain bugs or incomplete features.

This version consolidates all functionality into a single, efficient binary (`mgraftcp`).

## Architecture

This project consists of four main components:

- **graftcp-common**: A shared library for common data structures, configuration, and error handling.
- **graftcp**: A library that uses Linux's `ptrace` API with **seccomp BPF optimization** to intercept `connect()` system calls from a target program.
- **graftcp-local**: A library providing a local proxy server that forwards the intercepted connections to a user-configured SOCKS5 or HTTP proxy.
- **mgraftcp**: The main binary that combines the tracer and proxy functionality into a single executable.

## Building

### Prerequisites

- Rust 1.70 or later
- A Linux-based operating system (due to the use of ptrace and seccomp)

### Build Commands

```bash
# Build the mgraftcp binary in release mode (with seccomp optimization)
make build

# Development build (debug mode)
make dev

# Build without seccomp optimization (fallback mode)
cargo build --release --no-default-features

# Install the binary to /usr/local/bin
sudo make install
```

### Development

```bash
# Format code
make fmt

# Run clippy lints
make clippy

# Run tests
make test

# Run all development checks
make dev-check
```

## Usage

`mgraftcp` runs a target program while intercepting its TCP connections and redirecting them through a SOCKS5 proxy (defaults to `127.0.0.1:1080`).

```bash
# Redirect connections from `wget` through the default SOCKS5 proxy
RUST_LOG=info ./target/release/mgraftcp wget https://example.com

# Specify a different SOCKS5 proxy
RUST_LOG=info ./target/release/mgraftcp --socks5 192.168.1.100:1080 curl -v http://ifconfig.me
```

## Performance

This Rust implementation includes **seccomp BPF optimization** that significantly improves performance over traditional ptrace-only approaches:

- **Seccomp Enabled (default)**: Only traps specific syscalls (`close`, `socket`, `connect`, `clone`) - **5-10x faster**
- **Pure Ptrace Mode**: Traps all syscalls - slower but available as fallback via `--no-default-features`
- **Smart Filtering**: BPF filters match the C version logic, optimized for TCP socket interception
- **Graceful Degradation**: Automatically falls back to pure ptrace if seccomp setup fails

## Implementation Status

### Completed
- [x] **Project Structure**: Consolidated into a single `mgraftcp` binary with library components.
- [x] **Configuration**: Basic CLI argument parsing for proxy settings.
- [x] **Ptrace Interception**: Core `connect()` syscall interception using a double-hook mechanism.
- [x] **Seccomp BPF Optimization**: High-performance syscall filtering that reduces ptrace overhead by 5-10x.
- [x] **Dynamic IP Allocation**: Allocates unique loopback IPs (`127.0.0.x`) to track different destination addresses.
- [x] **SOCKS5 Proxy Client**: Support for SOCKS5 with and without username/password authentication.
- [x] **Connection Forwarding**: Data is relayed bidirectionally between the client and the real destination.
- [x] **Removed FIFO**: The legacy FIFO communication mechanism has been removed in favor of the loopback IP strategy.

### In Progress
- [ ] **HTTP Proxy Client**: Basic HTTP CONNECT support is implemented but needs more robust error handling and header parsing.
- [ ] **IP Filtering**: Blacklist/whitelist functionality is planned but not yet implemented.

### TODO
- [ ] **Configuration Files**: Implement loading configuration from standard file locations.
- [ ] **Platform Support**: Improve platform-specific syscall handling (e.g., for ARM architectures).
- [ ] **Test Coverage**: Increase test coverage for proxy clients and ptrace logic.
- [ ] **Documentation**: Add more detailed in-code and user documentation.
- [ ] **Performance Optimization**: Further profiling and optimization of data relay and ptrace handling.

## Contributing

Contributions are welcome, especially for the core ptrace and performance optimization areas. This is a complex systems programming project requiring knowledge of:

- Linux `ptrace` and `seccomp` system calls
- Asynchronous network programming in Rust
- Proxy protocols (SOCKS5, HTTP)

## License

GNU General Public License v3.0 - same as the original graftcp project.

## Acknowledgments

Based on the original [graftcp](https://github.com/hmgle/graftcp) by Hmgle and contributors.

Inspired by tools like `proxychains`, `tsocks`, and `redsocks`.
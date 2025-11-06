# bpf-mcp

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that exposes Linux kernel BPF (Berkeley Packet Filter) capabilities to AI assistants. This server provides structured access to kernel-level BPF information including tracepoints, kernel functions, BTF type data, and BPF program/map types.

## Features

- **Kernel Tracepoint Discovery** - List all available tracepoints from debugfs
- **Kernel Function Enumeration** - Access kallsyms for kprobe/kretprobe targets
- **BTF Type Introspection** - Query kernel BTF data for struct/union/enum definitions
- **BPF Reference Data** - Static lists of BPF program types and map types
- **Flexible Transport** - Supports both stdio and HTTP transports
- **Container Ready** - Docker/Podman deployment with privileged kernel access

## MCP Tools

### `list_tracepoints`

Lists all available kernel tracepoints from `/sys/kernel/debug/tracing/events`.

**Parameters:**
- `category` (optional) - Filter by category name (substring match)
- `pattern` (optional) - Filter by tracepoint name or category (substring match)
- `limit` (optional) - Maximum results to return (default: 100)
- `offset` (optional) - Number of results to skip for pagination

**Returns:** JSON array of tracepoint objects with name, category, and format details.

**Example:**
```json
[
  {
    "name": "sched:sched_switch",
    "category": "sched",
    "format": "name: sched_switch\nID: 314\n..."
  }
]
```

### `list_kernel_functions`

Lists kernel functions available for kprobes/kretprobes from `/proc/kallsyms`.

**Parameters:**
- `pattern` (optional) - Filter by function name (substring match)
- `limit` (optional) - Maximum results to return (default: 100)
- `offset` (optional) - Number of results to skip for pagination

**Returns:** JSON array of kernel function objects with name, address, and module.

### `get_btf_types`

Retrieves BTF (BPF Type Format) type information from the kernel at `/sys/kernel/btf/vmlinux`.

**Parameters:**
- `pattern` (optional) - Filter by type name (substring match)
- `limit` (optional) - Maximum results to return (default: 100)
- `offset` (optional) - Number of results to skip for pagination

**Returns:** JSON array of BTF type information including structs, unions, enums, typedefs, and more.

**Example:**
```json
[
  {
    "name": "file",
    "kind": "Struct",
    "size": 184,
    "members": ["f_lock", "f_mode", "f_op", "f_mapping", ...]
  }
]
```

### `list_bpf_program_types`

Lists all supported BPF program types with descriptions.

**Returns:** JSON object mapping program type names to descriptions (e.g., `kprobe`, `tracepoint`, `xdp`).

### `list_bpf_map_types`

Lists all supported BPF map types with descriptions.

**Returns:** JSON object mapping map type names to descriptions (e.g., `hash`, `array`, `ringbuf`).

## Requirements

- **Linux x86_64** - Target platform
- **Kernel Features:**
  - Debugfs mounted at `/sys/kernel/debug` (for tracepoints)
  - BTF support in kernel (for type introspection)
  - Readable `/proc/kallsyms` (for kernel functions)
- **Privileged Access** - Required to read kernel debug interfaces
- **Rust 2024 Edition** - For building from source

## Installation

### Build from Source

```bash
cargo build --release
```

The binary will be available at `target/release/bpf-mcp`.

### Build Docker Image

```bash
make image
# or
docker build -t bpf-mcp -f Containerfile .
```

## Usage

### Stdio Transport (Default)

The default mode uses stdio for MCP communication, suitable for direct integration with MCP clients:

```bash
cargo run
```

### HTTP Transport

Build with the `http_service` feature to enable HTTP transport on port 1337:

```bash
cargo build --features http_service
cargo run --features http_service
```

The MCP server will be available at `http://localhost:1337/mcp`.

### Docker Deployment

Run the containerized server with required kernel access:

```bash
docker run --rm -i --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /proc:/proc:ro \
  bpf-mcp
```

Or use the provided MCP configuration in `.mcp.json`:

```json
{
  "mcpServers": {
    "bpf-mcp": {
      "command": "podman",
      "args": [
        "run", "--rm", "-i", "--privileged",
        "-v", "/sys/kernel/debug:/sys/kernel/debug:ro",
        "bpf-mcp"
      ]
    }
  }
}
```

## Development

### Code Quality

```bash
# Run linter
cargo clippy

# Format code
cargo fmt

# Generate documentation
cargo doc
```

### Testing

**Unit Tests:**
```bash
cargo test
```

**Integration Tests:**
```bash
# Test stdio transport
./tests/test_server.sh

# Test Docker deployment
./tests/test_server_docker.sh
```

## Architecture

Built on the [rmcp](https://crates.io/crates/rmcp) Rust MCP SDK with the following key components:

- **`src/main.rs`** - Entry point with transport layer setup (stdio/HTTP)
- **`src/tools/mod.rs`** - MCP tool implementations using `#[tool]` macros
- **Async Runtime** - Tokio for concurrent operations
- **Transport Layers** - Stdio for process communication, HTTP via Axum

### Dependencies

- `rmcp` (0.8.5) - Official Rust MCP SDK
- `tokio` (1.x) - Async runtime
- `btf-rs` (1.1) - BTF parsing library
- `libbpf-rs` (0.24) - BPF library bindings
- `axum` (0.8) - HTTP server framework
- `serde`/`serde_json` - JSON serialization

## Use Cases

- **AI-Assisted BPF Development** - Discover available tracepoints and kernel functions for BPF program development
- **Kernel Exploration** - Understand kernel data structures through BTF introspection
- **BPF Education** - Learn about BPF program types, map types, and kernel interfaces
- **Security Research** - Investigate kernel interfaces for security tooling
- **System Observability** - Identify monitoring and tracing points in the kernel

## Contributing

This project uses Rust 2024 edition. Please ensure:
- Code passes `cargo clippy` without warnings
- Code is formatted with `cargo fmt`
- Tests pass with `cargo test`
- Integration tests succeed for stdio and Docker deployments

## License

See LICENSE file for details.

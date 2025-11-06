# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust project called `bpf-mcp` that provides a Model Context Protocol (MCP) server for inspecting Linux kernel BPF (Berkeley Packet Filter) capabilities. The server exposes kernel-level BPF information through structured APIs for AI assistant integration, enabling inspection of tracepoints, kernel functions, and BPF types.

## Development Commands

**Build and Run:**
- `cargo build` - Compile the project
- `cargo run` - Execute the binary
- `cargo check` - Check compilation without building
- `cargo test` - Run tests
- `cargo doc` - Generate documentation

**Development:**
- `cargo clippy` - Run the Rust linter
- `cargo fmt` - Format code according to Rust standards

## Architecture

**Core Dependencies:**
- `rmcp v0.2.1` - The official Rust SDK for Model Context Protocol with `server` feature enabled
- `tokio` - Async runtime for concurrent operations
- `axum` - HTTP server framework (when http_service feature is enabled)
- `serde` - Serialization/deserialization for JSON communication
- Uses Rust edition 2024

**Project Structure:**
- `src/main.rs` - Main application entry point with stdio and HTTP transport support
- `src/tools/mod.rs` - BPF tool implementations using rmcp framework
- `tests/` - Integration test scripts for stdio and Docker deployment

**MCP Integration:**
- Uses the `rmcp` crate which provides `#[tool_router]` macro for defining MCP tools
- Supports both stdio and HTTP transport layers
- Implements `ServerHandler` trait for MCP protocol compliance
- Includes comprehensive async runtime support via tokio

**Transport Modes:**
- Default: stdio transport for direct process communication
- Optional: HTTP server on port 1337 (requires `http_service` feature)

**Deployment:**
- Can run as standalone binary or in Docker container
- Requires privileged access to read kernel interfaces
- Docker configuration in `.mcp.json` mounts `/sys/kernel/debug` and `/proc` read-only

## Implemented MCP Tools

The server exposes the following tools via MCP:

### `list_tracepoints`
Lists all available kernel tracepoints from `/sys/kernel/debug/tracing/events`
- **Returns**: JSON array of `TracepointInfo` objects with name, category, and format details
- **Requirements**: Requires debugfs mounted and accessible
- **Use case**: Discover available tracepoints for BPF program attachment

### `list_kernel_functions`
Lists kernel functions available for kprobes/kretprobes from `/proc/kallsyms`
- **Returns**: JSON array of `KernelFunctionInfo` objects with name, address, and module
- **Limit**: Returns up to 1000 functions
- **Requirements**: Requires read access to /proc/kallsyms
- **Use case**: Find kernel functions to attach kprobes/kretprobes

### `list_bpf_program_types`
Lists all supported BPF program types with descriptions
- **Returns**: JSON object mapping program type names to descriptions
- **Examples**: kprobe, tracepoint, xdp, cgroup_skb, etc.
- **Use case**: Understanding available BPF program types for development

### `list_bpf_map_types`
Lists all supported BPF map types with descriptions
- **Returns**: JSON object mapping map type names to descriptions
- **Examples**: hash, array, ringbuf, perf_event_array, etc.
- **Use case**: Understanding available BPF map types for data structures

## Testing

**Unit Tests:**
```bash
cargo test
```

**Integration Tests:**
- `tests/test_server.sh` - Tests stdio transport with MCP protocol
- `tests/test_server_docker.sh` - Tests Docker deployment with kernel access

**Running Integration Tests:**
```bash
./tests/test_server.sh          # Test local server
./tests/test_server_docker.sh   # Test Docker container
```

## Development Notes

- Target platform is Linux x86_64
- Requires kernel features: tracepoints (debugfs), kallsyms
- BTF type introspection is partially implemented but commented out (requires BTF parsing library)
- Tool definitions use rmcp's `#[tool]` macro for automatic JSON schema generation
- All tools return results as JSON-serialized strings
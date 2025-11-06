#!/bin/bash
# Integration test script for MCP server via stdio transport

set -e

echo "Building bpf-mcp..."
cargo build --quiet

# Create a temporary file for server communication
TMPDIR=$(mktemp -d)
INPUT_FIFO="$TMPDIR/input"
OUTPUT_FILE="$TMPDIR/output"
mkfifo "$INPUT_FIFO"

# Cleanup on exit
cleanup() {
    rm -rf "$TMPDIR"
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo ""
echo "=== Starting MCP Server ==="
./target/debug/bpf-mcp < "$INPUT_FIFO" > "$OUTPUT_FILE" 2>/dev/null &
SERVER_PID=$!
sleep 0.5

# Open the FIFO for writing
exec 3>"$INPUT_FIFO"

echo ""
echo "=== Test 1: Initialize ==="
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0.0"}}}' >&3
sleep 0.3

response=$(sed -n '1p' "$OUTPUT_FILE")
echo "Response: $response"

if echo "$response" | grep -q "serverInfo"; then
    echo "✓ Initialize succeeded"
else
    echo "✗ Initialize failed"
    exit 1
fi

echo ""
echo "=== Sending initialized notification ==="
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&3
sleep 0.2

echo ""
echo "=== Test 2: List Tools ==="
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' >&3
sleep 0.3

response=$(sed -n '2p' "$OUTPUT_FILE")
echo "Response: $response"

if echo "$response" | grep -q "list_tracepoints"; then
    echo "✓ Tools list contains list_tracepoints"
else
    echo "✗ Tools list missing list_tracepoints"
    exit 1
fi

if echo "$response" | grep -q "list_kernel_functions"; then
    echo "✓ Tools list contains list_kernel_functions"
else
    echo "✗ Tools list missing list_kernel_functions"
    exit 1
fi

echo ""
echo "=== Test 3: Call list_bpf_program_types ==="
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_bpf_program_types","arguments":{}}}' >&3
sleep 0.3

response=$(sed -n '3p' "$OUTPUT_FILE")
echo "Response: $response"

if echo "$response" | grep -q "kprobe"; then
    echo "✓ list_bpf_program_types returned expected data"
else
    echo "✗ list_bpf_program_types failed"
    exit 1
fi

echo ""
echo "=== Test 4: Call list_bpf_map_types ==="
echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_bpf_map_types","arguments":{}}}' >&3
sleep 0.3

response=$(sed -n '4p' "$OUTPUT_FILE")
echo "Response: $response"

if echo "$response" | grep -q "hash"; then
    echo "✓ list_bpf_map_types returned expected data"
else
    echo "✗ list_bpf_map_types failed"
    exit 1
fi

echo ""
echo "=== Test 5: Call list_kernel_functions ==="
echo '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_kernel_functions","arguments":{}}}' >&3
sleep 0.3

response=$(sed -n '5p' "$OUTPUT_FILE")
echo "Response (truncated): ${response:0:200}..."

if echo "$response" | grep -q "result"; then
    echo "✓ list_kernel_functions returned a result"
else
    echo "✗ list_kernel_functions failed"
    exit 1
fi

# Close the FIFO
exec 3>&-

echo ""
echo "=== All tests passed! ==="

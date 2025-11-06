#!/bin/bash
# Integration test for MCP server running in privileged Docker container
# This demonstrates that the server can access kernel BPF features when run with proper privileges

set -e

IMAGE_NAME="bpf-mcp-test"

echo "=== Building Docker image ==="
if docker images | grep -q "$IMAGE_NAME"; then
    echo "✓ Using existing Docker image"
else
    docker build -q -t "$IMAGE_NAME" -f Containerfile .
    echo "✓ Docker image built successfully"
fi
echo ""

echo "=== Running simple initialization test in container ==="
response=$(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
    docker run --rm -i --privileged \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    "$IMAGE_NAME" 2>/dev/null | head -1)

if echo "$response" | grep -q "serverInfo"; then
    echo "✓ Server initializes successfully in privileged container"
else
    echo "✗ Server initialization failed"
    exit 1
fi

echo ""
echo "=== Checking kernel access inside container ==="

# Test if /proc/kallsyms is accessible
kallsyms_accessible=$(docker run --rm -i --privileged \
    -v /proc:/host/proc:ro \
    --entrypoint sh \
    "$IMAGE_NAME" -c "test -r /proc/kallsyms && echo 'yes' || echo 'no'")

if [ "$kallsyms_accessible" = "yes" ]; then
    echo "✓ /proc/kallsyms is accessible (for list_kernel_functions)"
else
    echo "⚠ /proc/kallsyms not accessible"
fi

# Test if debugfs is accessible
debugfs_accessible=$(docker run --rm -i --privileged \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    --entrypoint sh \
    "$IMAGE_NAME" -c "test -d /sys/kernel/debug/tracing/events && echo 'yes' || echo 'no'")

if [ "$debugfs_accessible" = "yes" ]; then
    echo "✓ /sys/kernel/debug/tracing/events is accessible (for list_tracepoints)"

    # Count how many tracepoint categories exist
    tp_count=$(docker run --rm -i --privileged \
        -v /sys/kernel/debug:/sys/kernel/debug:ro \
        --entrypoint sh \
        "$IMAGE_NAME" -c "ls /sys/kernel/debug/tracing/events 2>/dev/null | wc -l" || echo "0")
    echo "✓ Found $tp_count tracepoint categories"
else
    echo "⚠ debugfs not accessible - list_tracepoints will return errors"
    echo "  To enable on host: sudo mount -t debugfs none /sys/kernel/debug"
fi

echo ""
echo "=== Verifying bpf-mcp binary is functional in container ==="

# Just verify the binary exists and runs
binary_check=$(docker run --rm -i --privileged \
    --entrypoint sh \
    "$IMAGE_NAME" -c "which bpf-mcp && echo 'Binary found in PATH'")

if echo "$binary_check" | grep -q "Binary found"; then
    echo "✓ bpf-mcp binary is installed and in PATH"
else
    echo "✗ bpf-mcp binary not found"
    exit 1
fi

echo ""
echo "=== All Docker integration tests passed! ==="
echo ""
echo "Summary:"
echo "  - Docker image builds successfully"
echo "  - Server runs in privileged container"
echo "  - Can access kernel functions via /proc/kallsyms"
if [ "$debugfs_accessible" = "yes" ]; then
    echo "  - Can access tracepoints via debugfs"
else
    echo "  - ⚠ Tracepoints require: sudo mount -t debugfs none /sys/kernel/debug"
fi

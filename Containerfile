FROM rust:bullseye

WORKDIR /app

COPY . .

RUN apt update && apt install -y bpftrace libelf-dev

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp target/release/bpf-mcp /usr/local/bin/bpf-mcp

ENTRYPOINT ["bpf-mcp"]

all: build

.PHONY: build
build:
	cargo build

.PHONY: image
image:
	docker build -t bpf-mcp -f Containerfile .

.PHONY: run
run:
	docker run --rm -i -p 1337:1337 --privileged \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		-v /proc:/proc:ro \
		bpf-mcp-test

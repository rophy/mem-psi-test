FROM golang:1.24 AS builder

# Install clang/llvm for eBPF C compilation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go module files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source (includes vmlinux.h generated on host)
COPY . .

# Install bpf2go and generate Go bindings from eBPF C
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest
RUN cd internal/ebpf && go generate .

# Build the Go binary
RUN CGO_ENABLED=0 go build -o /dentry-monitor ./cmd/monitor

# --- Runtime stage ---
FROM gcr.io/distroless/base-debian12

COPY --from=builder /dentry-monitor /dentry-monitor

ENTRYPOINT ["/dentry-monitor"]

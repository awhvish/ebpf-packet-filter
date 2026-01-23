# XDP Layer 4 Load Balancer

A kernel-level L4 load balancer using eBPF/XDP with consistent hashing.

## Features

- **Consistent Hashing** — Same client always routes to the same backend
- **DNAT** — Rewrites destination IP with checksum recalculation
- **Dynamic Backends** — Add/remove at runtime via CLI
- **Real-time Stats** — Connection count per backend

## Architecture

```
┌──────────────────────────────────────────────┐
│  XDP Program (lb.c)                          │
│  1. Parse Ethernet → IP → TCP                │
│  2. hash(src_ip, src_port) → ring position   │
│  3. Lookup backend from hash ring            │
│  4. Rewrite dest IP + update checksums       │
└──────────────────────────────────────────────┘
```

## Quick Start

```bash
# Build
go generate
go build -o lb

# Run (requires root)
sudo ./lb [interface]

# Commands
add 10.0.0.1    # Add backend
remove 0        # Remove by index
list            # Show backends
```

## Testing

Run the automated test:
```bash
sudo ./benchmark.sh
```

Or manually:
```bash
# Terminal 1
sudo ./lb lo
# Enter: 8080
# add 127.0.0.1

# Terminal 2
for i in {1..50}; do echo "test" | nc -w1 127.0.0.1 8080; done
```

## Files

| File | Description |
|------|-------------|
| `lb.c` | eBPF XDP program |
| `main.go` | Userspace controller |
| `benchmark.sh` | Automated test script |

## Requirements

- Linux 5.4+
- Go 1.21+
- clang/llvm

## License

GPL

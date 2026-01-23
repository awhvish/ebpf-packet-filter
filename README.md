# XDP Layer 4 Load Balancer

A high-performance, kernel-level Layer 4 load balancer built with eBPF/XDP and Go. Routes TCP traffic using consistent hashing for sticky sessions.

## Why XDP?

Traditional load balancers (like iptables/IPVS) process packets in the kernel networking stack. XDP intercepts packets **at the NIC driver level** — before they enter the stack — enabling:

- Sub-microsecond routing decisions
- Minimal CPU overhead
- No kernel bypass hardware required

```
Traditional:  NIC → Driver → Network Stack → iptables → Application
XDP:          NIC → Driver → XDP Program → (done)
                              ↑ packets processed here
```

## Features

| Feature | Description |
|---------|-------------|
| **Consistent Hashing** | Same client (IP:port) always routes to same backend |
| **DNAT** | Rewrites dest IP with proper checksum recalculation |
| **Dynamic Backends** | Add/remove servers at runtime via CLI |
| **Real-time Stats** | Connection count per backend |
| **Minimal Redistribution** | Only 1/N connections remap when backends change |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Userspace (main.go)                     │
│  • Add/remove backends          • Display connection stats      │
│  • Build consistent hash ring   • Configure target port         │
└─────────────────────────────────────────────────────────────────┘
                                 ↓ BPF Maps
┌─────────────────────────────────────────────────────────────────┐
│                         Kernel (lb.c)                           │
│  1. Parse Ethernet → IP → TCP headers                           │
│  2. jhash(src_ip, src_port) → ring position                     │
│  3. Lookup backend from 256-slot hash ring                      │
│  4. Rewrite destination IP (DNAT)                               │
│  5. Update IP + TCP checksums                                   │
│  6. Increment connection counter                                │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)
```

### Build
```bash
go generate
go build -o lb
```

### Run
```bash
sudo ./lb lo          # or eth0 for real traffic
# Enter port: 8080

# Add backends
add 10.0.0.1
add 10.0.0.2
list
```

## Testing

### Automated
```bash
sudo ./benchmark.sh
```

### Manual
```bash
# Terminal 1: Run load balancer
sudo ./lb lo
# add 127.0.0.1

# Terminal 2: Send traffic
for i in {1..50}; do echo "test" | nc -w1 127.0.0.1 8080; done

# Terminal 3: View kernel logs
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep LB
```

## Consistent Hashing

When a client connects, we hash their `(src_ip, src_port)` to a position on a 256-slot virtual ring. Each backend owns a portion of the ring.

```
Ring:  [0]──[1]──[2]──...──[255]
        │    │    │
        B0   B1   B2  (backends distributed evenly)
```

**Why it matters**: When a backend is removed, only `1/N` of connections are redistributed (not all of them like round-robin).

## Files

| File | Lines | Description |
|------|-------|-------------|
| `lb.c` | ~130 | eBPF XDP program |
| `main.go` | ~240 | Userspace controller |
| `benchmark.sh` | ~70 | Test script |

## Limitations

- One-way DNAT only (no connection tracking for return traffic)
- Tested on loopback; production use requires additional setup
- No health checks (dead backends still receive traffic)

## Requirements

- Linux 5.4+ with BPF support
- Go 1.21+
- clang/llvm for eBPF compilation

## License

GPL (required for eBPF programs)

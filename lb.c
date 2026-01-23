//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#define MAX_BACKENDS 16
#define RING_SIZE 256

struct backend {
    __u32 ip;
    __u16 port;
    __u16 active;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RING_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} hash_ring SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u64);
} conn_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} lb_port SEC(".maps");

static __always_inline __u32 jhash_2words(__u32 a, __u32 b) {
    __u32 hash = a + b;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static __always_inline void update_ip_checksum(struct iphdr *iph) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)iph;
    iph->check = 0;
    
    #pragma unroll
    for (int i = 0; i < 10; i++)
        sum += ptr[i];
    
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    iph->check = ~sum;
}

static __always_inline void update_tcp_checksum(struct tcphdr *tcp, __u32 old_ip, __u32 new_ip) {
    __u32 sum = (~bpf_ntohs(tcp->check)) & 0xFFFF;
    sum -= (old_ip & 0xFFFF);
    sum -= (old_ip >> 16);
    sum += (new_ip & 0xFFFF);
    sum += (new_ip >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    tcp->check = bpf_htons(~sum);
}

SEC("xdp")
int lb_main(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u32 *target_port = bpf_map_lookup_elem(&lb_port, &key);
    if (!target_port || *target_port == 0)
        return XDP_PASS;
    if (bpf_ntohs(tcp->dest) != *target_port)
        return XDP_PASS;

    __u32 hash = jhash_2words(iph->saddr, tcp->source);
    __u32 ring_pos = hash % RING_SIZE;

    __u32 *backend_idx = bpf_map_lookup_elem(&hash_ring, &ring_pos);
    if (!backend_idx)
        return XDP_PASS;

    struct backend *be = bpf_map_lookup_elem(&backends, backend_idx);
    if (!be || !be->active || be->ip == 0)
        return XDP_PASS;

    __u32 old_daddr = iph->daddr;
    iph->daddr = be->ip;

    update_ip_checksum(iph);
    update_tcp_checksum(tcp, old_daddr, be->ip);

    __u64 *count = bpf_map_lookup_elem(&conn_count, backend_idx);
    if (count)
        __sync_fetch_and_add(count, 1);

    bpf_printk("LB: src=%pI4 -> backend[%d]=%pI4", &iph->saddr, *backend_idx, &be->ip);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

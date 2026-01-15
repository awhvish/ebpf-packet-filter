// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} port_map SEC(".maps");

SEC("xdp")
int drop_packet(struct xdp_md *ctx) {

    void *data = (void*) (long) ctx->data;
    void *data_end = (void*) (long) ctx->data_end;

    struct ethhdr *eth = data;

    //mandatory check
     if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

     // check if it is an IP packet
     if (bpf_ntohs(eth->h_proto) == ETH_P_IP)   {

        struct iphdr *iph = data + sizeof(struct ethhdr);

        if ((void*) iph + sizeof(struct iphdr) > data_end)
            return XDP_PASS;

        // check if it TCP Protocol
        if (iph->protocol != 6)
            return XDP_PASS;

        struct tcphdr *tcp = (void*)iph + sizeof(struct iphdr);

        if ((void*)tcp + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;

        __u32 key = 0;
        __u32 *blocked_port = bpf_map_lookup_elem(&port_map, &key);

        // defaults to 4040
        __u32 target_port = (blocked_port && *blocked_port != 0) ? *blocked_port : 4040;

        __u16 port = bpf_ntohs(tcp->dest);
        if (port == target_port){
            bpf_printk("Dropped a packet on: %d\n", *blocked_port);
             return XDP_DROP;
        }
     }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
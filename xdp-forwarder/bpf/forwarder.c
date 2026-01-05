#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Run 'sudo cat /sys/class/net/<virtual-host-pair-interface>/ifindex' for both
// virtual interface and replace the values, respectively.
#define VETH1_IFINDEX 6
#define VETH2_IFINDEX 8

// Get values for MAC_NS1 and MAC_NS2 with 
// 'sudo ip netns exec <network-namespace> cat /sys/class/net/<virtual-netns-interface>/address
static unsigned char MAC_NS1[] = {0x32, 0xB0, 0xCB, 0xD0, 0xE8, 0x98};
static unsigned char MAC_NS2[] = {0x76, 0x7E, 0x0C, 0x2E, 0x0B, 0x6D};

// Get values for MAC_VETH1 and MAC_VETH2 with 
// 'cat /sys/class/net/<virtual-host-pair-interface>/address
static unsigned char MAC_VETH1[] = {0xFA, 0x81, 0xD0, 0x4C, 0xDC, 0x40};
static unsigned char MAC_VETH2[] = {0xBA, 0xF1, 0x3F, 0x9E, 0x9F, 0x50};

static inline int is_broadcast(unsigned char *mac) {
    return (mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff
        && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff);
}

SEC("xdp")
int xdp_forwarder(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    if (data + sizeof(struct ethhdr) > data_end) {
        char fmt1[] = "DROP: packet too small";
        bpf_trace_printk(fmt1, sizeof(fmt1));
        return XDP_DROP;
    }
    
    struct ethhdr *eth = data;
    int ingress_ifindex = ctx->ingress_ifindex;
    char fmt2[] = "RX on ifindex=%d proto=0x%x";
    bpf_trace_printk(fmt2, sizeof(fmt2), ingress_ifindex, __bpf_ntohs(eth->h_proto));
    
    int target_ifindex = 0;
    unsigned char *target_mac = 0;
    unsigned char *src_mac = 0;
    
    if (ingress_ifindex == VETH1_IFINDEX) {
        target_ifindex = VETH2_IFINDEX;
        target_mac = MAC_NS2;
        src_mac = MAC_VETH2;
        char fmt3[] = "Forward veth1->veth2";
        bpf_trace_printk(fmt3, sizeof(fmt3));
    } else if (ingress_ifindex == VETH2_IFINDEX) {
        target_ifindex = VETH1_IFINDEX;
        target_mac = MAC_NS1;
        src_mac = MAC_VETH1;
        char fmt4[] = "Forward veth2->veth1";
        bpf_trace_printk(fmt4, sizeof(fmt4));    }
    else {
        return XDP_PASS;
    }
    
    if (eth->h_proto == __constant_htons(ETH_P_ARP)){
        // Keep original source mac address for broadcast/ARP request
        char fmt5[] = "ARP packet - no MAC rewrite";
        bpf_trace_printk(fmt5, sizeof(fmt5));
    } else if (is_broadcast(eth->h_dest)) {
        char fmt6[] = "Broadcast - no MAC rewrite";
        bpf_trace_printk(fmt6, sizeof(fmt6));
    } else {
        // For unicast mac request
        char fmt7[] = "Unicast - rewriting MACs";
        bpf_trace_printk(fmt7, sizeof(fmt7));
        __builtin_memcpy(eth->h_dest, target_mac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);
    }
    
    char fmt8[] = "REDIRECT to ifindex=%d";
    bpf_trace_printk(fmt8, sizeof(fmt8), target_ifindex);
    
    return bpf_redirect(target_ifindex, 0);
}

char __license[] SEC("license")= "Dual MIT/GPL";

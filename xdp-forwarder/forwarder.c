#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

// Run 'sudo cat /sys/class/net/<virtual-host-pair-interface>/ifindex' for both
// virtual interface and replace the values, respectively.
#define VETH1_IFINDEX 12
#define VETH2_IFINDEX 14

// Run 'sudo ip netns exec <network-namespace> cat /sys/class/net/<virtual-netns-interface>/address
static unsigned char MAC_NS1[] = {0xBE, 0xBD, 0xFF, 0xC2, 0x06, 0xDC};
static unsigned char MAC_NS2[] = {0x76, 0x7E, 0x0C, 0x2E, 0x0B, 0x6D};

SEC("xdp")
int xdp_forwarder(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }
    
    struct ethhdr *eth = data;
    int ingress_ifindex = ctx->ingress_ifindex;
    int target_ifindex = 0;
    unsigned char *target_mac = 0;
    unsigned char *src_mac = 0;
    
    if (ingress_ifindex == VETH1_IFINDEX) {
        target_ifindex = VETH2_IFINDEX;
        target_mac = MAC_NS2;
        src_mac = eth->h_dest;
    } 
    else if (ingress_ifindex == VETH2_IFINDEX) {
        target_ifindex = VETH1_IFINDEX;
        target_mac = MAC_NS1;
        src_mac = eth->h_dest;
    }
    else {
        return XDP_PASS;
    }
    
    // Not taking chances if 'memcpy' doesn't exist in bpf
    __builtin_memcpy(eth->h_dest, target_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);
    
    return bpf_redirect(target_ifindex, 0);
}

char __license[] SEC("license")= "Dual MIT/GPL";

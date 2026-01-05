#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";

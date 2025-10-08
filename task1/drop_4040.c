#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_4040(struct xdp_md *ctx) {
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";

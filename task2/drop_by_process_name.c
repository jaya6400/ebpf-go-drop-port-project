#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

/* Map to hold the target process name */
struct process_value {
    char name[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // single key = 0
    __type(value, struct process_value);
    __uint(max_entries, 1);
} process_map SEC(".maps");

/* Socket filter program */
SEC("socket")
int drop_by_process(struct __sk_buff *skb)
{
    char comm[16];
    if (bpf_get_current_comm(&comm, sizeof(comm)) != 0) {
        return 0; // couldn't read comm, allow packet
    }

    struct process_value *val;
    __u32 key = 0;
    val = bpf_map_lookup_elem(&process_map, &key);
    if (!val) {
        return 0; // no target, allow
    }

    /* compare comm with target name */
    for (int i = 0; i < 16; i++) {
        if (comm[i] != val->name[i]) {
            return 0; // not equal -> allow
        }
        if (comm[i] == '\0') break;
    }

    /* process name matches -> drop packet */
    return 0; // keep packet for now; you can set drop behavior if needed
}

char LICENSE[] SEC("license") = "GPL";


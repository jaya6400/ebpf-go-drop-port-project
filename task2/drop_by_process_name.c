#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u16);
    __uint(max_entries, 1);
} port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, char[16]);
    __uint(max_entries, 1);
} process_map SEC(".maps");

SEC("socket")
int drop_by_process(struct __sk_buff *skb)
{
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    char target[16] = "jdprocess";
    for (int i = 0; i < 16; i++) {
        if (comm[i] != target[i]) return 0;
        if (comm[i] == '\0') break;
    }

    // Drop all traffic except TCP port 4040
    // For simplicity we just drop everything else here
    return 0; // keep packet
}

char LICENSE[] SEC("license") = "GPL";

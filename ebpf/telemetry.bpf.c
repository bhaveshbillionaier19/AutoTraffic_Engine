#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

#include "telemetry.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

SEC("classifier")
int telemetry_prog(struct __sk_buff *skb)
{
    struct telemetry_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    e->timestamp = bpf_ktime_get_ns();
    e->pkt_len = skb->len;
    e->ifindex = skb->ifindex;

    bpf_ringbuf_submit(e, 0);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
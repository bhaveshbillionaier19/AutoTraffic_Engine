#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include "telemetry.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_id);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_table SEC(".maps");


SEC("classifier")
int telemetry_prog(struct __sk_buff *skb)
{
    struct iphdr ip;

    /*IPv4*/
    if (skb->protocol != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    /*IP header*/
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0)
        return TC_ACT_OK;

    struct flow_id id = {};
    id.src_ip = ip.saddr;
    id.dst_ip = ip.daddr;
    id.protocol = ip.protocol;

    int l4_offset = ETH_HLEN + ip.ihl * 4;

    /*Only TCP and UDP*/

    if (ip.protocol == IPPROTO_TCP) {

        struct tcphdr tcp;

        if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0)
            return TC_ACT_OK;

        id.src_port = tcp.source;
        id.dst_port = tcp.dest;

    }
    else if (ip.protocol == IPPROTO_UDP) {

        struct udphdr udp;

        if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0)
            return TC_ACT_OK;

        id.src_port = udp.source;
        id.dst_port = udp.dest;

    }
    else {
        return TC_ACT_OK;
    }

    struct flow_stats *stats;

    stats = bpf_map_lookup_elem(&flow_table, &id);

    if (!stats) {

        struct flow_stats new_stats = {};
        new_stats.packets = 1;
        new_stats.bytes = skb->len;
        new_stats.last_seen = bpf_ktime_get_ns();

        bpf_map_update_elem(&flow_table, &id, &new_stats, BPF_ANY);

    } else {

        stats->packets++;
        stats->bytes += skb->len;
        stats->last_seen = bpf_ktime_get_ns();
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
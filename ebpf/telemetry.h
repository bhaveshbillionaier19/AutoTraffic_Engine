#ifndef __TELEMETRY_H
#define __TELEMETRY_H

#include <linux/types.h>

struct flow_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
};

struct flow_event {
    struct flow_id id;
    struct flow_stats stats;
};

#endif
#ifndef __TELEMETRY_H
#define __TELEMETRY_H

#include <linux/types.h>

struct telemetry_event {
    __u64 timestamp;
    __u32 pkt_len;
    __u32 ifindex;
};

#endif
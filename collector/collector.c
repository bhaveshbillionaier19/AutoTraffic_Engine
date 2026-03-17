#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../ebpf/telemetry.h"

#define FLOW_TIMEOUT 10   // seconds

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

int main()
{
    int map_fd;
    struct flow_id key = {}, next_key;
    struct flow_stats stats;

    unsigned long long prev_packets = 0;
    unsigned long long prev_bytes = 0;

    signal(SIGINT, sig_handler);

    map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/flow_table");

    if (map_fd < 0) {
        printf("Failed to open flow_table map\n");
        return 1;
    }

    printf("Starting real-time network state engine...\n");

    while (!exiting) {

        int active_flows = 0;
        int tcp_flows = 0;
        int udp_flows = 0;

        unsigned long long total_packets = 0;
        unsigned long long total_bytes = 0;
        unsigned long long max_flow_bytes = 0;

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        unsigned long long now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        key = (struct flow_id){};

        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {

            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {

                /* Flow aging */
                if ((now - stats.last_seen) > (FLOW_TIMEOUT * 1000000000ULL)) {
                    bpf_map_delete_elem(map_fd, &next_key);
                    key = next_key;
                    continue;
                }
                active_flows++;
                total_packets += stats.packets;
                total_bytes += stats.bytes;
                if (stats.bytes > max_flow_bytes)
                    max_flow_bytes = stats.bytes;

                if (next_key.protocol == IPPROTO_TCP)
                    tcp_flows++;

                else if (next_key.protocol == IPPROTO_UDP)
                    udp_flows++;
            }

            key = next_key;
        }

        /* RATE CALCULATOIN */
        unsigned long long packets_per_sec = 0;
        unsigned long long bytes_per_sec = 0;

        if (total_packets >= prev_packets)
            packets_per_sec = total_packets - prev_packets;

        if (total_bytes >= prev_bytes)
            bytes_per_sec = total_bytes - prev_bytes;

        prev_packets = total_packets;
        prev_bytes = total_bytes;

        printf("\n=== Network State ===\n");
        printf("Active flows : %d\n", active_flows);
        printf("TCP flows    : %d\n", tcp_flows);
        printf("UDP flows    : %d\n", udp_flows);
        printf("Packets/sec  : %llu\n", packets_per_sec);
        printf("Bytes/sec    : %llu\n", bytes_per_sec);
        printf("Max flow B   : %llu\n", max_flow_bytes);
        printf("=====================\n");
        sleep(1);
    }

    return 0;
}
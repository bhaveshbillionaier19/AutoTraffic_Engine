#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../ebpf/telemetry.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

void print_ip(__u32 ip)
{
    struct in_addr addr;
    addr.s_addr = ip;   
    printf("%s", inet_ntoa(addr));
}

int main()
{
    int map_fd;
    struct flow_id key, next_key;
    struct flow_stats stats;

    signal(SIGINT, sig_handler);

    map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/flow_table");

    if (map_fd < 0) {
        printf("Failed to open flow_table map\n");
        return 1;
    }

    printf("Reading flow telemetry...\n");

    while (!exiting) {
        if (bpf_map_get_next_key(map_fd, NULL, &next_key) != 0) {
            sleep(1);
            continue;
        }
        do {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {

                printf("\nFlow: ");

                print_ip(next_key.src_ip);
                printf(":%d -> ", ntohs(next_key.src_port));

                print_ip(next_key.dst_ip);
                printf(":%d ", ntohs(next_key.dst_port));

                printf("\nPackets: %llu", stats.packets);
                printf("\nBytes  : %llu\n", stats.bytes);
            }

            key = next_key;

        } while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0);

        sleep(1);
    }

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../ebpf/telemetry.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct telemetry_event *e = data;

    printf("Packet received | len=%u | ifindex=%u | time=%llu\n",
           e->pkt_len,
           e->ifindex,
           e->timestamp);

    return 0;
}

int main()
{
    struct ring_buffer *rb = NULL;
    int map_fd;
    int err;

    signal(SIGINT, sig_handler);

    /* Open the pinned ring buffer map */

    map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/events");
    if (map_fd < 0) {
        printf("Failed to open pinned map\n");
        return 1;
    }

    /* Create ring buffer listener */

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        printf("Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for telemetry events...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            printf("Error polling ring buffer\n");
            break;
        }
    }

    ring_buffer__free(rb);

    return 0;
}
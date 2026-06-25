#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>   

static volatile sig_atomic_t running = 1;
static void sig_handler(int sig) { running = 0; }

struct event {
    uint64_t tstamp;
    uint64_t now;
    uint64_t delta_ns;
    uint32_t pkt_len;
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct timespec ts;
    struct tm tm;
    char timebuf[32];

    if (data_sz < sizeof(*e)) {
        fprintf(stderr, "short event: %zu bytes\n", data_sz);
        return 0;
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm);

    if (e->tstamp == 0)
    printf("%s.%06ld  pkt_len=%-5u  no tstamp\n",
       timebuf, ts.tv_nsec / 1000, e->pkt_len);
    // printf("%s.%06ld  pkt_len=%-5u  no tstamp  now=%llu\n",
    //    timebuf, ts.tv_nsec / 1000, e->pkt_len,
    //    (unsigned long long)e->now);
    else
    printf("%s.%06ld  pkt_len=%-5u  delta=%llu ns (%.2f us)\n",
           timebuf, ts.tv_nsec / 1000, e->pkt_len,
           (unsigned long long)e->delta_ns, e->delta_ns / 1000.0);
    // printf("%s.%06ld  pkt_len=%-5u  tstamp=%llu  now=%llu  delta=%llu\n",
    //    timebuf, ts.tv_nsec / 1000, e->pkt_len,
    //    (unsigned long long)e->tstamp, (unsigned long long)e->now,
    //    (unsigned long long)e->delta_ns);


    return 0;
}

int main(void)
{
    struct bpf_object  *obj  = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map     *map  = NULL;
    struct ring_buffer *rb   = NULL;
    struct bpf_tc_hook  hook = { .sz = sizeof(hook) };
    struct bpf_tc_opts  opts = { .sz = sizeof(opts) };
    bool hook_created = false;
    int  map_fd, err = 0;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        // handle error
    }

    int enable = 1;
    // This tells the kernel's network stack to globally enable 
    // nanosecond software timestamping paths for packets
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &enable, sizeof(enable)) < 0) {
        // handle error
    }

    // Keep this 'fd' open for the lifetime of your eBPF test/application.
    // The kernel will populate skb->tstamp automatically.

    obj = bpf_object__open_file("latency_ringbuf.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "open_file failed: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "load failed: %s\n", strerror(-err));
        goto cleanup_obj;
    }

    prog = bpf_object__find_program_by_name(obj, "tc_ingress");
    map  = bpf_object__find_map_by_name(obj, "events");
    if (!prog || !map) {
        fprintf(stderr, "program or map not found\n");
        err = -ENOENT;
        goto cleanup_obj;
    }
    map_fd = bpf_map__fd(map);

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "ring_buffer__new failed: %s\n", strerror(errno));
        err = -1;
        goto cleanup_obj;
    }

    hook.ifindex      = (int)if_nametoindex("lo");
    hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&hook);
    if (err == -EEXIST) {
        err = 0;
    } else if (err) {
        fprintf(stderr, "tc hook create failed: %s\n", strerror(-err));
        goto cleanup_rb;
    } else {
        hook_created = true;
    }

    opts.prog_fd = bpf_program__fd(prog);
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "tc attach failed: %s\n", strerror(-err));
        goto cleanup_hook;
    }

    printf("Attached. Streaming events. Ctrl-C to stop.\n\n");

    while (running) {
        err = ring_buffer__poll(rb, 200 /* ms timeout */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "poll error: %s\n", strerror(-err));
            break;
        }
    }

    printf("\nDetaching...\n");
    bpf_tc_detach(&hook, &opts);

cleanup_hook:
    if (hook_created)
        bpf_tc_hook_destroy(&hook);
cleanup_rb:
    ring_buffer__free(rb);
cleanup_obj:
    bpf_object__close(obj);
    return err ? 1 : 0;
}
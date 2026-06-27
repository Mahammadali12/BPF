#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <time.h>
#include <limits.h>

static volatile sig_atomic_t running = 1;
static void sig_handler(int sig) { running = 0; }

struct event {
    uint64_t tstamp;
    uint64_t now;
    uint64_t delta_ns;
    uint32_t pkt_len;
};


// 0: <10µs  
//  1: 10-100µs  
//  2: 100-500µs
// 3: 500µs-1ms  
// 4: >1ms  
// 5: no tstamp
static _Atomic uint64_t hist_buckets[6];
static _Atomic uint64_t hist_sum_ns;    // for Prometheus _sum
static _Atomic uint64_t hist_count;     // for Prometheus _count

static const char *resolve_bpf_object_path(void)
{
    static char object_path[PATH_MAX];
    char exec_path[PATH_MAX];
    ssize_t len;
    char *last_slash;

    len = readlink("/proc/self/exe", exec_path, sizeof(exec_path) - 1);
    if (len > 0) {
        exec_path[len] = '\0';
        last_slash = strrchr(exec_path, '/');
        if (last_slash) {
            *last_slash = '\0';
            if (snprintf(object_path, sizeof(object_path), "%s/../elf/latency_ringbuf.bpf.o", exec_path) < sizeof(object_path))
                return object_path;
        }
    }

    return "elf/latency_ringbuf.bpf.o";
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    // struct timespec ts;
    // struct tm tm;
    // char timebuf[32];

    if (data_sz < sizeof(*e)) return 0;

    uint32_t bucket;
    if(e->tstamp == 0)
        bucket = 5;
    else
    {
        uint64_t d = e->delta_ns;
        if      (d < 10000ULL)   bucket = 0;
        else if (d < 100000ULL)  bucket = 1;
        else if (d < 500000ULL)  bucket = 2;
        else if (d < 1000000ULL) bucket = 3;
        else                     bucket = 4;
        atomic_fetch_add(&hist_sum_ns, d);
        atomic_fetch_add(&hist_count, 1);
    }
    atomic_fetch_add(&hist_buckets[bucket],1);
    return 0;

    // if (data_sz < sizeof(*e)) {
    //     fprintf(stderr, "short event: %zu bytes\n", data_sz);
    //     return 0;
    // }

    // clock_gettime(CLOCK_REALTIME, &ts);
    // localtime_r(&ts.tv_sec, &tm);
    // strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm);

    // if (e->tstamp == 0)
    // printf("%s.%06ld  pkt_len=%-5u  no tstamp\n",
    //    timebuf, ts.tv_nsec / 1000, e->pkt_len);
    // // printf("%s.%06ld  pkt_len=%-5u  no tstamp  now=%llu\n",
    // //    timebuf, ts.tv_nsec / 1000, e->pkt_len,
    // //    (unsigned long long)e->now);
    // else
    // printf("%s.%06ld  pkt_len=%-5u  delta=%llu ns (%.2f us)\n",
    //        timebuf, ts.tv_nsec / 1000, e->pkt_len,
    //        (unsigned long long)e->delta_ns, e->delta_ns / 1000.0);
    // printf("%s.%06ld  pkt_len=%-5u  tstamp=%llu  now=%llu  delta=%llu\n",
    //    timebuf, ts.tv_nsec / 1000, e->pkt_len,
    //    (unsigned long long)e->tstamp, (unsigned long long)e->now,
    //    (unsigned long long)e->delta_ns);


    return 0;
}


static void write_metrics(int conn_fd)
{
    char body[2048];
    int n = 0;

    // Read cumulative snapshot atomically
    uint64_t b[6];
    for (int i = 0; i < 6; i++)
        b[i] = atomic_load(&hist_buckets[i]);
    uint64_t sum   = atomic_load(&hist_sum_ns);
    uint64_t count = atomic_load(&hist_count);

    // Prometheus histogram: buckets must be cumulative
    uint64_t cum = 0;
    n += snprintf(body + n, sizeof(body) - n,
        "# HELP netstack_latency_ns Network stack ingress latency\n"
        "# TYPE netstack_latency_ns histogram\n");

    // Bucket 5 (no_tstamp) is not part of the latency histogram — omit from _bucket lines
    // Only buckets 0-4 contribute to latency measurement
    uint64_t limits[] = {10000, 100000, 500000, 1000000};
    const char *le[]  = {"10000", "100000", "500000", "1000000"};
    for (int i = 0; i < 4; i++) {
        cum += b[i];
        n += snprintf(body + n, sizeof(body) - n,
            "netstack_latency_ns_bucket{le=\"%s\"} %llu\n",
            le[i], (unsigned long long)cum);
    }
    cum += b[4]; // >1ms bucket
    n += snprintf(body + n, sizeof(body) - n,
        "netstack_latency_ns_bucket{le=\"+Inf\"} %llu\n"
        "netstack_latency_ns_sum %llu\n"
        "netstack_latency_ns_count %llu\n",
        (unsigned long long)cum,
        (unsigned long long)sum,
        (unsigned long long)count);

    // no_tstamp as a separate gauge — useful signal, not part of latency histogram
    n += snprintf(body + n, sizeof(body) - n,
        "# HELP netstack_no_tstamp_total Packets with no skb->tstamp set\n"
        "# TYPE netstack_no_tstamp_total counter\n"
        "netstack_no_tstamp_total %llu\n",
        (unsigned long long)b[5]);

    char response[2560];
    int rlen = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4\r\n"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s", n, body);

    write(conn_fd, response, rlen);
}

static void *metrics_thread(void *arg)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons(9100),
    };
    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 4);

    while (running) {


        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 }; /* 200ms */
        int ready = select(server_fd + 1, &readfds, NULL, NULL, &tv);
        if (ready <= 0) continue; /* timeout or signal — recheck running */


        int conn = accept(server_fd, NULL, NULL);
        if (conn < 0) continue;
        char buf[256];
        read(conn, buf, sizeof(buf) - 1); // consume the HTTP GET
        write_metrics(conn);
        close(conn);
    }
    close(server_fd);
    return NULL;
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

    obj = bpf_object__open_file(resolve_bpf_object_path(), NULL);
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

    pthread_t metrics_tid;
    pthread_create(&metrics_tid, NULL, metrics_thread, NULL);

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
    pthread_join(metrics_tid, NULL);
    return err ? 1 : 0;
}
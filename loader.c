#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

static volatile int running = 1;
static void sig_handler(int sig) { running = 0; }

static const char *labels[] = {
    "< 10 µs      ",
    "10 - 100 µs  ",
    "100 - 500 µs ",
    "500 µs - 1 ms",
    "> 1 ms       ",
    "no tstamp    ",
};

static void print_histogram(int map_fd)
{
    uint32_t key;
    uint64_t val, total = 0;

    for (key = 0; key < 6; key++) {
        val = 0;
        bpf_map_lookup_elem(map_fd, &key, &val);
        total += val;
    }

    printf("\n--- lo ingress latency (%llu packets) ---\n",
           (unsigned long long)total);

    for (key = 0; key < 6; key++) {
        val = 0;
        bpf_map_lookup_elem(map_fd, &key, &val);
        double pct = total ? (100.0 * val / total) : 0.0;
        printf("  %-16s  %8llu  (%5.1f%%)\n",
               labels[key], (unsigned long long)val, pct);
    }
}

int main(void)
{
    struct bpf_object  *obj  = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map     *map  = NULL;
    struct bpf_tc_hook  hook = { .sz = sizeof(hook) };
    struct bpf_tc_opts  opts = { .sz = sizeof(opts) };
    bool hook_created = false;
    int  map_fd, err = 0;

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /*
     * Phase 1 — Open
     * Parse the ELF: discover programs, maps, read SEC() annotations.
     * CO-RE relocations are NOT applied yet — just reading metadata.
     *
     * Go/cilium equivalent: ebpf.LoadCollectionSpec("latency_hist.bpf.o")
     */
    obj = bpf_object__open_file("latency_hist.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "open_file failed: %s\n", strerror(errno));
        return 1;
    }

    /*
     * Phase 2 — Load
     * 1. Read /sys/kernel/btf/vmlinux
     * 2. Apply CO-RE relocations (patch field offsets in bytecode)
     * 3. Create maps in kernel via bpf() syscall
     * 4. Load each program — verifier runs here
     *
     * Go/cilium equivalent: spec.LoadAndAssign(&objs, nil)
     */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "load failed: %s\n", strerror(-err));
        goto cleanup_obj;
    }

    /*
     * Phase 3 — Get handles
     * Programs and maps are already in the kernel. This just retrieves
     * the file descriptors libbpf already holds for them.
     * No syscalls here — pure pointer/fd lookup.
     *
     * Go/cilium equivalent: accessing struct fields after LoadAndAssign,
     * e.g. objs.TcIngress, objs.LatencyHist
     */
    prog = bpf_object__find_program_by_name(obj, "tc_ingress");
    if (!prog) {
        fprintf(stderr, "program 'tc_ingress' not found\n");
        err = -ENOENT;
        goto cleanup_obj;
    }

    map = bpf_object__find_map_by_name(obj, "latency_hist");
    if (!map) {
        fprintf(stderr, "map 'latency_hist' not found\n");
        err = -ENOENT;
        goto cleanup_obj;
    }
    map_fd = bpf_map__fd(map);

    /*
     * Phase 4 — Create TC hook
     * Creates the clsact qdisc on lo.
     * Equivalent to: tc qdisc add dev lo clsact
     *
     * EEXIST means the qdisc already existed before we ran.
     !!* Critical: if we didn't create it, we must NOT destroy it on exit.
     !!* Destroying someone else's qdisc silently removes all their filters.
     *
     * Go/cilium equivalent: netlink.QdiscAdd() or TCX link setup
     */
    hook.ifindex      = (int)if_nametoindex("lo");
    hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&hook);
    if (err == -EEXIST) {
        err = 0;
    } else if (err) {
        fprintf(stderr, "tc hook create failed: %s\n", strerror(-err));
        goto cleanup_obj;
    } else {
        hook_created = true;
    }

    /*
     * Phase 5 — Attach
     * Installs the BPF program as a TC filter on lo ingress.
     * Equivalent to: tc filter add dev lo ingress bpf ... direct-action
     *
     * After success, opts.handle and opts.priority are populated by libbpf.
     * You MUST pass this same opts to bpf_tc_detach() — it identifies
     * which filter to remove. Don't zero it out.
     *
     * Go/cilium equivalent: link.AttachTCX() or netlink filter add
     */
    opts.prog_fd = bpf_program__fd(prog);
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "tc attach failed: %s\n", strerror(-err));
        goto cleanup_hook;
    }

    printf("Attached to lo ingress. Ctrl-C to stop.\n\n");
    printf("In another terminal:\n");
    printf("  sudo tcpdump -i lo -n > /dev/null &\n");
    printf("  ping -c 20 127.0.0.1\n");

    /* Phase 6 — Poll */
    while (running) {
        sleep(2);
        print_histogram(map_fd);
    }

    /*
     * Phase 7 — Cleanup
     * Detach filter first, then conditionally destroy the qdisc.
     * opts still holds handle+priority from the attach call.
     * bpf_object__close() closes all prog and map fds.
     */
    printf("\nDetaching...\n");
    bpf_tc_detach(&hook, &opts);

cleanup_hook:
    if (hook_created)
        bpf_tc_hook_destroy(&hook);

cleanup_obj:
    bpf_object__close(obj);
    return err ? 1 : 0;
}
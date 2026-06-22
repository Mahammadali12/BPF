#include <bpf/bpf.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static const char *labels[] = {
    "< 10 µs      ",
    "10 - 100 µs  ",
    "100 - 500 µs ",
    "500 µs - 1 ms",
    "> 1 ms       ",
    "no tstamp    ",
};

int main(void)
{
    int map_fd;
    uint32_t key;
    uint64_t val;
    uint64_t total = 0;

    map_fd = bpf_obj_get("/sys/fs/bpf/maps/latency_hist");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    /* First pass: get total for percentage */
    for (key = 0; key < 6; key++) {
        val = 0;
        bpf_map_lookup_elem(map_fd, &key, &val);
        total += val;
    }

    printf("\nLatency histogram — lo ingress (%llu packets total)\n",
           (unsigned long long)total);
    printf("%-16s  %10s  %6s\n", "Bucket", "Count", "%%");
    printf("%-16s  %10s  %6s\n", "------", "-----", "--");

    for (key = 0; key < 6; key++) {
        val = 0;
        bpf_map_lookup_elem(map_fd, &key, &val);
        double pct = total ? (100.0 * val / total) : 0.0;
        printf("%-16s  %10llu  %5.1f%%\n",
               labels[key], (unsigned long long)val, pct);
    }

    return 0;
}
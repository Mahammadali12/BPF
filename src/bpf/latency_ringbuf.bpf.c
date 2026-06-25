#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

struct event {
    __u64 tstamp;     /* original skb->tstamp, 0 if unset */
    __u64 now;     
    __u64 delta_ns;   /* now - tstamp, 0 if tstamp was 0 */
    __u32 pkt_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* must be power of 2, kernel enforces */
} events SEC(".maps");

SEC("classifier")
int tc_ingress(struct __sk_buff *skb)
{
    struct event *e;
    __u64 tstamp = skb->tstamp;
    // __u64 now = bpf_ktime_get_ns();
    __u64 now = bpf_ktime_get_tai_ns();
    __u64 delta = 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;   /* buffer full — drop the event, never drop the packet */

    if (tstamp != 0) 
        delta = (now >= tstamp) ? (now - tstamp) : 0;

    e->tstamp   = tstamp;
    e->now      = now;
    e->delta_ns = delta;
    e->pkt_len  = skb->len;

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0

/*
 * Buckets:
 * 0: < 10 µs
 * 1: 10–100 µs
 * 2: 100–500 µs
 * 3: 500 µs – 1 ms
 * 4: > 1 ms
 * 5: skb->tstamp was 0 (packet not timestamped)
 */


struct 
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries,6);
    __type(key, __u32);
    __type(value, __u64);
    
} latency_hist SEC(".maps");


SEC("classifier")
int tc_ingress(struct __sk_buff *skb)
{
    __u64 timestamp = skb->tstamp;
    __u32 bucket;
    __u64 *val;

    if (timestamp == 0)
        bucket = 5;
    else {
        __u64 now = bpf_ktime_get_ns();
        __u64 delta = (now >= timestamp) ? (now - timestamp) : 0;

        if (delta < 10000ULL)        bucket = 0;
        else if (delta < 100000ULL)  bucket = 1;
        else if (delta < 500000ULL)  bucket = 2;
        else if (delta < 1000000ULL) bucket = 3;
        else                         bucket = 4;
    }

    val = bpf_map_lookup_elem(&latency_hist,&bucket);
    if(val)
        __sync_fetch_and_add(val,1);
    
    return TC_ACT_OK;

}

char _license[] SEC("license") = "GPL";
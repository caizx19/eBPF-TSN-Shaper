#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_qdisc_common.h"

char _license[] SEC("license") = "GPL";

/* EXTERNAL KFUNCS DECLARATION */
extern void bpf_qdisc_set_tstamp(struct sk_buff *skb, u64 tstamp) __ksym;

static __always_inline struct qdisc_skb_cb *qdisc_skb_cb(const struct sk_buff *skb)
{
    return (struct qdisc_skb_cb *)skb->cb;
}

/* ATS core definitions */
#define NUM_QUEUES 4
#define RATE_NS_PER_BYTE 381  /* Shaping rate: around 21Mbps */
#define MAX_BURST_BYTES 128   /* Max tolerance */
#define MAX_BURST_TIME_NS (MAX_BURST_BYTES * RATE_NS_PER_BYTE)

/* Map definition */
struct ats_queue {
    struct bpf_spin_lock lock;
    struct bpf_list_head root __contains_kptr(sk_buff, bpf_list);
    u64 last_eligibility_time; 
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct ats_queue);
    __uint(max_entries, NUM_QUEUES);
} ats_queues SEC(".maps");

SEC("struct_ops/bpf_ats_enqueue")
int BPF_PROG(bpf_ats_enqueue, struct sk_buff *skb, struct Qdisc *sch, struct bpf_sk_buff_ptr *to_free)
{
    u32 prio = skb->priority;
    u32 key = prio & (NUM_QUEUES - 1);
    struct ats_queue *q;
    u64 now, eligibility_time, pkt_duration, burst_thresh, send_time;

    if (sch->q.qlen >= sch->limit) {
        sch->qstats.drops++;
        bpf_qdisc_skb_drop(skb, to_free);
        return NET_XMIT_DROP;
    }

    q = bpf_map_lookup_elem(&ats_queues, &key);
    if (!q) {
        sch->qstats.drops++;
        bpf_qdisc_skb_drop(skb, to_free);
        return NET_XMIT_DROP;
    }

    now = bpf_ktime_get_ns();
    pkt_duration = (u64)qdisc_skb_cb(skb)->pkt_len * RATE_NS_PER_BYTE;

    bpf_spin_lock(&q->lock);
    
    /* Credit cap */
    burst_thresh = (now > MAX_BURST_TIME_NS) ? (now - MAX_BURST_TIME_NS) : 0;

    if (q->last_eligibility_time < burst_thresh) {
        q->last_eligibility_time = burst_thresh;
    }

    eligibility_time = q->last_eligibility_time + pkt_duration;
    q->last_eligibility_time = eligibility_time;
    
    bpf_spin_unlock(&q->lock);

    send_time = (eligibility_time > now) ? eligibility_time : now;
    
    /* ZERO OVERHEAD TIMESTAMPING */
    bpf_qdisc_set_tstamp(skb, send_time);

    /* DIRECT INSERTION: No allocation, just link the skb */
    bpf_spin_lock(&q->lock);
    bpf_list_push_back(&q->root, &skb->bpf_list);
    bpf_spin_unlock(&q->lock);

    sch->q.qlen++;
    sch->qstats.backlog += qdisc_skb_cb(skb)->pkt_len;

    return NET_XMIT_SUCCESS;
}

SEC("struct_ops/bpf_ats_dequeue")
struct sk_buff *BPF_PROG(bpf_ats_dequeue, struct Qdisc *sch)
{
    u64 now = bpf_ktime_get_ns();
    struct ats_queue *q;
    struct bpf_list_node *node;
    struct sk_buff *skb;

    for (int i = 0; i < NUM_QUEUES; i++) {
        u32 key = i;
        q = bpf_map_lookup_elem(&ats_queues, &key);
        if (!q) continue;

        bpf_spin_lock(&q->lock);
        
        node = bpf_list_pop_front(&q->root);
        if (node) {
            skb = container_of(node, struct sk_buff, bpf_list);
            
            if (skb->tstamp <= now) {
                bpf_spin_unlock(&q->lock);
                sch->q.qlen--;
                sch->qstats.backlog -= qdisc_skb_cb(skb)->pkt_len;
                bpf_qdisc_bstats_update(sch, skb);
                return skb;
            } else {
                bpf_list_push_front(&q->root, &skb->bpf_list);
                bpf_qdisc_watchdog_schedule(sch, skb->tstamp, 0);
                bpf_spin_unlock(&q->lock);
            }
        } else {
            bpf_spin_unlock(&q->lock);
        }
    }
    return NULL;
}

static int reset_ats_queue(u32 index, void *ctx)
{
    struct ats_queue *q = bpf_map_lookup_elem(&ats_queues, &index);
    struct bpf_list_node *node; 
    struct sk_buff *skb;

    if (!q) return 0;

    bpf_spin_lock(&q->lock);
    while ((node = bpf_list_pop_front(&q->root))) {
        skb = container_of(node, struct sk_buff, bpf_list);
        bpf_kfree_skb(skb);
    }
    q->last_eligibility_time = 0;
    bpf_spin_unlock(&q->lock);
    return 0;
}

SEC("struct_ops/bpf_ats_reset")
void BPF_PROG(bpf_ats_reset, struct Qdisc *sch)
{
    bpf_loop(NUM_QUEUES, reset_ats_queue, NULL, 0);
    sch->q.qlen = 0;
    sch->qstats.backlog = 0;
}

SEC("struct_ops/bpf_ats_init")
int BPF_PROG(bpf_ats_init, struct Qdisc *sch, struct nlattr *opt,
             struct netlink_ext_ack *extack)
{
    return 0;
}

SEC(".struct_ops")
struct Qdisc_ops ats_direct = {
    .enqueue   = (void *)bpf_ats_enqueue,
    .dequeue   = (void *)bpf_ats_dequeue,
    .reset     = (void *)bpf_ats_reset,
    .init      = (void *)bpf_ats_init,
    .id        = "bpf_ats_direct",
};

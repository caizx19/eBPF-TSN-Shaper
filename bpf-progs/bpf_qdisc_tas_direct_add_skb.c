// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include "bpf_qdisc_common.h"

char _license[] SEC("license") = "GPL";

#define NSEC_PER_USEC 1000L
#define NSEC_PER_SEC 1000000000L
#define NUM_PRIOS 16
#define MAX_QLEN 10000
#define GCL_NUM 2

/* EXTERNAL KFUNCS DECLARATION */
extern void bpf_qdisc_set_tstamp(struct sk_buff *skb, u64 tstamp) __ksym;

/* Queue Definition: Head points DIRECTLY to sk_buffs */
struct prio_queue {
	struct bpf_spin_lock lock;
	struct bpf_list_head head __contains_kptr(sk_buff, bpf_list);
	u32 qlen;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUM_PRIOS);
	__type(key, u32);
	__type(value, struct prio_queue);
} tas_queues SEC(".maps");

struct tas_prio_stats {
	u64 drops;
	u64 sent;
	u64 total_latency_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NUM_PRIOS);
	__type(key, u32);
	__type(value, struct tas_prio_stats);
} tas_stats SEC(".maps");

struct gcl_entry {
	u64 duration_ns;
	u16 gate_mask;
};

struct gcl_loop_ctx {
	u64 offset;
	u64 accum;
	u16 *mask;
	u64 *slot_end_rel;
};

struct tas_data {
	u64 base_time;
	u64 cycle_time;
	u32 num_entries;
	u32 timer_slack;
};

private(A) struct tas_data q;

const struct gcl_entry gcl[] SEC(".rodata") = {
    {10000, 0x8001},
    {990000, 0x0001},
};


SEC("struct_ops/bpf_tas_enqueue")
int BPF_PROG(bpf_tas_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	u32 pri = skb->priority & (NUM_PRIOS - 1);
	struct prio_queue *pq;
	u32 key = pri;
	struct tas_prio_stats *stats;

	stats = bpf_map_lookup_elem(&tas_stats, &key);
	if (!stats)
		goto drop;

	if (sch->q.qlen >= sch->limit)
		goto drop_with_stats;

	pq = bpf_map_lookup_elem(&tas_queues, &key);
	if (!pq)
		goto drop_with_stats;

	sch->qstats.backlog += qdisc_pkt_len(skb);

	/* * ZERO OVERHEAD TIMESTAMPING 
	 * 1. Get current time.
	 * 2. Write it directly to skb->tstamp using kfuncs.
	 */
	u64 now = bpf_ktime_get_tai_ns();
	bpf_qdisc_set_tstamp(skb, now);

	bpf_spin_lock(&pq->lock);
	
	/* DIRECT INSERTION: No allocation, just link the skb */
	bpf_list_excl_push_back(&pq->head, &skb->bpf_list);
	
	pq->qlen++;
	bpf_spin_unlock(&pq->lock);

	sch->q.qlen++;

	return NET_XMIT_SUCCESS;

drop_with_stats:
	__sync_fetch_and_add(&stats->drops, 1);
drop:
	bpf_qdisc_skb_drop(skb, to_free);
	sch->qstats.drops++;
	return NET_XMIT_DROP;
}

static int find_gcl_entry(u32 index, struct gcl_loop_ctx *ctx)
{
	u64 dur;

	if (index >= GCL_NUM) return 1; 

	dur = gcl[index].duration_ns;
	if (ctx->offset < ctx->accum + dur) {
		*ctx->mask = gcl[index].gate_mask;
		*ctx->slot_end_rel = ctx->accum + dur;
		return 1; 
	}
	ctx->accum += dur;

	return 0; 
}

SEC("struct_ops/bpf_tas_dequeue")
struct sk_buff *BPF_PROG(bpf_tas_dequeue, struct Qdisc *sch)
{
	struct sk_buff *skb = NULL;
	struct bpf_list_excl_node *node;
	u64 now, offset;
	u64 slot_end_rel = 0;
	u16 mask = 0;
	int pri;

	if (!sch->q.qlen)
		return NULL;

	now = bpf_ktime_get_tai_ns();
	if (q.cycle_time == 0)
		return NULL;

	offset = (now - q.base_time) % q.cycle_time;

	struct gcl_loop_ctx lctx = {
		.offset = offset,
		.accum = 0,
		.mask = &mask,
		.slot_end_rel = &slot_end_rel,
	};
	bpf_loop(q.num_entries, find_gcl_entry, &lctx, 0);

	if (mask == 0)
		goto schedule_next;

	bpf_for(pri, 0, NUM_PRIOS) {
		int actual_pri = NUM_PRIOS - 1 - pri;
		if (mask & (1u << actual_pri)) {
			u32 key = actual_pri;
			struct prio_queue *pq = bpf_map_lookup_elem(&tas_queues, &key);

			if (pq && pq->qlen > 0) {
				bpf_spin_lock(&pq->lock);
				node = bpf_list_excl_pop_front(&pq->head);
				if (node) pq->qlen--;
				bpf_spin_unlock(&pq->lock);

				if (node) {
					/* Get skb back from list node */
					skb = container_of(node, struct sk_buff, bpf_list);

					/* * ZERO OVERHEAD STATS
					 * Read tstamp directly. Reading is allowed by verifier.
					 */
					u64 enqueue_time = skb->tstamp;
					u64 latency_ns = now - enqueue_time;
					
					u32 stats_key = actual_pri;
					struct tas_prio_stats *stats = bpf_map_lookup_elem(&tas_stats, &stats_key);
					if (stats) {
						__sync_fetch_and_add(&stats->sent, 1);
						__sync_fetch_and_add(&stats->total_latency_ns, latency_ns);
					}

					sch->q.qlen--;
					sch->qstats.backlog -= qdisc_pkt_len(skb);
					bpf_qdisc_bstats_update(sch, skb);
					return skb;
				}
			}
		}
	}

schedule_next:
	if (sch->q.qlen > 0) {
		u64 current_cycle_start = now - offset;
		u64 next_event = current_cycle_start + slot_end_rel;
		if (next_event <= now)
			next_event += q.cycle_time;
		bpf_qdisc_watchdog_schedule(sch, next_event, q.timer_slack);
	}

	return NULL;
}

struct drain_ctx {
	struct prio_queue *pq;
};

static int drain_one(u32 idx, struct drain_ctx *ctx)
{
	struct bpf_list_excl_node *node;
	struct sk_buff *skb;

	bpf_spin_lock(&ctx->pq->lock);
	node = bpf_list_excl_pop_front(&ctx->pq->head);
	bpf_spin_unlock(&ctx->pq->lock);

	if (!node) return 1; 

	skb = container_of(node, struct sk_buff, bpf_list);
	
	/* Release directly (no wrapper) */
	bpf_kfree_skb(skb);

	return 0; 
}

static int clear_stats_map(u32 index, void *ctx)
{
	u32 key = index;
	struct tas_prio_stats zero_stats = {};
	bpf_map_update_elem(&tas_stats, &key, &zero_stats, 0);
	return 0;
}

static int tas_drop_queue(u32 index, void *ctx)
{
	u32 key = index;
	struct prio_queue *pq = bpf_map_lookup_elem(&tas_queues, &key);
	struct drain_ctx dctx = { .pq = pq };

	if (!pq) return 0;

	bpf_loop(MAX_QLEN + 1, drain_one, &dctx, 0);

	bpf_spin_lock(&pq->lock);
	pq->qlen = 0;
	bpf_spin_unlock(&pq->lock);

	return 0;
}

SEC("struct_ops/bpf_tas_reset")
void BPF_PROG(bpf_tas_reset, struct Qdisc *sch)
{
	sch->q.qlen = 0;
	sch->qstats.backlog = 0;
	bpf_loop(NUM_PRIOS, tas_drop_queue, NULL, 0);
	bpf_loop(NUM_PRIOS, clear_stats_map, NULL, 0);
}

SEC("struct_ops/bpf_tas_init")
int BPF_PROG(bpf_tas_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	q.base_time = 0;
	q.cycle_time = 1000000;
	q.num_entries = GCL_NUM;
	q.timer_slack = 1 * NSEC_PER_USEC;
	sch->limit = MAX_QLEN;
	return 0;
}

SEC("struct_ops")
void BPF_PROG(bpf_tas_destroy, struct Qdisc *sch) {}

SEC(".struct_ops")
struct Qdisc_ops tas_direct = {
	.enqueue   = (void *)bpf_tas_enqueue,
	.dequeue   = (void *)bpf_tas_dequeue,
	.reset     = (void *)bpf_tas_reset,
	.init      = (void *)bpf_tas_init,
	.destroy   = (void *)bpf_tas_destroy,
	.id        = "bpf_tas_direct",
};

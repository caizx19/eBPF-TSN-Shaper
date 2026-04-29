// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "bpf_experimental.h"
#include "bpf_qdisc_common.h"

char _license[] SEC("license") = "GPL";

/* Queue Definition: Head points DIRECTLY to sk_buffs */
private(A) struct bpf_spin_lock q_fifo_lock;
private(A) struct bpf_list_head q_fifo __contains_kptr(sk_buff, bpf_list);

bool init_called;

SEC("struct_ops/bpf_fifo_enqueue")
int BPF_PROG(bpf_fifo_enqueue, struct sk_buff *skb, struct Qdisc *sch,
	     struct bpf_sk_buff_ptr *to_free)
{
	u32 pkt_len;

	if (sch->q.qlen == sch->limit)
		goto drop;

	pkt_len = qdisc_pkt_len(skb);

	bpf_spin_lock(&q_fifo_lock);
	
	/* DIRECT INSERTION: No allocation, just link the skb */
	bpf_list_excl_push_back(&q_fifo, &skb->bpf_list);
	bpf_spin_unlock(&q_fifo_lock);

	sch->q.qlen++;
	sch->qstats.backlog += pkt_len;
	return NET_XMIT_SUCCESS;
drop:
	bpf_qdisc_skb_drop(skb, to_free);
	return NET_XMIT_DROP;
}

SEC("struct_ops/bpf_fifo_dequeue")
struct sk_buff *BPF_PROG(bpf_fifo_dequeue, struct Qdisc *sch)
{
	struct bpf_list_excl_node *node;
	struct sk_buff *skb = NULL;

	bpf_spin_lock(&q_fifo_lock);

	node = bpf_list_excl_pop_front(&q_fifo);
	bpf_spin_unlock(&q_fifo_lock);
	if (!node)
		return NULL;

	skb = container_of(node, struct sk_buff, bpf_list);

	sch->qstats.backlog -= qdisc_pkt_len(skb);
	bpf_qdisc_bstats_update(sch, skb);
	sch->q.qlen--;

	return skb;
}

SEC("struct_ops/bpf_fifo_init")
int BPF_PROG(bpf_fifo_init, struct Qdisc *sch, struct nlattr *opt,
	     struct netlink_ext_ack *extack)
{
	sch->limit = 1000;
	init_called = true;
	return 0;
}

SEC("struct_ops/bpf_fifo_reset")
void BPF_PROG(bpf_fifo_reset, struct Qdisc *sch)
{
	struct bpf_list_excl_node *node;
	int i;

	bpf_for(i, 0, sch->q.qlen) {
		struct sk_buff *skb;

		bpf_spin_lock(&q_fifo_lock);
		node = bpf_list_excl_pop_front(&q_fifo);
		bpf_spin_unlock(&q_fifo_lock);

		if (!node)
			break;

		skb = container_of(node, struct sk_buff, bpf_list);
		bpf_kfree_skb(skb);
	}
	sch->q.qlen = 0;
}

SEC("struct_ops")
void BPF_PROG(bpf_fifo_destroy, struct Qdisc *sch)
{
}

SEC(".struct_ops")
struct Qdisc_ops fifo = {
	.enqueue   = (void *)bpf_fifo_enqueue,
	.dequeue   = (void *)bpf_fifo_dequeue,
	.init      = (void *)bpf_fifo_init,
	.reset     = (void *)bpf_fifo_reset,
	.destroy   = (void *)bpf_fifo_destroy,
	.id        = "bpf_fifo_direct",
};

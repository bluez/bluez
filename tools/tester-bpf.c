// SPDX-License-Identifier: GPL-2.0
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Pauli Virtanen
 *
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif

#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif

#include "tester-bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} tx_tstamp_events SEC(".maps");

static inline void tx_tstamp_event_emit(__u32 type, __u32 tskey)
{
	struct tx_tstamp_event *event;

	event = bpf_ringbuf_reserve(&tx_tstamp_events, sizeof(*event), 0);
	if (!event)
		return;

	event->type = type;
	event->id = tskey;
	event->nsec = bpf_ktime_get_ns();

	bpf_ringbuf_submit(event, 0);
}

SEC("sockops")
int skops_sockopt(struct bpf_sock_ops *skops)
{
	struct bpf_sock *bpf_sk = skops->sk;
	struct bpf_sock_ops_kern *skops_kern;
	struct skb_shared_info *shinfo;
	const struct sk_buff *skb;

	if (!bpf_sk)
		return 1;

	if (skops->family != AF_BLUETOOTH)
		return 1;

	skops_kern = bpf_cast_to_kern_ctx(skops);
	skb = skops_kern->skb;
	shinfo = bpf_core_cast(skb->head + skb->end, struct skb_shared_info);

	switch (skops->op) {
	case BPF_SOCK_OPS_TSTAMP_SENDMSG_CB:
		bpf_sock_ops_enable_tx_tstamp(skops_kern, 0);
		break;
	case BPF_SOCK_OPS_TSTAMP_SCHED_CB:
		tx_tstamp_event_emit(SCM_TSTAMP_SCHED, shinfo->tskey);
		break;
	case BPF_SOCK_OPS_TSTAMP_SND_SW_CB:
		tx_tstamp_event_emit(SCM_TSTAMP_SND, shinfo->tskey);
		break;
	case BPF_SOCK_OPS_TSTAMP_ACK_CB:
		tx_tstamp_event_emit(SCM_TSTAMP_ACK, shinfo->tskey);
		break;
	case BPF_SOCK_OPS_TSTAMP_COMPLETION_CB:
		tx_tstamp_event_emit(SCM_TSTAMP_COMPLETION, shinfo->tskey);
		break;
	}

	return 1;
}

SEC("cgroup/setsockopt")
int _setsockopt(struct bpf_sockopt *ctx)
{
	if (ctx->level == SOL_CUSTOM_TESTER) {
		int flag = SK_BPF_CB_TX_TIMESTAMPING;

		bpf_setsockopt(ctx->sk, SOL_SOCKET,
			SK_BPF_CB_FLAGS, &flag, sizeof(flag));

		ctx->optlen = -1;
		return 1;
	}

	return 1;
}

char _license[] SEC("license") = "GPL";

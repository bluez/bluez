// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation.
 *
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>

#include <glib.h>

#ifdef HAVE_BPF
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include "tester-bpf.h"
#include "tester-skel.h"
#endif

#define SEC_NSEC(_t)  ((_t) * 1000000000ULL)
#define TS_NSEC(_ts)  (SEC_NSEC((_ts)->tv_sec) + (_ts)->tv_nsec)

#if !HAVE_DECL_SOF_TIMESTAMPING_TX_COMPLETION
#define SOF_TIMESTAMPING_TX_COMPLETION	(1 << 18)
#endif
#if !HAVE_DECL_SCM_TSTAMP_COMPLETION
#define SCM_TSTAMP_COMPLETION		(SCM_TSTAMP_ACK + 1)
#endif
#define TS_TX_RECORD_MASK		(SOF_TIMESTAMPING_TX_RECORD_MASK | \
						SOF_TIMESTAMPING_TX_COMPLETION)

struct tx_tstamp_data {
	struct {
		uint32_t id;
		uint32_t type;
	} expect[16];
	unsigned int pos;
	unsigned int count;
	unsigned int sent;
	uint32_t so_timestamping;
	bool stream;
	bool bpf;
#ifdef HAVE_BPF
	struct tester_bpf *skel;
	struct ring_buffer *buf;
	int cgroup_fd;
	int bpf_err;
#endif
};

static inline void tx_tstamp_init(struct tx_tstamp_data *data,
				uint32_t so_timestamping, bool stream, bool bpf)
{
	memset(data, 0, sizeof(*data));
	memset(data->expect, 0xff, sizeof(data->expect));

	data->so_timestamping = so_timestamping;
	data->stream = stream;
	data->bpf = bpf;
}

static inline int tx_tstamp_expect(struct tx_tstamp_data *data, size_t len)
{
	unsigned int pos = data->count;
	int steps;

	if (data->stream && len)
		data->sent += len - 1;

	if (data->bpf) {
		bool have_tskey =
			data->so_timestamping & SOF_TIMESTAMPING_OPT_ID &&
			data->so_timestamping & SOF_TIMESTAMPING_TX_RECORD_MASK;

		g_assert(pos + 2 <= ARRAY_SIZE(data->expect));
		data->expect[pos].type = SCM_TSTAMP_SND;
		data->expect[pos].id = have_tskey ? data->sent : 0;
		pos++;
		data->expect[pos].type = SCM_TSTAMP_COMPLETION;
		data->expect[pos].id = have_tskey ? data->sent : 0;
		pos++;
		goto done;
	}

	if (data->so_timestamping & SOF_TIMESTAMPING_TX_SCHED) {
		g_assert(pos < ARRAY_SIZE(data->expect));
		data->expect[pos].type = SCM_TSTAMP_SCHED;
		data->expect[pos].id = data->sent;
		pos++;
	}

	if (data->so_timestamping & SOF_TIMESTAMPING_TX_SOFTWARE) {
		g_assert(pos < ARRAY_SIZE(data->expect));
		data->expect[pos].type = SCM_TSTAMP_SND;
		data->expect[pos].id = data->sent;
		pos++;
	}

	if (data->so_timestamping & SOF_TIMESTAMPING_TX_COMPLETION) {
		g_assert(pos < ARRAY_SIZE(data->expect));
		data->expect[pos].type = SCM_TSTAMP_COMPLETION;
		data->expect[pos].id = data->sent;
		pos++;
	}

done:
	if (!data->stream || len)
		data->sent++;

	steps = pos - data->count;
	data->count = pos;
	return steps;
}

static inline int tx_tstamp_validate(struct tx_tstamp_data *data,
				const char *source, uint32_t type, uint32_t id,
				uint64_t nsec, uint64_t now)
{
	unsigned int i;

	if (now < nsec || now > nsec + SEC_NSEC(10)) {
		tester_warn("nonsense in timestamp");
		return -EINVAL;
	}

	if (data->pos >= data->count) {
		tester_warn("Too many timestamps");
		return -EINVAL;
	}

	/* Find first unreceived timestamp of the right type */
	for (i = 0; i < data->count; ++i) {
		if (data->expect[i].type >= 0xffff)
			continue;

		if (type == data->expect[i].type) {
			data->expect[i].type = 0xffff;
			break;
		}
	}
	if (i == data->count) {
		tester_warn("Bad timestamp type %u", type);
		return -EINVAL;
	}

	if ((data->so_timestamping & SOF_TIMESTAMPING_OPT_ID || data->bpf) &&
				id != data->expect[i].id) {
		tester_warn("Bad timestamp id %u", id);
		return -EINVAL;
	}

	tester_print("Got valid %s TX timestamp %u (type %u, id %u)",
							source, i, type, id);

	++data->pos;

	return data->count - data->pos;
}

static inline int tx_tstamp_recv(struct tx_tstamp_data *data, int sk, int len)
{
	unsigned char control[512];
	ssize_t ret;
	char buf[1024];
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct scm_timestamping *tss = NULL;
	struct sock_extended_err *serr = NULL;
	struct timespec now;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	ret = recvmsg(sk, &msg, MSG_ERRQUEUE);
	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return data->count - data->pos;

		tester_warn("Failed to read from errqueue: %s (%d)",
							strerror(errno), errno);
		return -EINVAL;
	}

	if (data->so_timestamping & SOF_TIMESTAMPING_OPT_TSONLY) {
		if (ret != 0) {
			tester_warn("Packet copied back to errqueue");
			return -EINVAL;
		}
	} else if (len > ret) {
		tester_warn("Packet not copied back to errqueue: %zd", ret);
		return -EINVAL;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
					cmsg->cmsg_type == SCM_TIMESTAMPING) {
			tss = (void *)CMSG_DATA(cmsg);
		} else if (cmsg->cmsg_level == SOL_BLUETOOTH &&
					cmsg->cmsg_type == BT_SCM_ERROR) {
			serr = (void *)CMSG_DATA(cmsg);
		}
	}

	if (!tss) {
		tester_warn("SCM_TIMESTAMPING not found");
		return -EINVAL;
	}

	if (!serr) {
		tester_warn("BT_SCM_ERROR not found");
		return -EINVAL;
	}

	if (serr->ee_errno != ENOMSG ||
				serr->ee_origin != SO_EE_ORIGIN_TIMESTAMPING) {
		tester_warn("BT_SCM_ERROR wrong for timestamping");
		return -EINVAL;
	}

	clock_gettime(CLOCK_REALTIME, &now);

	return tx_tstamp_validate(data, "socket", serr->ee_info, serr->ee_data,
					TS_NSEC(tss->ts), TS_NSEC(&now));
}


#ifdef HAVE_BPF

static inline int tx_tstamp_event_handler(void *ctx, void *buf, size_t size)
{
	struct tx_tstamp_data *data = ctx;
	struct tx_tstamp_event *event = buf;
	struct timespec now;

	if (size < sizeof(*event)) {
		tester_warn("Bad BPF event");
		return -EIO;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);

	data->bpf_err = tx_tstamp_validate(data, "BPF", event->type, event->id,
						event->nsec, TS_NSEC(&now));
	return data->bpf_err;
}

static inline int tx_tstamp_bpf_start(struct tx_tstamp_data *data, int sk)
{
	int flag;

	data->cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
	if (data->cgroup_fd < 0) {
		tester_warn("opening cgroup failed");
		goto fail;
	}

	data->skel = tester_bpf__open_and_load();
	if (!data->skel)
		goto fail;

	data->buf = ring_buffer__new(
			bpf_map__fd(data->skel->maps.tx_tstamp_events),
			tx_tstamp_event_handler, data, NULL);
	if (!data->buf) {
		tester_warn("ringbuffer failed");
		goto fail;
	}

	if (tester_bpf__attach(data->skel)) {
		tester_warn("attach failed");
		goto fail;
	}

	data->skel->links.skops_sockopt =
		bpf_program__attach_cgroup(data->skel->progs.skops_sockopt,
							data->cgroup_fd);
	if (!data->skel->links.skops_sockopt) {
		tester_warn("BPF sockops attach cgroup failed");
		goto fail;
	}

	data->skel->links._setsockopt =
		bpf_program__attach_cgroup(data->skel->progs._setsockopt,
							data->cgroup_fd);
	if (!data->skel->links._setsockopt) {
		tester_warn("BPF setsockopt attach cgroup failed");
		goto fail;
	}

	flag = 0;
	if (setsockopt(sk, SOL_CUSTOM_TESTER, 0, &flag, sizeof(flag))) {
		tester_warn("BPF setsockopt failed");
		goto fail;
	}

	tester_print("BPF test program attached");
	return ring_buffer__epoll_fd(data->buf);

fail:
	if (data->buf)
		ring_buffer__free(data->buf);
	if (data->skel)
		tester_bpf__destroy(data->skel);
	if (data->cgroup_fd > 0)
		close(data->cgroup_fd);
	data->buf = NULL;
	data->skel = NULL;
	data->cgroup_fd = 0;
	return -EIO;
}

static inline int tx_tstamp_bpf_process(struct tx_tstamp_data *data, int *step)
{
	int err;

	err = ring_buffer__consume(data->buf);
	if (err < 0) {
		data->bpf_err = err;
	} else if (step) {
		if (*step >= err)
			*step -= err;
		else
			data->bpf_err = -E2BIG;
	}

	return data->bpf_err;
}

static inline void tx_tstamp_teardown(struct tx_tstamp_data *data)
{
	if (data->skel)
		tester_bpf__detach(data->skel);
	if (data->cgroup_fd > 0)
		close(data->cgroup_fd);
	if (data->buf)
		ring_buffer__free(data->buf);
	if (data->skel) {
		tester_bpf__destroy(data->skel);
		tester_print("BPF test program removed");
	}

	data->buf = NULL;
	data->skel = NULL;
	data->cgroup_fd = 0;
}

#else

static inline int tx_tstamp_bpf_start(struct tx_tstamp_data *data, int sk)
{
	tester_warn("Tester compiled without BPF");
	return -EOPNOTSUPP;
}

static inline int tx_tstamp_bpf_process(struct tx_tstamp_data *data, int *step)
{
	return false;
}

static inline void tx_tstamp_teardown(struct tx_tstamp_data *data)
{
}

#endif


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
#include <sys/socket.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <glib.h>

#define SEC_NSEC(_t)  ((_t) * 1000000000LL)
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
};

static inline void tx_tstamp_init(struct tx_tstamp_data *data,
				uint32_t so_timestamping, bool stream)
{
	memset(data, 0, sizeof(*data));
	memset(data->expect, 0xff, sizeof(data->expect));

	data->so_timestamping = so_timestamping;
	data->stream = stream;
}

static inline int tx_tstamp_expect(struct tx_tstamp_data *data, size_t len)
{
	unsigned int pos = data->count;
	int steps;

	if (data->stream && len)
		data->sent += len - 1;

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

	if (!data->stream || len)
		data->sent++;

	steps = pos - data->count;
	data->count = pos;
	return steps;
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
	unsigned int i;

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

	if (TS_NSEC(&now) < TS_NSEC(tss->ts) ||
			TS_NSEC(&now) > TS_NSEC(tss->ts) + SEC_NSEC(10)) {
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

		if (serr->ee_info == data->expect[i].type) {
			data->expect[i].type = 0xffff;
			break;
		}
	}
	if (i == data->count) {
		tester_warn("Bad timestamp type %u", serr->ee_info);
		return -EINVAL;
	}

	if ((data->so_timestamping & SOF_TIMESTAMPING_OPT_ID) &&
				serr->ee_data != data->expect[i].id) {
		tester_warn("Bad timestamp id %u", serr->ee_data);
		return -EINVAL;
	}

	tester_print("Got valid TX timestamp %u (type %u, id %u)", i,
						serr->ee_info, serr->ee_data);

	++data->pos;

	return data->count - data->pos;
}

static inline int rx_timestamp_check(struct msghdr *msg, uint32_t flags,
							int64_t expect_t_hw)
{
	bool soft_tstamp = flags & SOF_TIMESTAMPING_RX_SOFTWARE;
	bool hw_tstamp = flags & SOF_TIMESTAMPING_RX_HARDWARE;
	struct cmsghdr *cmsg;
	struct timespec now;
	int64_t t = 0, t_hw = 0;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		struct scm_timestamping *tss;

		if (cmsg->cmsg_level != SOL_SOCKET)
			continue;
		if (cmsg->cmsg_type != SCM_TIMESTAMPING)
			continue;

		tss = (struct scm_timestamping *)CMSG_DATA(cmsg);
		t = TS_NSEC(&tss->ts[0]);
		t_hw = TS_NSEC(&tss->ts[2]);
		break;
	}

	if (!cmsg) {
		if (!soft_tstamp && !hw_tstamp)
			return 0;
		tester_warn("RX timestamp missing");
		return -EINVAL;
	} else if (!soft_tstamp && !hw_tstamp) {
		tester_warn("Spurious RX timestamp");
		return -EINVAL;
	}

	if (soft_tstamp) {
		clock_gettime(CLOCK_REALTIME, &now);

		if (TS_NSEC(&now) < t || TS_NSEC(&now) > t + SEC_NSEC(10)) {
			tester_warn("Software RX timestamp bad time");
			return -EINVAL;
		}

		tester_print("Got valid RX software timestamp");
	}

	if (hw_tstamp) {
		if (t_hw != expect_t_hw) {
			tester_warn("Bad hardware RX timestamp: %d != %d",
						(int)t_hw, (int)expect_t_hw);
			return -EINVAL;
		}
		tester_print("Got valid hardware RX timestamp");
	}

	return 0;
}

static inline ssize_t recv_tstamp(int sk, void *buf, size_t size, bool tstamp)
{
	union {
		char buf[2 * CMSG_SPACE(sizeof(struct scm_timestamping))];
		struct cmsghdr align;
	} control;
	struct iovec data = {
		.iov_base = buf,
		.iov_len = size
	};
	struct msghdr msg = {
		.msg_iov = &data,
		.msg_iovlen = 1,
		.msg_control = control.buf,
		.msg_controllen = sizeof(control.buf),
	};
	ssize_t ret;

	ret = recvmsg(sk, &msg, 0);
	if (ret < 0 || !tstamp)
		return ret;

	if (rx_timestamp_check(&msg, SOF_TIMESTAMPING_RX_SOFTWARE, 0)) {
		errno = EIO;
		return -1;
	}

	return ret;
}

static inline int rx_timestamping_init(int fd, int flags)
{
	socklen_t len = sizeof(flags);

	if (!(flags & (SOF_TIMESTAMPING_RX_SOFTWARE |
						SOF_TIMESTAMPING_RX_HARDWARE)))
		return 0;

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, len) < 0) {
		tester_warn("failed to set SO_TIMESTAMPING");
		tester_test_failed();
		return -EIO;
	}

	return 0;
}

static inline void test_ethtool_get_ts_info(unsigned int index, int proto,
							bool sco_flowctl)
{
	struct ifreq ifr = {};
	struct ethtool_ts_info cmd = {};
	uint32_t so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_TX_COMPLETION;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, proto);
	if (sk < 0) {
		if (sk == -EPROTONOSUPPORT)
			tester_test_abort();
		else
			tester_test_failed();
		return;
	}

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "hci%u", index);
	ifr.ifr_data = (void *)&cmd;
	cmd.cmd = ETHTOOL_GET_TS_INFO;

	if (ioctl(sk, SIOCETHTOOL, &ifr) == -1) {
		tester_warn("SIOCETHTOOL failed");
		tester_test_failed();
		close(sk);
		return;
	}
	close(sk);

	if (proto == BTPROTO_SCO && !sco_flowctl)
		so_timestamping &= ~SOF_TIMESTAMPING_TX_COMPLETION;

	if (cmd.cmd != ETHTOOL_GET_TS_INFO ||
			cmd.so_timestamping != so_timestamping ||
			cmd.phc_index != -1 ||
			cmd.tx_types != (1 << HWTSTAMP_TX_OFF) ||
			cmd.rx_filters != (1 << HWTSTAMP_FILTER_NONE)) {
		tester_warn("bad ethtool_ts_info");
		tester_test_failed();
		return;
	}

	tester_test_passed();
}

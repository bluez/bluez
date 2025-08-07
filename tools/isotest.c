// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation.
 *  Copyright 2023 NXP
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/sockios.h>
#include <time.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <poll.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"
#include "bluetooth/hci_lib.h"
#include "bluetooth/mgmt.h"
#include "bluetooth/iso.h"

#include "src/shared/util.h"

#define NSEC_USEC(_t) (_t / 1000L)
#define SEC_USEC(_t)  (_t  * 1000000L)
#define TS_USEC(_ts)  (SEC_USEC((_ts)->tv_sec) + NSEC_USEC((_ts)->tv_nsec))
#define ROUND_CLOSEST(_x, _y) (((_x) + (_y / 2)) / (_y))

#define DEFAULT_BIG_ID 0x01
#define DEFAULT_BIS_ID 0x01

#define MAX_DATA_SIZE 0x40000000

/* Test modes */
enum {
	SEND,
	RECV,
	RECONNECT,
	MULTY,
	DUMP,
	CONNECT
};

static unsigned char *buf;

/* Default data size */
static long data_size = 251;

static int mgmt_index = MGMT_INDEX_NONE;
static bdaddr_t bdaddr;
static int bdaddr_type = BDADDR_LE_PUBLIC;

static int defer_setup;
static int sndbuf;
static struct timeval sndto;
static bool quiet;

struct bt_iso_qos *iso_qos;
static bool inout;

static uint8_t num_bis = 1;

struct lookup_table {
	const char *name;
	int flag;
};

static struct lookup_table bdaddr_types[] = {
	{ "le_public",	BDADDR_LE_PUBLIC	},
	{ "le_random",	BDADDR_LE_RANDOM	},
	{ NULL,		0			},
};

static int get_lookup_flag(struct lookup_table *table, char *name)
{
	int i;

	for (i = 0; table[i].name; i++)
		if (!strcasecmp(table[i].name, name))
			return table[i].flag;

	return -1;
}

static void print_lookup_values(struct lookup_table *table, char *header)
{
	int i;

	printf("%s\n", header);

	for (i = 0; table[i].name; i++)
		printf("\t%s\n", table[i].name);
}

static float tv2fl(struct timeval tv)
{
	return (float)tv.tv_sec + (float)(tv.tv_usec/1000000.0);
}

static const uint8_t set_iso_socket_param[] = {
	0x3e, 0xe0, 0xb4, 0xfd, 0xdd, 0xd6, 0x85, 0x98, /* UUID - ISO Socket */
	0x6a, 0x49, 0xe0, 0x05, 0x88, 0xf1, 0xba, 0x6f,
	0x01,						/* Action - enable */
};

static int mgmt_recv(int fd)
{
	uint8_t buf[1024];

	return read(fd, buf, sizeof(buf));
}

static int mgmt_send_cmd(int fd, uint16_t op, uint16_t id, const void *data,
								size_t len)
{
	struct mgmt_hdr hdr;
	struct iovec iov[2];
	int ret;

	memset(&hdr, 0, sizeof(hdr));
	hdr.opcode = htobs(op);
	hdr.index = htobs(id);
	hdr.len = htobs(len);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);

	iov[1].iov_base = (void *)data;
	iov[1].iov_len = len;

	ret = writev(fd, iov, 2);
	if (ret < 0)
		return ret;

	/* Wait for MGMT to respond */
	ret = mgmt_recv(fd);
	if (ret < 0)
		return ret;

	return 0;
}

static int mgmt_open(void)
{
	union {
		struct sockaddr common;
		struct sockaddr_hci hci;
	} addr;
	int fd, err;

	fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
								BTPROTO_HCI);
	if (fd < 0) {
		syslog(LOG_ERR, "Can't create mgmt socket: %s (%d)",
							strerror(errno), errno);
		return -errno;
	}

	syslog(LOG_ERR, "mgmt socket: fd %d", fd);

	memset(&addr, 0, sizeof(addr));
	addr.hci.hci_family = AF_BLUETOOTH;
	addr.hci.hci_dev = HCI_DEV_NONE;
	addr.hci.hci_channel = HCI_CHANNEL_CONTROL;

	if (bind(fd, &addr.common, sizeof(addr.hci)) < 0) {
		syslog(LOG_ERR, "Can't bind mgmt socket: %s (%d)",
							strerror(errno), errno);
		err = -errno;
		close(fd);
		return err;
	}

	return fd;
}


static const uint8_t set_le_param[] = {
	0x01,						/* Action - enable */
};

static int mgmt_set_le(int fd)
{
	int err, index;

	index = mgmt_index;
	if (index == MGMT_INDEX_NONE)
		index = 0;

	err = mgmt_send_cmd(fd, MGMT_OP_SET_LE, index,
				set_le_param, sizeof(set_le_param));
	if (err < 0) {
		syslog(LOG_ERR, "Fail to write mgmt socket: %s (%d)",
							strerror(errno), errno);
		err = -errno;
	}

	syslog(LOG_ERR, "%s: err %d", __func__, err);

	return err < 0 ? err : 0;
}

static int mgmt_set_experimental(void)
{
	int fd, err;

	fd = mgmt_open();
	if (fd < 0)
		return fd;

	err = mgmt_set_le(fd);
	if (err < 0)
		goto fail;

	err = mgmt_send_cmd(fd, MGMT_OP_SET_EXP_FEATURE, MGMT_INDEX_NONE,
			set_iso_socket_param, sizeof(set_iso_socket_param));
	if (err < 0) {
		syslog(LOG_ERR, "Fail to write mgmt socket: %s (%d)",
							strerror(errno), errno);
		err = -errno;
	}

	syslog(LOG_ERR, "%s: err %d", __func__, err);

fail:
	close(fd);

	return err < 0 ? err : 0;
}

static void print_ucast_qos(int sk)
{
	struct bt_iso_qos qos;
	socklen_t len;

	/* Read Out QOS */
	memset(&qos, 0, sizeof(qos));
	len = sizeof(qos);

	if (getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len) < 0) {
		syslog(LOG_ERR, "Can't get QoS socket option: %s (%d)",
				strerror(errno), errno);
		return;
	}

	syslog(LOG_INFO, "QoS CIG 0x%02x CIS 0x%02x Packing 0x%02x "
		"Framing 0x%02x]", qos.ucast.cig, qos.ucast.cis,
		qos.ucast.packing, qos.ucast.framing);

	syslog(LOG_INFO, "Input QoS [Interval %u us Latency %u "
		"ms SDU %u PHY 0x%02x RTN %u]", qos.ucast.in.interval,
		qos.ucast.in.latency, qos.ucast.in.sdu, qos.ucast.in.phy,
		qos.ucast.in.rtn);

	syslog(LOG_INFO, "Output QoS [Interval %u us Latency %u "
		"ms SDU %u PHY 0x%02x RTN %u]", qos.ucast.out.interval,
		qos.ucast.out.latency, qos.ucast.out.sdu, qos.ucast.out.phy,
		qos.ucast.out.rtn);
}

static void print_bcast_qos(int sk)
{
	struct bt_iso_qos qos;
	socklen_t len;

	/* Read Out QOS */
	memset(&qos, 0, sizeof(qos));
	len = sizeof(qos);

	if (getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len) < 0) {
		syslog(LOG_ERR, "Can't get QoS socket option: %s (%d)",
				strerror(errno), errno);
		return;
	}

	syslog(LOG_INFO, "QoS [BIG 0x%02x BIS 0x%02x Packing 0x%02x "
		"Framing 0x%02x Encryption 0x%02x]", qos.bcast.big,
		qos.bcast.bis, qos.bcast.packing, qos.bcast.framing,
		qos.bcast.encryption);

	if (qos.bcast.encryption == 0x01)
		syslog(LOG_INFO, "Broadcast Code 0x%02x 0x%02x 0x%02x 0x%02x "
		"0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x "
		"0x%02x 0x%02x 0x%02x 0x%02x", qos.bcast.bcode[0],
		qos.bcast.bcode[1], qos.bcast.bcode[2], qos.bcast.bcode[3],
		qos.bcast.bcode[4], qos.bcast.bcode[5], qos.bcast.bcode[6],
		qos.bcast.bcode[7], qos.bcast.bcode[8], qos.bcast.bcode[9],
		qos.bcast.bcode[10], qos.bcast.bcode[11], qos.bcast.bcode[12],
		qos.bcast.bcode[13], qos.bcast.bcode[14], qos.bcast.bcode[15]);

	syslog(LOG_INFO, "Input QoS [Interval %u us Latency %u "
		"ms SDU %u PHY 0x%02x RTN %u]", qos.bcast.in.interval,
		qos.bcast.in.latency, qos.bcast.in.sdu,
		qos.bcast.in.phy, qos.bcast.in.rtn);

	syslog(LOG_INFO, "Output QoS [Interval %u us Latency %u "
		"ms SDU %u PHY 0x%02x RTN %u]", qos.bcast.out.interval,
		qos.bcast.out.latency, qos.bcast.out.sdu,
		qos.bcast.out.phy, qos.bcast.out.rtn);
}

static int do_connect(char *peer)
{
	struct sockaddr_iso addr;
	int sk;

	/* Create socket */
	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't create socket: %s (%d)",
							strerror(errno), errno);
		return -1;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.iso_family = AF_BLUETOOTH;
	bacpy(&addr.iso_bdaddr, mgmt_index != MGMT_INDEX_NONE ?
					&bdaddr : BDADDR_ANY);
	addr.iso_bdaddr_type = BDADDR_LE_PUBLIC;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't bind socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Set QoS if available */
	if (iso_qos) {
		if (!inout || !strcmp(peer, "00:00:00:00:00:00")) {
			iso_qos->ucast.in.phy = 0x00;
			iso_qos->ucast.in.sdu = 0;
		}

		if (setsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, iso_qos,
					sizeof(*iso_qos)) < 0) {
			syslog(LOG_ERR, "Can't set QoS socket option: "
					"%s (%d)", strerror(errno), errno);
			goto error;
		}
	}

	/* Enable deferred setup */
	if (defer_setup && setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP,
				&defer_setup, sizeof(defer_setup)) < 0) {
		syslog(LOG_ERR, "Can't enable deferred setup : %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.iso_family = AF_BLUETOOTH;
	str2ba(peer, &addr.iso_bdaddr);
	addr.iso_bdaddr_type = bdaddr_type;

	syslog(LOG_INFO, "Connecting %s ...", peer);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't connect: %s (%d)", strerror(errno),
								errno);
		goto error;
	}

	syslog(LOG_INFO, "Connected [%s]", peer);

	if (!strcmp(peer, "00:00:00:00:00:00"))
		print_bcast_qos(sk);
	else
		print_ucast_qos(sk);

	return sk;

error:
	close(sk);
	return -1;
}

static int *bcast_do_connect_mbis(uint8_t count, char *peer)
{
	int *sk;
	uint8_t sk_cnt = 0;

	sk = malloc(count * sizeof(*sk));
	if (!sk) {
		syslog(LOG_ERR, "Can't allocate socket array");
		return NULL;
	}

	defer_setup = 1;

	for (int i = 0; i < count; i++) {
		if (i == count - 1)
			defer_setup = 0;

		sk[i] = do_connect(peer);
		if (sk[i] < 0) {
			syslog(LOG_ERR, "Can't create socket: %s (%d)",
					strerror(errno), errno);

			goto error;
		}

		sk_cnt++;
	}

	return sk;

error:
	for (int i = 0; i < sk_cnt; i++)
		close(sk[i]);

	free(sk);
	return NULL;

}

static int accept_conn(int sk, struct sockaddr_iso *addr, char *peer)
{
	socklen_t optlen;
	int nsk, err, sk_err;
	struct pollfd fds;
	socklen_t len;

	memset(addr, 0, sizeof(*addr) + sizeof(*addr->iso_bc));
	optlen = sizeof(*addr);

	if (peer)
		optlen += sizeof(*addr->iso_bc);

	nsk = accept(sk, (struct sockaddr *) addr, &optlen);
	if (nsk < 0) {
		syslog(LOG_ERR, "Accept failed: %s (%d)",
						strerror(errno), errno);
		return -1;
	}

	/* Check if connection was successful */
	memset(&fds, 0, sizeof(fds));
	fds.fd = nsk;
	fds.events = POLLERR;

	if (poll(&fds, 1, 0) > 0 && (fds.revents & POLLERR)) {
		len = sizeof(sk_err);

		if (getsockopt(nsk, SOL_SOCKET, SO_ERROR,
					&sk_err, &len) < 0)
			err = -errno;
		else
			err = -sk_err;

		if (err < 0)
			syslog(LOG_ERR, "Connection failed: %s (%d)",
					strerror(-err), -err);

		close(nsk);
		return -1;
	}

	return nsk;
}

static void do_listen(char *filename,
		void (*handler)(int fd, int sk, char *peer),
		char *peer)
{
	struct sockaddr_iso *addr = NULL;
	socklen_t optlen;
	int sk, nsk, fd = -1;
	char ba[18];
	int read_len;

	if (filename) {
		fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (fd < 0) {
			syslog(LOG_ERR, "Can't open file %s: %s\n",
						filename, strerror(errno));
			exit(1);
		}
	}

	mgmt_set_experimental();

	/* Create socket */
	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't create socket: %s (%d)",
							strerror(errno), errno);
		if (fd >= 0)
			close(fd);
		exit(1);
	}

	/* Bind to local address */
	addr = malloc(sizeof(*addr) + sizeof(*addr->iso_bc));
	memset(addr, 0, sizeof(*addr) + sizeof(*addr->iso_bc));
	addr->iso_family = AF_BLUETOOTH;
	bacpy(&addr->iso_bdaddr, mgmt_index != MGMT_INDEX_NONE ?
					&bdaddr : BDADDR_ANY);
	addr->iso_bdaddr_type = BDADDR_LE_PUBLIC;
	optlen = sizeof(*addr);

	if (peer) {
		str2ba(peer, &addr->iso_bc->bc_bdaddr);
		addr->iso_bc->bc_bdaddr_type = bdaddr_type;
		addr->iso_bc->bc_num_bis = num_bis;

		for (int i = 0; i < num_bis; i++)
			addr->iso_bc->bc_bis[i] = i + 1;

		optlen += sizeof(*addr->iso_bc);
	}

	if (bind(sk, (struct sockaddr *) addr, optlen) < 0) {
		syslog(LOG_ERR, "Can't bind socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Enable deferred setup */
	if (defer_setup && setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP,
				&defer_setup, sizeof(defer_setup)) < 0) {
		syslog(LOG_ERR, "Can't enable deferred setup : %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Set QoS if available */
	if (iso_qos) {
		if (setsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, iso_qos,
					sizeof(*iso_qos)) < 0) {
			syslog(LOG_ERR, "Can't set QoS socket option: "
					"%s (%d)", strerror(errno), errno);
			goto error;
		}
	}

	/* Listen for connections */
	if (listen(sk, 10)) {
		syslog(LOG_ERR, "Can not listen on the socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	syslog(LOG_INFO, "Waiting for connection %s...", peer ? peer : "");

	/* Handle deferred setup */
	if (defer_setup && peer) {
		nsk = accept_conn(sk, addr, peer);
		if (nsk < 0)
			goto error;

		close(sk);
		sk = nsk;

		read_len = read(sk, buf, data_size);
		if (read_len < 0)
			syslog(LOG_ERR, "Initial read error: %s (%d)",
						strerror(errno), errno);
		else
			syslog(LOG_INFO, "Initial bytes %d", read_len);
	}

	while (1) {
		nsk = accept_conn(sk, addr, peer);
		if (nsk < 0)
			continue;

		if (fork()) {
			/* Parent */
			close(nsk);
			continue;
		}
		/* Child */
		close(sk);

		ba2str(&addr->iso_bdaddr, ba);
		syslog(LOG_INFO, "Connected [%s]", ba);

		if (peer)
			print_bcast_qos(nsk);
		else
			print_ucast_qos(nsk);

		/* Handle deferred setup */
		if (defer_setup) {
			syslog(LOG_INFO, "Waiting for %d seconds",
							abs(defer_setup) - 1);
			sleep(abs(defer_setup) - 1);

			if (defer_setup < 0) {
				close(nsk);
				exit(1);
			}
		}

		handler(fd, nsk, peer);

		syslog(LOG_INFO, "Disconnect");
		exit(0);
	}

error:
	free(addr);

	if (fd >= 0)
		close(fd);
	close(sk);
	exit(1);
}

static void dump_mode(int fd, int sk, char *peer)
{
	int len;

	if (defer_setup && !peer) {
		len = read(sk, buf, data_size);
		if (len < 0)
			syslog(LOG_ERR, "Initial read error: %s (%d)",
						strerror(errno), errno);
		else
			syslog(LOG_INFO, "Initial bytes %d", len);
	}

	syslog(LOG_INFO, "Receiving ...");
	while ((len = read(sk, buf, data_size)) >= 0) {
		if (fd >= 0) {
			len = write(fd, buf, len);
			if (len < 0) {
				syslog(LOG_ERR, "Write failed: %s (%d)",
						strerror(errno), errno);
				return;
			}
		} else if (!quiet)
			syslog(LOG_INFO, "Received %d bytes", len);
	}
}

static void recv_mode(int fd, int sk, char *peer)
{
	struct timeval tv_beg, tv_end, tv_diff;
	long total;
	int len;
	uint32_t seq;

	if (defer_setup && !peer) {
		len = read(sk, buf, data_size);
		if (len < 0)
			syslog(LOG_ERR, "Initial read error: %s (%d)",
						strerror(errno), errno);
		else
			syslog(LOG_INFO, "Initial bytes %d", len);
	}

	syslog(LOG_INFO, "Receiving ...");

	for (seq = 0; ; seq++) {
		gettimeofday(&tv_beg, NULL);
		total = 0;
		while (total < data_size) {
			int r;

			r = recv(sk, buf, data_size, 0);
			if (r < 0) {
				syslog(LOG_ERR, "Read failed: %s (%d)",
						strerror(errno), errno);

				if (errno != ENOTCONN)
					return;

				r = 0;
			}

			if (fd >= 0) {
				r = write(fd, buf, r);
				if (r < 0) {
					syslog(LOG_ERR, "Write failed: %s (%d)",
							strerror(errno), errno);
					return;
				}
			}

			total += r;
		}
		gettimeofday(&tv_end, NULL);

		timersub(&tv_end, &tv_beg, &tv_diff);

		if (!quiet)
			syslog(LOG_INFO,
				"[seq %d] %ld bytes in %.2f sec speed %.2f "
				"kb/s", seq, total, tv2fl(tv_diff),
				(float)(total * 8 / tv2fl(tv_diff)) / 1024.0);
	}
}

static int open_file(const char *filename)
{
	int fd = -1;

	syslog(LOG_INFO, "Opening %s ...", filename);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		syslog(LOG_ERR, "Can't open file %s: %s\n",
						filename, strerror(errno));
	}

	return fd;
}

static void send_wait(struct timespec *t_start, uint32_t us)
{
	struct timespec t_now;
	struct timespec t_diff;
	int64_t delta_us;

	/* Skip sleep at start */
	if (!us)
		return;

	if (clock_gettime(CLOCK_MONOTONIC, &t_now) < 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}

	t_diff.tv_sec = t_now.tv_sec - t_start->tv_sec;
	if (t_start->tv_nsec > t_now.tv_nsec) {
		t_diff.tv_sec--;
		t_now.tv_nsec += 1000000000L;
	}
	t_diff.tv_nsec = t_now.tv_nsec - t_start->tv_nsec;

	delta_us = us - TS_USEC(&t_diff);

	if (delta_us < 0) {
		syslog(LOG_INFO, "Send is behind: %" PRId64 " us", delta_us);
		delta_us = 1000;
	}

	if (!quiet)
		syslog(LOG_INFO, "Waiting (%" PRId64 " us)...", delta_us);

	usleep(delta_us);

	if (clock_gettime(CLOCK_MONOTONIC, t_start) < 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
}

static int read_stream(int fd, ssize_t count)
{
	ssize_t len, ret = 0;

	while (ret < count) {
		len = read(fd, buf + ret, count - ret);
		if (len < 0)
			return -errno;

		ret += len;
		usleep(1000);
	}

	return ret;
}

static int read_file(int fd, ssize_t count, bool rewind)
{
	ssize_t len;

	if (fd == STDIN_FILENO)
		return read_stream(fd, count);

	len = read(fd, buf, count);
	if (len <= 0) {
		if (!len) {
			if (rewind) {
				lseek(fd, 0, SEEK_SET);
				return read_file(fd, count, rewind);
			}
			return len;
		}

		return -errno;
	}

	return len;
}

static void do_send(int sk, int fd, char *peer, bool repeat)
{
	uint32_t seq;
	struct timespec t_start;
	int send_len, used;
	socklen_t len;
	struct bt_iso_qos qos;
	uint32_t num;
	struct bt_iso_io_qos *out;

	syslog(LOG_INFO, "Sending ...");

	/* Read QoS */
	if (!strcmp(peer, "00:00:00:00:00:00"))
		out = &qos.bcast.out;
	else
		out = &qos.ucast.out;

	memset(&qos, 0, sizeof(qos));
	len = sizeof(qos);
	if (getsockopt(sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len) < 0) {
		syslog(LOG_ERR, "Can't get Output QoS socket option: %s (%d)",
				strerror(errno), errno);
		out->sdu = ISO_DEFAULT_MTU;
	}

	/* num of packets = latency (ms) / interval (us) */
	num = ROUND_CLOSEST(out->latency * 1000, out->interval);
	if (!num)
		num = 1;

	syslog(LOG_INFO, "Number of packets: %d", num);

	if (!sndbuf)
		/* Use socket buffer as a jitter buffer for the entire buffer
		 * latency:
		 * jitter buffer = 2 * (SDU * subevents)
		 */
		sndbuf = 2 * (num * out->sdu);

	len = sizeof(sndbuf);
	if (setsockopt(sk, SOL_SOCKET, SO_SNDBUF, &sndbuf, len) < 0) {
		syslog(LOG_ERR, "Can't set socket SO_SNDBUF option: %s (%d)",
				strerror(errno), errno);
	}

	syslog(LOG_INFO, "Socket jitter buffer: %d buffer", sndbuf);

	if (sndto.tv_usec) {
		len = sizeof(sndto);
		if (setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO, &sndto, len) < 0) {
			syslog(LOG_ERR, "Can't set socket SO_SNDTIMEO option: "
				"%s (%d)", strerror(errno), errno);
		} else {
			syslog(LOG_INFO, "Socket send timeout: %ld usec",
							sndto.tv_usec);
		}
	}

	for (int i = 6; i < out->sdu; i++)
		buf[i] = 0x7f;

	if (clock_gettime(CLOCK_MONOTONIC, &t_start) < 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}

	for (seq = 0; ; seq++) {
		if (fd >= 0) {
			send_len = read_file(fd, out->sdu, repeat);
			if (send_len < 0) {
				syslog(LOG_ERR, "read failed: %s (%d)",
						strerror(-send_len), -send_len);
				exit(1);
			}
		} else
			send_len = out->sdu;

		send_len = send(sk, buf, send_len, 0);
		if (send_len <= 0) {
			syslog(LOG_ERR, "send failed: %s (%d)",
						strerror(errno), errno);
			exit(1);
		}

		ioctl(sk, TIOCOUTQ, &used);

		if (!quiet)
			syslog(LOG_INFO,
				"[seq %d] %d bytes buffered %d (%d bytes)",
				seq, send_len, used / send_len, used);

		if (seq && !((seq + 1) % num))
			send_wait(&t_start, num * out->interval);
	}
}

static void send_mode(char *filename, char *peer, int i, bool repeat)
{
	int sk, fd = -1;
	int *sk_arr;
	uint8_t nconn = strcmp(peer, "00:00:00:00:00:00") ? 1 : num_bis;

	mgmt_set_experimental();

	if (filename) {
		char altername[PATH_MAX];
		struct stat st;
		int err;

		snprintf(altername, PATH_MAX, "%s.%u", filename, i);

		err = stat(altername, &st);
		if (!err)
			fd = open_file(altername);

		if (fd < 0)
			fd = open_file(filename);
	}

	if (nconn > 1) {
		sk_arr = bcast_do_connect_mbis(nconn, peer);
		if (!sk_arr)
			exit(1);

		for (int i = 0; i < nconn; i++) {
			if (fork()) {
				/* Parent */
				continue;
			}

			/* Child */
			do_send(sk_arr[i], fd, peer, repeat);
			exit(0);
		}

		/* Wait for children to exit */
		while (wait(NULL) > 0)
			;

		for (int i = 0; i < nconn; i++)
			close(sk_arr[i]);

		free(sk_arr);
		if (fd >= 0)
			close(fd);
		return;
	}

	sk = do_connect(peer);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't connect to the server: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	if (defer_setup) {
		syslog(LOG_INFO, "Waiting for %d seconds",
			abs(defer_setup) - 1);
		sleep(abs(defer_setup) - 1);
	}

	do_send(sk, fd, peer, repeat);
}

static void reconnect_mode(char *peer)
{
	mgmt_set_experimental();

	while (1) {
		int sk;

		sk = do_connect(peer);
		if (sk < 0) {
			syslog(LOG_ERR, "Can't connect to the server: %s (%d)",
							strerror(errno), errno);
			exit(1);
		}

		close(sk);

		sleep(5);
	}
}

static void multy_connect_mode(char *peer)
{
	mgmt_set_experimental();

	while (1) {
		int i, sk;

		for (i = 0; i < 10; i++) {
			if (fork())
				continue;

			/* Child */
			sk = do_connect(peer);
			if (sk < 0) {
				syslog(LOG_ERR, "Can't connect to the server: "
					"%s (%d)", strerror(errno), errno);
			}
			close(sk);
			exit(0);
		}

		sleep(19);
	}
}

#define QOS_IO(_interval, _latency, _sdu, _phy, _rtn) \
{ \
	.interval = _interval, \
	.latency = _latency, \
	.sdu = _sdu, \
	.phy = _phy, \
	.rtn = _rtn, \
}

#define QOS(_interval, _latency, _sdu, _phy, _rtn) \
{ \
	.bcast = { \
		.big = BT_ISO_QOS_BIG_UNSET, \
		.bis = BT_ISO_QOS_BIS_UNSET, \
		.sync_factor = 0x07, \
		.packing = 0x00, \
		.framing = 0x00, \
		.out = QOS_IO(_interval, _latency, _sdu, _phy, _rtn), \
		.encryption = 0x00, \
		.bcode = {0}, \
		.options = 0x00, \
		.skip = 0x0000, \
		.sync_timeout = 0x4000, \
		.sync_cte_type = 0x00, \
		.mse = 0x00, \
		.timeout = 0x4000, \
	}, \
}

#define QOS_PRESET(_name, _inout, _interval, _latency, _sdu, _phy, _rtn) \
{ \
	.name = _name, \
	.inout = _inout, \
	.qos = QOS(_interval, _latency, _sdu, _phy, _rtn), \
}

static struct qos_preset {
	const char *name;
	bool inout;
	struct bt_iso_qos qos;
} presets[] = {
	/* QoS Configuration settings for low latency audio data */
	QOS_PRESET("8_1_1", true, 7500, 8, 26, 0x02, 2),
	QOS_PRESET("8_2_1", true, 10000, 10, 30, 0x02, 2),
	QOS_PRESET("16_1_1", true, 7500, 8, 30, 0x02, 2),
	QOS_PRESET("16_2_1", true, 10000, 10, 40, 0x02, 2),
	QOS_PRESET("24_1_1", true, 7500, 8, 45, 0x02, 2),
	QOS_PRESET("24_2_1", true, 10000, 10, 60, 0x02, 2),
	QOS_PRESET("32_1_1", true, 7500, 8, 60, 0x02, 2),
	QOS_PRESET("32_2_1", true, 10000, 10, 80, 0x02, 2),
	QOS_PRESET("44_1_1", false, 8163, 24, 98, 0x02, 5),
	QOS_PRESET("44_2_1", false, 10884, 31, 130, 0x02, 5),
	QOS_PRESET("48_1_1", false, 7500, 15, 75, 0x02, 5),
	QOS_PRESET("48_2_1", false, 10000, 20, 100, 0x02, 5),
	QOS_PRESET("48_3_1", false, 7500, 15, 90, 0x02, 5),
	QOS_PRESET("48_4_1", false, 10000, 20, 120, 0x02, 5),
	QOS_PRESET("48_5_1", false, 7500, 15, 117, 0x02, 5),
	QOS_PRESET("44_6_1", false, 10000, 20, 155, 0x02, 5),
	/* QoS Configuration settings for high reliability audio data */
	QOS_PRESET("8_1_2", true, 7500, 75, 26, 0x02, 13),
	QOS_PRESET("8_2_2", true, 10000, 95, 30, 0x02, 13),
	QOS_PRESET("16_1_2", true, 7500, 75, 30, 0x02, 13),
	QOS_PRESET("16_2_2", true, 10000, 95, 40, 0x02, 13),
	QOS_PRESET("24_1_2", true, 7500, 75, 45, 0x02, 13),
	QOS_PRESET("24_2_2", true, 10000, 95, 60, 0x02, 13),
	QOS_PRESET("32_1_2", true, 7500, 75, 60, 0x02, 13),
	QOS_PRESET("32_2_2", true, 10000, 95, 80, 0x02, 13),
	QOS_PRESET("44_1_2", false, 8163, 80, 97, 0x02, 13),
	QOS_PRESET("44_2_2", false, 10884, 85, 130, 0x02, 13),
	QOS_PRESET("48_1_2", false, 7500, 75, 75, 0x02, 13),
	QOS_PRESET("48_2_2", false, 10000, 95, 100, 0x02, 13),
	QOS_PRESET("48_3_2", false, 7500, 75, 90, 0x02, 13),
	QOS_PRESET("48_4_2", false, 10000, 100, 120, 0x02, 13),
	QOS_PRESET("48_5_2", false, 7500, 75, 117, 0x02, 13),
	QOS_PRESET("44_6_2", false, 10000, 100, 155, 0x02, 13),
	/* QoS configuration support setting requirements for the UGG and UGT */
	QOS_PRESET("16_1_gs", true, 7500, 15, 30, 0x02, 1),
	QOS_PRESET("16_2_gs", true, 10000, 20, 40, 0x02, 1),
	QOS_PRESET("32_1_gs", true, 7500, 15, 60, 0x02, 1),
	QOS_PRESET("32_2_gs", true, 10000, 20, 80, 0x02, 1),
	QOS_PRESET("48_1_gs", true, 7500, 15, 75, 0x02, 1),
	QOS_PRESET("48_2_gs", true, 10000, 20, 100, 0x02, 1),
	QOS_PRESET("32_1_gr", true, 7500, 15, 60, 0x02, 1),
	QOS_PRESET("32_2_gr", true, 10000, 20, 80, 0x02, 1),
	QOS_PRESET("48_1_gr", true, 7500, 15, 75, 0x02, 1),
	QOS_PRESET("48_2_gr", true, 10000, 20, 100, 0x02, 1),
	QOS_PRESET("48_3_gr", true, 7500, 15, 90, 0x02, 1),
	QOS_PRESET("48_4_gr", true, 10000, 20, 120, 0x02, 1),
};

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static void usage(void)
{
	printf("isotest - ISO testing\n"
		"Usage:\n");
	printf("\tisotest <mode> [options] [bdaddr] [bdaddr1]...\n");
	printf("Modes:\n"
		"\t-d, --dump [filename]    dump (server)\n"
		"\t-c, --reconnect          reconnect (client)\n"
		"\t-m, --multiple           multiple connects (client)\n"
		"\t-r, --receive [filename] receive (server)\n"
		"\t-s, --send [filename,...] connect and send "
		"(client/broadcaster)\n"
		"\t-n, --silent             connect and be silent (client)\n"
		"Options:\n"
		"\t[-b, --bytes <value>]\n"
		"\t[-i, --device <num>]\n"
		"\t[-j, --jitter <bytes>    socket/jitter buffer]\n"
		"\t[-h, --help]\n"
		"\t[-q, --quiet             disable packet logging]\n"
		"\t[-t, --timeout <usec>    send timeout]\n"
		"\t[-C, --continue]\n"
		"\t[-W, --defer <seconds>]  enable deferred setup\n"
		"\t[-M, --mtu <value>]\n"
		"\t[-S, --sca/adv-interval <value>]\n"
		"\t[-P, --packing <value>]\n"
		"\t[-F, --framing <value>]\n"
		"\t[-I, --interval <useconds>]\n"
		"\t[-L, --latency <mseconds>]\n"
		"\t[-Y, --phy <value>]\n"
		"\t[-R, --rtn <value>]\n"
		"\t[-B, --preset <value>]\n"
		"\t[-G, --CIG/BIG <value>]\n"
		"\t[-T, --CIS/BIS <value>]\n"
		"\t[-V, --type <value>] address type (help for list)\n"
		"\t[-N, --nbis <value>] Number of BISes to create/synchronize to\n");
}

static const struct option main_options[] = {
	{ "dump",      optional_argument, NULL, 'd'},
	{ "reconnect", no_argument,       NULL, 'c'},
	{ "multiple",  no_argument,       NULL, 'm'},
	{ "receive",   optional_argument, NULL, 'r'},
	{ "send",      optional_argument, NULL, 's'},
	{ "silent",    no_argument,       NULL, 'n'},
	{ "bytes",     required_argument, NULL, 'b'},
	{ "index",     required_argument, NULL, 'i'},
	{ "jitter",    required_argument, NULL, 'j'},
	{ "help",      no_argument,       NULL, 'h'},
	{ "quiet",     no_argument,       NULL, 'q'},
	{ "timeout",   required_argument, NULL, 't'},
	{ "continue",  no_argument,       NULL, 'C'},
	{ "defer",     required_argument, NULL, 'W'},
	{ "mtu",       required_argument, NULL, 'M'},
	{ "sca",       required_argument, NULL, 'S'},
	{ "packing",   required_argument, NULL, 'P'},
	{ "framing",   required_argument, NULL, 'F'},
	{ "interval",  required_argument, NULL, 'I'},
	{ "latency",   required_argument, NULL, 'L'},
	{ "phy",       required_argument, NULL, 'Y'},
	{ "rtn",       required_argument, NULL, 'R'},
	{ "preset",    required_argument, NULL, 'B'},
	{ "CIG/BIG",   required_argument, NULL, 'G'},
	{ "CIS/BIS",   required_argument, NULL, 'T'},
	{ "type",      required_argument, NULL, 'V'},
	{ "nbis",      required_argument, NULL, 'N'},
	{}
};

static bool str2hex(const char *str, uint16_t in_len, uint8_t *out,
		uint16_t out_len)
{
	uint16_t i;

	if (in_len < out_len * 2)
		return false;

	if (!strncasecmp(str, "0x", 2))
		str += 2;

	for (i = 0; i < out_len; i++) {
		if (sscanf(&str[i * 2], "%02hhx", &out[i]) != 1)
			return false;
	}

	return true;
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int sk, mode = RECV;
	char *filename = NULL;
	bool repeat = false;
	unsigned int i;
	uint8_t nconn = 1;
	char *peer;

	iso_qos = malloc(sizeof(*iso_qos));
	/* Default to 16_2_1 */
	*iso_qos = presets[3].qos;
	inout = true;

	while (1) {
		int opt;

		opt = getopt_long(argc, argv,
			"d::cmr::s::nb:i:j:hqt:CV:W:M:S:P:F:I:L:Y:R:B:G:T:e:k:N:",
			main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'r':
			mode = RECV;
			if (optarg)
				filename = strdup(optarg);
			break;

		case 's':
			mode = SEND;
			if (optarg)
				filename = strdup(optarg);
			break;

		case 'd':
			mode = DUMP;
			if (optarg)
				filename = strdup(optarg);
			break;

		case 'c':
			mode = RECONNECT;
			break;

		case 'm':
			mode = MULTY;
			break;

		case 'n':
			mode = CONNECT;
			break;

		case 'b':
			if (optarg && atoi(optarg) < MAX_DATA_SIZE)
				data_size = atoi(optarg);
			break;

		case 'i':
			if (!optarg)
				break;

			if (!strncasecmp(optarg, "hci", 3)) {
				mgmt_index = atoi(optarg + 3);
				hci_devba(mgmt_index, &bdaddr);
			} else
				str2ba(optarg, &bdaddr);
			break;

		case 'j':
			if (optarg)
				sndbuf = atoi(optarg);
			break;

		case 'q':
			quiet = true;
			break;

		case 't':
			if (optarg)
				sndto.tv_usec = atoi(optarg);
			break;

		case 'C':
			repeat = true;
			break;

		case 'V':
			if (optarg)
				bdaddr_type = get_lookup_flag(bdaddr_types,
								optarg);

			if (bdaddr_type == -1) {
				print_lookup_values(bdaddr_types,
						"List Address types:");
				exit(1);
			}

			break;

		case 'W':
			if (optarg)
				defer_setup = atoi(optarg);
			break;

		case 'M':
			if (optarg)
				iso_qos->ucast.out.sdu = atoi(optarg);
			break;

		case 'S':
			if (optarg)
				iso_qos->ucast.sca = atoi(optarg);
			break;


		case 'P':
			if (optarg)
				iso_qos->ucast.packing = atoi(optarg);
			break;

		case 'F':
			if (optarg)
				iso_qos->ucast.framing = atoi(optarg);
			break;

		case 'I':
			if (optarg)
				iso_qos->ucast.out.interval = atoi(optarg);
			break;

		case 'L':
			if (optarg)
				iso_qos->ucast.out.latency = atoi(optarg);
			break;

		case 'Y':
			if (optarg)
				iso_qos->ucast.out.phy = atoi(optarg);
			break;

		case 'R':
			if (optarg)
				iso_qos->ucast.out.rtn = atoi(optarg);
			break;

		case 'B':
			if (!optarg)
				break;

			for (i = 0; i < ARRAY_SIZE(presets); i++) {
				if (!strcmp(presets[i].name, optarg)) {
					*iso_qos = presets[i].qos;
					inout = presets[i].inout;
					break;
				}
			}

			break;

		case 'G':
			if (optarg)
				iso_qos->ucast.cig = atoi(optarg);
			break;

		case 'T':
			if (optarg)
				iso_qos->ucast.cis = atoi(optarg);
			break;

		case 'e':
			if (optarg)
				iso_qos->bcast.encryption =
					strtol(optarg, NULL, 16);
			break;

		case 'k':
			if (optarg)
				if (!str2hex(optarg, strlen(optarg),
						iso_qos->bcast.bcode, 16))
					exit(1);
			break;

		case 'N':
			if (optarg)
				num_bis = atoi(optarg);

			if (num_bis > 1) {
				/* If the user requested multiple BISes,
				 * make sure that all BISes are bound
				 * for the same BIG and advertising set
				 */
				if (iso_qos->bcast.big == BT_ISO_QOS_BIG_UNSET)
					iso_qos->bcast.big = DEFAULT_BIG_ID;

				if (iso_qos->bcast.bis == BT_ISO_QOS_BIS_UNSET)
					iso_qos->bcast.bis = DEFAULT_BIS_ID;
			}
			break;

		/* fall through */
		default:
			usage();
			exit(1);
		}
	}

	if (inout) {
		iso_qos->ucast.in = iso_qos->ucast.out;
	} else {
		/* Align interval and latency even if is unidirectional */
		iso_qos->ucast.in.interval = iso_qos->ucast.out.interval;
		iso_qos->ucast.in.latency = iso_qos->ucast.out.latency;
	}

	buf = malloc(data_size);
	if (!buf) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags   = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	openlog("isotest", LOG_PERROR | LOG_PID, LOG_LOCAL0);

	if (!(argc - optind)) {
		switch (mode) {
		case RECV:
			do_listen(filename, recv_mode, NULL);
			goto done;

		case DUMP:
			do_listen(filename, dump_mode, NULL);
			goto done;
		default:
			usage();
			exit(1);
		}
	}

	argc -= optind;

	for (i = 0; i < (unsigned int) argc; i++) {
		pid_t pid;

		pid = fork();
		if (pid < 0) {
			perror("Failed to fork new process");
			exit(1);
		}

		if (!pid)
			continue;

		switch (mode) {
		case SEND:
			peer = argv[optind + i];
			if (bachk(peer) < 0) {
				fprintf(stderr, "Invalid peer address '%s'\n",
						peer);
				exit(1);
			}
			send_mode(filename, peer, i, repeat);
			if (filename && strchr(filename, ',')) {
				char *tmp = filename;
				filename = strdup(strchr(filename, ',') + 1);
				free(tmp);
			}
			break;

		case RECONNECT:
			reconnect_mode(argv[optind + i]);
			break;

		case MULTY:
			multy_connect_mode(argv[optind + i]);
			break;

		case CONNECT:
			peer = argv[optind + i];
			if (bachk(peer) < 0) {
				fprintf(stderr, "Invalid peer address '%s'\n",
						peer);
				exit(1);
			}

			mgmt_set_experimental();

			if (!strcmp(peer, "00:00:00:00:00:00"))
				nconn = num_bis;

			if (nconn > 1) {
				int *sk_arr =  bcast_do_connect_mbis(nconn,
								peer);

				if (!sk_arr)
					exit(1);

				for (int i = 0; i < nconn; i++) {
					if (fork()) {
						/* Parent */
						continue;
					}

					/* Child */
					if (!strcmp(peer, "00:00:00:00:00:00"))
						dump_mode(-1, sk_arr[i], peer);
					else
						dump_mode(-1, sk_arr[i], NULL);

					exit(0);
				}

				/* Wait for children to exit */
				while (wait(NULL) > 0)
					;

				for (int i = 0; i < nconn; i++)
					close(sk_arr[i]);

				free(sk_arr);
			} else {
				sk = do_connect(peer);
				if (sk < 0)
					exit(1);

				if (!strcmp(peer, "00:00:00:00:00:00"))
					dump_mode(-1, sk, peer);
				else
					dump_mode(-1, sk, NULL);
			}

			break;

		case RECV:
			do_listen(filename, recv_mode, argv[optind + i]);
			break;

		case DUMP:
			do_listen(filename, dump_mode, argv[optind + i]);
			break;
		}

		break;
	}

done:
	free(filename);

	syslog(LOG_INFO, "Exit");

	closelog();

	return 0;
}

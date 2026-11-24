// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "src/shared/mainloop.h"
#include "src/shared/util.h"

#include "ttclient.h"

/* Protocol of include/uapi/linux/um_timetravel.h in Linux */
#define TT_ACK		0
#define TT_START	1
#define TT_REQUEST	2
#define TT_WAIT		3
#define TT_RUN		6
#define TT_FREE_UNTIL	7
#define TT_BROADCAST	9

struct tt_msg {
	uint32_t op;
	uint32_t seq;
	uint64_t time;
} __attribute__((packed));

static struct {
	int fd;
	uint32_t seq;
	uint64_t now;
	uint64_t quantum;
	bool running;
	int pace_id;
	ttc_run_func_t run;
	void *run_data;
	ttc_pace_func_t pace;
	void *pace_data;
	ttc_debug_func_t debug;
	void *debug_data;
} ttc = { .fd = -1 };

static void ttc_debug(const char *format, ...)
{
	char str[128];
	va_list ap;

	if (!ttc.debug)
		return;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	ttc.debug(str, ttc.debug_data);
}

/* Read a message, closing any file descriptors it carries (shared memory
 * offered with the START acknowledgment, which this client does not use).
 */
static bool read_msg(struct tt_msg *msg)
{
	char control[CMSG_SPACE(sizeof(int) * 2)];
	struct iovec iov = { msg, sizeof(*msg) };
	struct msghdr mh = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;
	ssize_t len;

	do {
		len = recvmsg(ttc.fd, &mh, MSG_CMSG_CLOEXEC);
	} while (len < 0 && errno == EINTR);

	for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		int fds[2];
		unsigned int i, n;

		if (cmsg->cmsg_level != SOL_SOCKET ||
					cmsg->cmsg_type != SCM_RIGHTS)
			continue;

		n = MIN((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int), 2U);
		memcpy(fds, CMSG_DATA(cmsg), n * sizeof(int));
		for (i = 0; i < n; i++)
			close(fds[i]);
	}

	return len == sizeof(*msg);
}

static void send_msg(uint32_t op, uint32_t seq, uint64_t time)
{
	struct tt_msg msg = { .op = op, .seq = seq, .time = time };

	if (write(ttc.fd, &msg, sizeof(msg)) < 0)
		ttc_debug("write failed: %s", strerror(errno));
}

/* Messages the calendar may send at any time */
static void handle_async(struct tt_msg *msg)
{

	switch (msg->op) {
	case TT_FREE_UNTIL:
	case TT_BROADCAST:
		send_msg(TT_ACK, msg->seq, 0);
		break;
	case TT_RUN:
		ttc.now = msg->time;
		ttc.running = true;
		send_msg(TT_ACK, msg->seq, 0);
		break;
	}
}

/* Send a request and wait for its acknowledgment */
static bool request(uint32_t op, uint64_t time, uint64_t *ack_time)
{
	uint32_t seq = ++ttc.seq;
	struct tt_msg msg;

	send_msg(op, seq, time);

	while (read_msg(&msg)) {
		if (msg.op == TT_ACK && msg.seq == seq) {
			if (ack_time)
				*ack_time = msg.time;
			return true;
		}

		handle_async(&msg);
	}

	ttc_debug("calendar connection lost");
	return false;
}

static void run(void);

void ttc_process(void)
{
	struct tt_msg msg;

	if (ttc.fd < 0)
		return;

	/* Only messages the calendar may send while the client runs */
	while (recv(ttc.fd, &msg, sizeof(msg), MSG_DONTWAIT | MSG_PEEK) ==
							sizeof(msg)) {
		if (msg.op != TT_FREE_UNTIL && msg.op != TT_BROADCAST)
			break;

		if (!read_msg(&msg))
			break;

		handle_async(&msg);
	}
}

/* Ask to run again one quantum later and let the guests run until then */
static void wait_next(void)
{
	if (!request(TT_REQUEST, ttc.now + ttc.quantum, NULL) ||
				!request(TT_WAIT, (uint64_t) -1, NULL)) {
		mainloop_remove_fd(ttc.fd);
		return;
	}

	ttc.running = false;
}

static void pace_callback(int id, void *user_data)
{
	mainloop_remove_timeout(id);
	ttc.pace_id = 0;
	wait_next();
}

static void run(void)
{
	if (ttc.run)
		ttc.run(ttc.run_data);

	/* Without anything asked of the guests, hold time for one quantum
	 * of real time, so it advances no faster than real time.
	 */
	if (ttc.pace && ttc.pace(ttc.pace_data)) {
		ttc.pace_id = mainloop_add_timeout(
				MAX(ttc.quantum / 1000000ULL, 1ULL),
				pace_callback, NULL, NULL);
		if (ttc.pace_id > 0)
			return;
	}

	wait_next();
}

static void read_callback(int fd, uint32_t events, void *user_data)
{
	struct tt_msg msg;

	if ((events & (EPOLLERR | EPOLLHUP)) || !read_msg(&msg)) {
		ttc_debug("calendar disconnected");
		mainloop_remove_fd(fd);
		return;
	}

	handle_async(&msg);

	if (msg.op == TT_RUN)
		run();
}

static void ttc_destroy(void *user_data)
{
	if (ttc.pace_id > 0)
		mainloop_remove_timeout(ttc.pace_id);

	close(ttc.fd);
	ttc.fd = -1;
	ttc.running = false;
}

bool ttc_open(const char *path, unsigned int id, unsigned int quantum_us)
{
	struct sockaddr_un addr;
	uint64_t ack;

	if (ttc.fd >= 0 || strlen(path) >= sizeof(addr.sun_path))
		return false;

	ttc.fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (ttc.fd < 0)
		return false;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, path, strlen(path));

	if (connect(ttc.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto fail;

	ttc.quantum = (uint64_t) (quantum_us ? quantum_us : 100) * 1000ULL;

	if (!request(TT_START, id, &ack))
		goto fail;

	ttc_debug("started, id %u", (unsigned int) (ack & 0xffff));

	if (mainloop_add_fd(ttc.fd, EPOLLIN, read_callback, NULL,
							ttc_destroy) < 0)
		goto fail;

	/* A client runs once started */
	ttc.running = true;
	run();

	return true;

fail:
	close(ttc.fd);
	ttc.fd = -1;
	return false;
}

bool ttc_enabled(void)
{
	return ttc.fd >= 0;
}

bool ttc_running(void)
{
	return ttc.fd < 0 || ttc.running;
}

void ttc_set_run(ttc_run_func_t func, void *user_data)
{
	ttc.run = func;
	ttc.run_data = user_data;
}

void ttc_set_pace(ttc_pace_func_t func, void *user_data)
{
	ttc.pace = func;
	ttc.pace_data = user_data;
}

void ttc_set_debug(ttc_debug_func_t callback, void *user_data)
{
	ttc.debug = callback;
	ttc.debug_data = user_data;
}

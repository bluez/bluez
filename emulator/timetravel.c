// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Intel Corporation
 *
 *
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "src/shared/mainloop.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"

#include "timetravel.h"

/* Protocol of include/uapi/linux/um_timetravel.h in Linux */
#define TT_ACK		0
#define TT_START	1
#define TT_REQUEST	2
#define TT_WAIT		3
#define TT_GET		4
#define TT_UPDATE	5
#define TT_RUN		6
#define TT_FREE_UNTIL	7
#define TT_GET_TOD	8
#define TT_BROADCAST	9

#define TT_SHM_SIZE	4096

struct tt_msg {
	uint32_t op;
	uint32_t seq;
	uint64_t time;
} __attribute__((packed));

struct tt_client {
	int fd;
	uint16_t id;
	bool waiting;
	bool has_request;
	uint64_t request;
	/* Time the client runs at, as far as known */
	uint64_t time;
	/* Time the running client may run until without asking, 0 if none */
	uint64_t free_until;
};

struct tt_flush {
	tt_flush_func_t func;
	void *user_data;
};

struct tt_timer {
	unsigned int id;
	uint64_t time;
	uint64_t interval;
	tt_timeout_func_t func;
	tt_destroy_func_t destroy;
	void *user_data;
};

static struct {
	int fd;
	struct queue *clients;
	struct queue *timers;
	uint64_t now;
	uint64_t skew;
	uint64_t tod;
	uint16_t next_id;
	unsigned int next_timer;
	bool scheduling;
	struct queue *flushes;
	tt_hold_func_t hold;
	void *hold_data;
	/* While held, time advances no faster than real time from here */
	bool held;
	uint64_t held_sim;
	uint64_t held_wall;
	int pace_id;
	tt_debug_func_t debug;
	void *debug_data;
} tt = { .fd = -1 };

static void tt_debug(const char *format, ...)
{
	char str[128];
	va_list ap;

	if (!tt.debug)
		return;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

	tt.debug(str, tt.debug_data);
}

static void send_msg(struct tt_client *client, uint32_t op, uint32_t seq,
							uint64_t time)
{
	struct tt_msg msg = { .op = op, .seq = seq, .time = time };

	if (write(client->fd, &msg, sizeof(msg)) < 0)
		tt_debug("client %u: write failed", client->id);
}

/* The ACK to START may carry a shared memory and a log file descriptor.
 * This calendar only uses messages, but UML uses the descriptors it
 * receives without checking how many it got, so send a shared memory it
 * rejects (version 0) and /dev/null.
 */
static void send_start_ack(struct tt_client *client, uint32_t seq)
{
	struct tt_msg msg = { .op = TT_ACK, .seq = seq, .time = client->id };
	char control[CMSG_SPACE(sizeof(int) * 2)];
	struct iovec iov = { &msg, sizeof(msg) };
	struct msghdr mh = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *cmsg;
	int fds[2];

	fds[0] = memfd_create("bt-time-shm", MFD_CLOEXEC);
	fds[1] = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (fds[0] < 0 || fds[1] < 0 || ftruncate(fds[0], TT_SHM_SIZE) < 0) {
		tt_debug("client %u: no file descriptors for START",
								client->id);
		send_msg(client, TT_ACK, seq, client->id);
		goto done;
	}

	memset(control, 0, sizeof(control));
	cmsg = CMSG_FIRSTHDR(&mh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

	if (sendmsg(client->fd, &mh, 0) < 0)
		tt_debug("client %u: sendmsg failed", client->id);

done:
	if (fds[0] >= 0)
		close(fds[0]);
	if (fds[1] >= 0)
		close(fds[1]);
}

static void find_running(void *data, void *user_data)
{
	struct tt_client *client = data;
	uint64_t *min = user_data;

	if (!client->waiting && client->time < *min)
		*min = client->time;
}

static void find_next_client(void *data, void *user_data)
{
	struct tt_client *client = data;
	struct tt_client **next = user_data;

	if (!client->waiting || !client->has_request)
		return;

	if (!*next || client->request < (*next)->request)
		*next = client;
}

static void find_next_timer(void *data, void *user_data)
{
	struct tt_timer *timer = data;
	struct tt_timer **next = user_data;

	if (!*next || timer->time < (*next)->time)
		*next = timer;
}

static void timer_free(void *data)
{
	struct tt_timer *timer = data;

	if (timer->destroy)
		timer->destroy(timer->user_data);

	free(timer);
}

static void fire_timer(struct tt_timer *timer)
{
	if (timer->func(timer->user_data)) {
		/* The callback may have removed the timer */
		if (queue_find(tt.timers, NULL, timer)) {
			timer->time = tt.now + timer->interval;
			return;
		}
	}

	if (queue_remove(tt.timers, timer))
		timer_free(timer);
}

static void run_flush(void *data, void *user_data)
{
	struct tt_flush *flush = data;

	flush->func(flush->user_data);
}

static void schedule(void);

struct free_limit {
	struct tt_client *client;
	uint64_t time;
};

static void find_free_limit(void *data, void *user_data)
{
	struct tt_client *client = data;
	struct free_limit *limit = user_data;

	if (client == limit->client)
		return;

	/* A client that has not waited yet may request any time */
	if (!client->waiting)
		limit->time = MIN(limit->time, tt.now);
	else if (client->has_request)
		limit->time = MIN(limit->time, client->request);
}

static void find_timer_limit(void *data, void *user_data)
{
	struct tt_timer *timer = data;
	uint64_t *limit = user_data;

	*limit = MIN(*limit, timer->time);
}

/* How far a client may run without asking: up to the earliest event of any
 * other client or timer. Only in lock-step, and not while time may be
 * paced, as pacing must be able to stop the client.
 */
static uint64_t free_until(struct tt_client *client)
{
	struct free_limit limit = { client, UINT64_MAX };

	if (tt.skew || tt.hold)
		return 0;

	queue_foreach(tt.clients, find_free_limit, &limit);
	queue_foreach(tt.timers, find_timer_limit, &limit.time);

	return limit.time;
}

/* Lower the limit of a running client when an earlier event appeared. This
 * happens in response to a client, e.g. while it waits for its virtio
 * notification to be acknowledged, so it receives the new limit before it
 * runs further.
 */
static void update_free_until(void *data, void *user_data)
{
	struct tt_client *client = data;
	uint64_t limit;

	if (client->waiting || !client->free_until)
		return;

	limit = free_until(client);
	if (limit >= client->free_until)
		return;

	client->free_until = limit;
	send_msg(client, TT_FREE_UNTIL, 0, limit);
}

static uint64_t wall_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t) ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void pace_callback(int id, void *user_data)
{
	mainloop_remove_timeout(id);
	tt.pace_id = 0;
	schedule();
}

/* Limit of time while held: real time elapsed since the hold started */
static uint64_t hold_limit(void)
{
	bool hold = tt.hold && tt.hold(tt.hold_data);

	if (!hold) {
		tt.held = false;
		return UINT64_MAX;
	}

	if (!tt.held) {
		tt.held = true;
		tt.held_sim = tt.now;
		tt.held_wall = wall_now();
	}

	return tt.held_sim + (wall_now() - tt.held_wall);
}

/* Schedule again when real time catches up with the next event */
static void pace(uint64_t next, uint64_t limit)
{
	unsigned int msec = (next - limit) / 1000000ULL + 1;

	if (tt.pace_id > 0)
		return;

	tt.pace_id = mainloop_add_timeout(MIN(msec, 100U), pace_callback,
								NULL, NULL);
}

/* Run whichever is due first, a timer of this process or the client with
 * the earliest request. In lock-step (no skew) time only advances when
 * every client waits. With a skew, time may advance up to that much beyond
 * the earliest running client, so clients run their own events in parallel
 * while others compute, which takes no simulated time.
 */
static void schedule(void)
{
	if (tt.scheduling)
		return;

	tt.scheduling = true;

	while (1) {
		struct tt_client *client = NULL;
		struct tt_timer *timer = NULL;
		uint64_t running = UINT64_MAX;
		uint64_t limit = UINT64_MAX;
		uint64_t hold;
		uint64_t next;

		queue_foreach(tt.flushes, run_flush, NULL);

		if (queue_isempty(tt.clients))
			break;

		queue_foreach(tt.clients, find_running, &running);
		if (running != UINT64_MAX) {
			if (!tt.skew) {
				queue_foreach(tt.clients, update_free_until,
									NULL);
				break;
			}
			limit = running + tt.skew;
		}

		hold = hold_limit();

		queue_foreach(tt.clients, find_next_client, &client);
		queue_foreach(tt.timers, find_next_timer, &timer);

		if (timer && (!client || timer->time <= client->request)) {
			next = timer->time;
			client = NULL;
		} else if (client) {
			next = client->request;
			timer = NULL;
		} else {
			break;
		}

		if (next > limit)
			break;

		if (next > hold) {
			pace(next, hold);
			break;
		}

		if (next > tt.now)
			tt.now = next;

		if (timer) {
			fire_timer(timer);
			continue;
		}

		client->waiting = false;
		client->has_request = false;
		client->time = next;

		/* Let the client run until the next event of another one,
		 * instead of asking for each of its own events.
		 */
		client->free_until = free_until(client);
		if (client->free_until)
			send_msg(client, TT_FREE_UNTIL, 0, client->free_until);

		send_msg(client, TT_RUN, 0, next);
	}

	tt.scheduling = false;
}

void tt_schedule(void)
{
	if (tt_enabled())
		schedule();
}

static void handle_msg(struct tt_client *client, struct tt_msg *msg)
{
	switch (msg->op) {
	case TT_ACK:
		/* ACK of a RUN */
		return;
	case TT_START:
		client->id = tt.next_id++;
		client->time = tt.now;
		tt_debug("client %u started", client->id);
		send_start_ack(client, msg->seq);
		return;
	case TT_REQUEST:
		client->has_request = true;
		/* The guest must run exactly at the time of its event */
		client->request = msg->time;
		send_msg(client, TT_ACK, msg->seq, 0);
		break;
	case TT_WAIT:
		client->waiting = true;
		client->free_until = 0;
		send_msg(client, TT_ACK, msg->seq, 0);
		break;
	case TT_GET:
		/* The guest takes it as the time of an interrupt: the current
		 * time, which no guest is ahead of.
		 */
		client->time = MAX(client->time, tt.now);
		send_msg(client, TT_ACK, msg->seq, client->time);
		return;
	case TT_UPDATE:
		if (msg->time > client->time)
			client->time = msg->time;
		/* In lock-step the running client sets the time, which may be
		 * ahead of the calendar when it runs until a FREE_UNTIL.
		 */
		if (!tt.skew && !client->waiting && client->time > tt.now)
			tt.now = client->time;
		/* The guest sends UPDATE before a virtio notification, which
		 * it does not wait for, and runs on meanwhile. Stop it at this
		 * time before acknowledging, so it cannot run ahead of what
		 * the notification causes, e.g. the device's interrupt.
		 */
		if (client->free_until && client->free_until > client->time) {
			client->free_until = client->time;
			send_msg(client, TT_FREE_UNTIL, 0, client->time);
		}
		send_msg(client, TT_ACK, msg->seq, 0);
		break;
	case TT_GET_TOD:
		send_msg(client, TT_ACK, msg->seq, tt.tod + tt.now);
		return;
	default:
		tt_debug("client %u: unsupported op %u", client->id, msg->op);
		send_msg(client, TT_ACK, msg->seq, 0);
		return;
	}
}

/* Returns 1 if a message was handled, 0 if none is pending and -1 if the
 * connection failed.
 */
static int read_msg(struct tt_client *client)
{
	struct tt_msg msg;
	ssize_t len;

	len = recv(client->fd, &msg, sizeof(msg), MSG_DONTWAIT);
	if (len < 0 && (errno == EAGAIN || errno == EINTR))
		return 0;

	if (len != sizeof(msg)) {
		tt_debug("client %u: read %zd", client->id, len);
		return -1;
	}

	handle_msg(client, &msg);

	return 1;
}

static void client_destroy(void *data)
{
	struct tt_client *client = data;

	tt_debug("client %u disconnected", client->id);

	queue_remove(tt.clients, client);
	close(client->fd);
	free(client);

	/* Clients and back-ends are destroyed in any order on shutdown, so
	 * only schedule while the calendar is open.
	 */
	if (tt.fd >= 0)
		schedule();
}

static void client_callback(int fd, uint32_t events, void *user_data)
{
	struct tt_client *client = user_data;

	int ret;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(client->fd);
		return;
	}

	/* Process everything that is pending before scheduling, messages
	 * may also have been processed already by tt_process().
	 */
	while ((ret = read_msg(client)) > 0)
		;

	if (ret < 0) {
		mainloop_remove_fd(client->fd);
		return;
	}

	schedule();
}

static void process_client(void *data, void *user_data)
{
	struct tt_client *client = data;

	while (read_msg(client) > 0)
		;
}

void tt_process(void)
{
	queue_foreach(tt.clients, process_client, NULL);
}

static void accept_callback(int fd, uint32_t events, void *user_data)
{
	struct tt_client *client;
	int nfd;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(fd);
		return;
	}

	nfd = accept(fd, NULL, NULL);
	if (nfd < 0)
		return;

	client = new0(struct tt_client, 1);
	client->fd = nfd;

	if (mainloop_add_fd(nfd, EPOLLIN, client_callback, client,
						client_destroy) < 0) {
		close(nfd);
		free(client);
		return;
	}

	queue_push_tail(tt.clients, client);
}

static void tt_destroy(void *user_data)
{
	close(tt.fd);
	tt.fd = -1;
}

bool tt_open(const char *path)
{
	struct sockaddr_un addr;
	struct timespec ts;

	if (tt.fd >= 0 || strlen(path) >= sizeof(addr.sun_path))
		return false;

	tt.fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (tt.fd < 0)
		return false;

	unlink(path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, path, strlen(path));

	if (bind(tt.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
						listen(tt.fd, 5) < 0)
		goto fail;

	if (mainloop_add_fd(tt.fd, EPOLLIN, accept_callback, NULL,
							tt_destroy) < 0)
		goto fail;

	clock_gettime(CLOCK_REALTIME, &ts);
	tt.tod = (uint64_t) ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	tt.clients = queue_new();
	tt.timers = queue_new();
	tt.next_id = 1;

	return true;

fail:
	close(tt.fd);
	tt.fd = -1;
	return false;
}

void tt_close(void)
{
	if (tt.fd >= 0)
		mainloop_remove_fd(tt.fd);
}

bool tt_enabled(void)
{
	return tt.fd >= 0;
}

uint64_t tt_now(void)
{
	return tt.now;
}

void tt_set_skew(unsigned int msec)
{
	tt.skew = (uint64_t) msec * 1000000ULL;
}

void tt_set_hold(tt_hold_func_t func, void *user_data)
{
	tt.hold = func;
	tt.hold_data = user_data;
}

static bool match_flush(const void *data, const void *match_data)
{
	const struct tt_flush *flush = data;
	const struct tt_flush *match = match_data;

	return flush->func == match->func &&
				flush->user_data == match->user_data;
}

void tt_remove_flush(tt_flush_func_t func, void *user_data)
{
	struct tt_flush match = { .func = func, .user_data = user_data };

	free(queue_remove_if(tt.flushes, match_flush, &match));
}

void tt_add_flush(tt_flush_func_t func, void *user_data)
{
	struct tt_flush *flush;

	if (!tt.flushes)
		tt.flushes = queue_new();

	flush = new0(struct tt_flush, 1);
	flush->func = func;
	flush->user_data = user_data;

	queue_push_tail(tt.flushes, flush);
}

unsigned int tt_timeout_add(unsigned int msec, tt_timeout_func_t func,
				void *user_data, tt_destroy_func_t destroy)
{
	struct tt_timer *timer;

	timer = new0(struct tt_timer, 1);
	timer->id = ++tt.next_timer;
	timer->interval = (uint64_t) msec * 1000000ULL;
	timer->time = tt.now + timer->interval;
	timer->func = func;
	timer->user_data = user_data;
	timer->destroy = destroy;

	queue_push_tail(tt.timers, timer);

	return timer->id;
}

static bool match_timer(const void *data, const void *match_data)
{
	const struct tt_timer *timer = data;

	return timer->id == PTR_TO_UINT(match_data);
}

void tt_timeout_remove(unsigned int id)
{
	struct tt_timer *timer;

	timer = queue_remove_if(tt.timers, match_timer, UINT_TO_PTR(id));
	if (timer)
		timer_free(timer);
}

void tt_set_debug(tt_debug_func_t callback, void *user_data)
{
	tt.debug = callback;
	tt.debug_data = user_data;
}

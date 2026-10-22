// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/signalfd.h>
#include <sys/socket.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/io.h"
#include "src/shared/tester.h"
#include "src/shared/log.h"
#include "src/shared/timeout.h"
#include "src/shared/queue.h"

#define COLOR_OFF	"\x1B[0m"
#define COLOR_BLACK	"\x1B[0;30m"
#define COLOR_RED	"\x1B[0;31m"
#define COLOR_GREEN	"\x1B[0;32m"
#define COLOR_YELLOW	"\x1B[0;33m"
#define COLOR_BLUE	"\x1B[0;34m"
#define COLOR_MAGENTA	"\x1B[0;35m"
#define COLOR_CYAN	"\x1B[0;36m"
#define COLOR_WHITE	"\x1B[0;37m"
#define COLOR_HIGHLIGHT	"\x1B[1;39m"

#define print_text(color, fmt, args...) \
		tester_log(color fmt COLOR_OFF, ## args)

#define print_summary(label, color, value, fmt, args...) \
		tester_log("%-52s " color "%-10s" COLOR_OFF fmt, \
							label, value, ## args)

#define print_progress(name, color, fmt, args...) \
		tester_log(COLOR_HIGHLIGHT "%s" COLOR_OFF " - " \
				color fmt COLOR_OFF, name, ## args)

enum test_result {
	TEST_RESULT_NOT_RUN,
	TEST_RESULT_PASSED,
	TEST_RESULT_FAILED,
	TEST_RESULT_TIMED_OUT,
};

enum test_stage {
	TEST_STAGE_INVALID,
	TEST_STAGE_PRE_SETUP,
	TEST_STAGE_SETUP,
	TEST_STAGE_RUN,
	TEST_STAGE_TEARDOWN,
	TEST_STAGE_POST_TEARDOWN,
};

struct test_case {
	char *name;
	enum test_result result;
	enum test_stage stage;
	const void *test_data;
	const struct iovec *iov;
	size_t iovcnt;
	tester_data_func_t pre_setup_func;
	tester_data_func_t setup_func;
	tester_data_func_t test_func;
	tester_data_func_t teardown_func;
	tester_data_func_t post_teardown_func;
	tester_data_func_t io_complete_func;
	double start_time;
	double end_time;
	unsigned int timeout;
	unsigned int timeout_id;
	unsigned int teardown_id;
	tester_destroy_func_t destroy;
	void *user_data;
};

static char *tester_name;

static struct queue *test_list;
static const struct queue_entry *test_current;
static double test_timer_start;
static double test_timer_stop;

static bool option_version;
static bool option_quiet;
static bool option_debug;
static bool option_monitor;
static bool option_list;
static const char *option_prefix = NULL;
static const char *option_string = NULL;

struct monitor_hdr {
	uint16_t opcode;
	uint16_t index;
	uint16_t len;
	uint8_t  priority;
	uint8_t  ident_len;
} __attribute__((packed));

struct monitor_l2cap_hdr {
	uint16_t cid;
	uint16_t psm;
} __attribute__((packed));

/* Seconds since tester_run(), on the clock the timeouts use */
static double test_timer_elapsed(void)
{
	struct timespec ts;

	if (test_timer_stop)
		return test_timer_stop - test_timer_start;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec + ts.tv_nsec / 1e9 - test_timer_start;
}

static void test_destroy(void *data)
{
	struct test_case *test = data;

	if (test->timeout_id > 0)
		timeout_remove(test->timeout_id);

	if (test->teardown_id > 0)
		timeout_remove(test->teardown_id);

	if (test->destroy)
		test->destroy(test->user_data);

	free(test->name);
	free(test);
}

static void tester_vprintf(const char *format, va_list ap)
{
	if (tester_use_quiet())
		return;

	printf("  %s", COLOR_WHITE);
	vprintf(format, ap);
	printf("%s\n", COLOR_OFF);
}

static void tester_log(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	printf("\n");
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_INFO, format, ap);
	va_end(ap);
}

void tester_print(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	tester_vprintf(format, ap);
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_INFO, format, ap);
	va_end(ap);
}

void tester_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	tester_vprintf(format, ap);
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_DEBUG, format, ap);
	va_end(ap);
}

void tester_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	tester_vprintf(format, ap);
	va_end(ap);

	va_start(ap, format);
	bt_log_vprintf(HCI_DEV_NONE, tester_name, LOG_WARNING, format, ap);
	va_end(ap);
}

static void monitor_debug(const char *str, void *user_data)
{
	const char *label = user_data;

	tester_debug("%s: %s", label, str);
}

static void monitor_log(char dir, uint16_t cid, uint16_t psm, const void *data,
								size_t len)
{
	struct iovec iov[3];
	struct monitor_l2cap_hdr hdr;
	uint8_t term = 0x00;
	char label[16];

	if (snprintf(label, sizeof(label), "%c %s", dir, tester_name) < 0)
		return;

	hdr.cid = cpu_to_le16(cid);
	hdr.psm = cpu_to_le16(psm);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);

	iov[1].iov_base = (void *) data;
	iov[1].iov_len = len;

	/* Kernel won't forward if data is no NULL terminated */
	iov[2].iov_base = &term;
	iov[2].iov_len = sizeof(term);

	bt_log_sendmsg(HCI_DEV_NONE, label, LOG_INFO, iov, 3);
}

void tester_monitor(char dir, uint16_t cid, uint16_t psm, const void *data,
								size_t len)
{
	monitor_log(dir, cid, psm, data, len);

	if (!tester_use_debug())
		return;

	util_hexdump(dir, data, len, monitor_debug, (void *) tester_name);
}

static void default_pre_setup(const void *test_data)
{
	tester_pre_setup_complete();
}

static void default_setup(const void *test_data)
{
	tester_setup_complete();
}

static void default_teardown(const void *test_data)
{
	tester_teardown_complete();
}

static void default_post_teardown(const void *test_data)
{
	tester_post_teardown_complete();
}

void tester_add_full(const char *name, const void *test_data,
				tester_data_func_t pre_setup_func,
				tester_data_func_t setup_func,
				tester_data_func_t test_func,
				tester_data_func_t teardown_func,
				tester_data_func_t post_teardown_func,
				unsigned int timeout,
				void *user_data, tester_destroy_func_t destroy)
{
	struct test_case *test;

	if (!test_func)
		return;

	if (option_prefix && strncmp(name, option_prefix,
						strlen(option_prefix))) {
		if (destroy)
			destroy(user_data);
		return;
	}

	if (option_string && !strstr(name, option_string)) {
		if (destroy)
			destroy(user_data);
		return;
	}

	if (option_list) {
		tester_log("%s", name);
		if (destroy)
			destroy(user_data);
		return;
	}

	test = new0(struct test_case, 1);
	test->name = strdup(name);
	test->result = TEST_RESULT_NOT_RUN;
	test->stage = TEST_STAGE_INVALID;

	test->test_data = test_data;

	if (pre_setup_func)
		test->pre_setup_func = pre_setup_func;
	else
		test->pre_setup_func = default_pre_setup;

	if (setup_func)
		test->setup_func = setup_func;
	else
		test->setup_func = default_setup;

	test->test_func = test_func;

	if (teardown_func)
		test->teardown_func = teardown_func;
	else
		test->teardown_func = default_teardown;

	if (post_teardown_func)
		test->post_teardown_func = post_teardown_func;
	else
		test->post_teardown_func = default_post_teardown;

	test->timeout = timeout;

	test->destroy = destroy;
	test->user_data = user_data;

	queue_push_tail(test_list, test);
}

void tester_add(const char *name, const void *test_data,
					tester_data_func_t setup_func,
					tester_data_func_t test_func,
					tester_data_func_t teardown_func)
{
	tester_add_full(name, test_data, NULL, setup_func, test_func,
					teardown_func, NULL, 0, NULL, NULL);
}

static struct test_case *tester_get_test(void)
{
	if (!test_current)
		return NULL;

	return test_current->data;
}

void *tester_get_data(void)
{
	struct test_case *test = tester_get_test();

	if (!test)
		return NULL;

	return test->user_data;
}

static int tester_summarize(void)
{
	unsigned int not_run = 0, passed = 0, failed = 0;
	double execution_time;
	const struct queue_entry *list;

	tester_log("");
	print_text(COLOR_HIGHLIGHT, "");
	print_text(COLOR_HIGHLIGHT, "Test Summary");
	print_text(COLOR_HIGHLIGHT, "------------");

	for (list = queue_get_entries(test_list); list; list = list->next) {
		struct test_case *test = list->data;
		double exec_time;

		exec_time = test->end_time - test->start_time;

		switch (test->result) {
		case TEST_RESULT_NOT_RUN:
			print_summary(test->name, COLOR_YELLOW, "Not Run", "");
			not_run++;
			break;
		case TEST_RESULT_PASSED:
			print_summary(test->name, COLOR_GREEN, "Passed",
						"%8.3f seconds", exec_time);
			passed++;
			break;
		case TEST_RESULT_FAILED:
			print_summary(test->name, COLOR_RED, "Failed",
						"%8.3f seconds", exec_time);
			failed++;
			break;
		case TEST_RESULT_TIMED_OUT:
			print_summary(test->name, COLOR_RED, "Timed out",
						"%8.3f seconds", exec_time);
			failed++;
			break;
		}
        }

	tester_log("Total: %d, "
		COLOR_GREEN "Passed: %d (%.1f%%)" COLOR_OFF ", "
		COLOR_RED "Failed: %d" COLOR_OFF ", "
		COLOR_YELLOW "Not Run: %d" COLOR_OFF,
			not_run + passed + failed, passed,
			(not_run + passed + failed) ?
			(float) passed * 100 / (not_run + passed + failed) : 0,
			failed, not_run);

	execution_time = test_timer_elapsed();
	tester_log("Overall execution time: %.3g seconds", execution_time);

	return failed;
}

static bool done_callback(void *user_data);

static bool teardown_timeout(void *user_data)
{
	struct test_case *test = user_data;

	test->timeout_id = 0;

	if (!test_current || test_current->data != test)
		return false;

	/* Give up waiting, e.g. for an index that was never added to be
	 * removed, rather than blocking for good. Its callbacks may still
	 * complete later, and would be taken for those of the test running
	 * then, so do not run the remaining tests.
	 */
	test->result = TEST_RESULT_TIMED_OUT;
	test->stage = TEST_STAGE_INVALID;

	print_progress(test->name, COLOR_RED, "teardown timed out");
	tester_warn("Not running the remaining tests");

	while (test_current->next)
		test_current = test_current->next;

	timeout_add(0, done_callback, test, NULL);

	return false;
}

/* Teardown may have to wait for the kernel to time out commands still sent
 * to a controller being removed, 2 seconds each, so only give up on a
 * teardown that clearly does not complete.
 */
#define TEARDOWN_TIMEOUT	30

static void teardown_timeout_start(struct test_case *test)
{
	if (test->timeout_id > 0) {
		timeout_remove(test->timeout_id);
		test->timeout_id = 0;
	}

	if (test->timeout > 0)
		test->timeout_id = timeout_add_seconds(
					MAX(test->timeout, TEARDOWN_TIMEOUT),
					teardown_timeout, test, NULL);
}

static bool teardown_callback(void *user_data)
{
	struct test_case *test = user_data;

	test->teardown_id = 0;
	test->stage = TEST_STAGE_TEARDOWN;

	teardown_timeout_start(test);

	print_progress(test->name, COLOR_MAGENTA, "teardown");
	test->teardown_func(test->test_data);

#ifdef HAVE_VALGRIND_MEMCHECK_H
	VALGRIND_DO_ADDED_LEAK_CHECK;
#endif

	return false;
}

static bool test_timeout(void *user_data)
{
	struct test_case *test = user_data;

	test->timeout_id = 0;

	if (!test_current)
		return false;

	test->result = TEST_RESULT_TIMED_OUT;
	print_progress(test->name, COLOR_RED, "test timed out");

	timeout_add(0, teardown_callback, test, NULL);

	return false;
}

static void next_test_case(void)
{
	struct test_case *test;

	if (test_current)
		test_current = test_current->next;
	else
		test_current = queue_get_entries(test_list);

	if (!test_current) {
		test_timer_stop = test_timer_elapsed() + test_timer_start;

		mainloop_quit();
		return;
	}

	test = test_current->data;

	tester_log("");
	print_progress(test->name, COLOR_BLACK, "init");

	test->start_time = test_timer_elapsed();

	if (test->timeout > 0)
		test->timeout_id = timeout_add_seconds(test->timeout,
							test_timeout, test,
							NULL);

	test->stage = TEST_STAGE_PRE_SETUP;

	test->pre_setup_func(test->test_data);
}

static bool setup_callback(void *user_data)
{
	struct test_case *test = user_data;

	test->stage = TEST_STAGE_SETUP;

	print_progress(test->name, COLOR_BLUE, "setup");
	test->setup_func(test->test_data);

	return false;
}

static bool run_callback(void *user_data)
{
	struct test_case *test = user_data;

	test->stage = TEST_STAGE_RUN;

	print_progress(test->name, COLOR_BLACK, "run");
	test->test_func(test->test_data);

	return false;
}

static bool done_callback(void *user_data)
{
	struct test_case *test = user_data;

	test->end_time = test_timer_elapsed();

	print_progress(test->name, COLOR_BLACK, "done");
	next_test_case();

	return false;
}

void tester_pre_setup_complete(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_PRE_SETUP)
		return;

	timeout_add(0, setup_callback, test, NULL);
}

void tester_pre_setup_failed(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_PRE_SETUP)
		return;

	if (test->timeout_id > 0) {
		timeout_remove(test->timeout_id);
		test->timeout_id = 0;
	}

	test->result = TEST_RESULT_FAILED;

	print_progress(test->name, COLOR_RED, "pre setup failed");

	timeout_add(0, done_callback, test, NULL);
}

void tester_pre_setup_abort(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_PRE_SETUP)
		return;

	if (test->timeout_id > 0) {
		timeout_remove(test->timeout_id);
		test->timeout_id = 0;
	}

	print_progress(test->name, COLOR_YELLOW, "not run");

	timeout_add(0, done_callback, test, NULL);
}

bool tester_pre_setup_skip_by_default(void)
{
	if (!option_prefix && !option_string) {
		tester_pre_setup_abort();
		return true;
	}

	return false;
}

void tester_setup_complete(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_SETUP)
		return;

	print_progress(test->name, COLOR_BLUE, "setup complete");

	timeout_add(0, run_callback, test, NULL);
}

void tester_setup_failed(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_SETUP)
		return;

	test->result = TEST_RESULT_FAILED;
	test->stage = TEST_STAGE_POST_TEARDOWN;

	teardown_timeout_start(test);

	print_progress(test->name, COLOR_RED, "setup failed");
	print_progress(test->name, COLOR_MAGENTA, "teardown");

	test->post_teardown_func(test->test_data);
}

static void test_result(enum test_result result)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_RUN)
		return;

	if (test->timeout_id > 0) {
		timeout_remove(test->timeout_id);
		test->timeout_id = 0;
	}

	tester_shutdown_io();

	if (test->result == TEST_RESULT_FAILED)
		result = TEST_RESULT_FAILED;

	test->result = result;
	switch (result) {
	case TEST_RESULT_PASSED:
		print_progress(test->name, COLOR_GREEN, "test passed");
		break;
	case TEST_RESULT_FAILED:
		print_progress(test->name, COLOR_RED, "test failed");
		break;
	case TEST_RESULT_NOT_RUN:
		print_progress(test->name, COLOR_YELLOW, "test not run");
		break;
	case TEST_RESULT_TIMED_OUT:
		print_progress(test->name, COLOR_RED, "test timed out");
		break;
	}

	if (test->teardown_id > 0)
		return;

	test->teardown_id = timeout_add(0, teardown_callback, test, NULL);
}

void tester_test_passed(void)
{
	test_result(TEST_RESULT_PASSED);
}

void tester_test_failed(void)
{
	test_result(TEST_RESULT_FAILED);
}

void tester_test_abort(void)
{
	test_result(TEST_RESULT_NOT_RUN);
}

void tester_teardown_complete(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_TEARDOWN)
		return;

	test->stage = TEST_STAGE_POST_TEARDOWN;

	test->post_teardown_func(test->test_data);
}

void tester_teardown_failed(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_TEARDOWN)
		return;

	test->stage = TEST_STAGE_POST_TEARDOWN;

	tester_post_teardown_failed();
}

void tester_post_teardown_complete(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_POST_TEARDOWN)
		return;

	if (test->timeout_id > 0) {
		timeout_remove(test->timeout_id);
		test->timeout_id = 0;
	}

	print_progress(test->name, COLOR_MAGENTA, "teardown complete");

	timeout_add(0, done_callback, test, NULL);
}

void tester_post_teardown_failed(void)
{
	struct test_case *test;

	if (!test_current)
		return;

	test = test_current->data;

	if (test->stage != TEST_STAGE_POST_TEARDOWN)
		return;

	if (test->timeout_id > 0) {
		timeout_remove(test->timeout_id);
		test->timeout_id = 0;
	}

	print_progress(test->name, COLOR_RED, "teardown failed");

	timeout_add(0, done_callback, test, NULL);
}

static bool start_tester(void *user_data)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	test_timer_start = ts.tv_sec + ts.tv_nsec / 1e9;

	next_test_case();

	return false;
}

struct wait_data {
	unsigned int seconds;
	struct test_case *test;
	tester_wait_func_t func;
	void *user_data;
};

static bool wait_callback(void *user_data)
{
	struct wait_data *wait = user_data;
	struct test_case *test = wait->test;

	wait->seconds--;

	if (wait->seconds > 0) {
		print_progress(test->name, COLOR_BLACK, "%u seconds left",
								wait->seconds);
		return true;
	}

	print_progress(test->name, COLOR_BLACK, "waiting done");

	wait->func(wait->user_data);

	free(wait);

	return false;
}

void tester_wait(unsigned int seconds, tester_wait_func_t func,
							void *user_data)
{
	struct test_case *test;
	struct wait_data *wait;

	if (!func || seconds < 1)
		return;

	if (!test_current)
		return;

	test = test_current->data;

	wait = new0(struct wait_data, 1);
	wait->seconds = seconds;
	wait->test = test;
	wait->func = func;
	wait->user_data = user_data;

	timeout_add(1000, wait_callback, wait, NULL);

	print_progress(test->name, COLOR_BLACK, "waiting %u seconds", seconds);
}

static void signal_callback(int signum, void *user_data)
{
	static bool terminated = false;

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		if (!terminated)
			mainloop_quit();

		terminated = true;
		break;
	}
}

bool tester_use_quiet(void)
{
	return option_quiet;
}

bool tester_use_debug(void)
{
	return option_debug;
}

static const struct option options[] = {
	{ "version",	no_argument,		NULL, 'v' },
	{ "quiet",	no_argument,		NULL, 'q' },
	{ "debug",	no_argument,		NULL, 'd' },
	{ "monitor",	no_argument,		NULL, 'm' },
	{ "list",	no_argument,		NULL, 'l' },
	{ "prefix",	required_argument,	NULL, 'p' },
	{ "string",	required_argument,	NULL, 's' },
	{ "help",	no_argument,		NULL, 'h' },
	{ }
};

static void usage(const char *name)
{
	printf("Usage:\n"
		"\t%s [options]\n"
		"Options:\n"
		"\t-v, --version          Show version information and exit\n"
		"\t-q, --quiet            Run tests without logging\n"
		"\t-d, --debug            Run tests with debug output\n"
		"\t-m, --monitor          Enable monitor output\n"
		"\t-l, --list             Only list the tests to be run\n"
		"\t-p, --prefix=<prefix>  Run tests matching provided prefix\n"
		"\t-s, --string=<string>  Run tests matching provided string\n"
		"\t-h, --help             Show help options\n", name);
}

void tester_init(int *argc, char ***argv)
{
	int opt, i;

	for (;;) {
		opt = getopt_long(*argc, *argv, "vqdmlp:s:h", options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'v':
			option_version = true;
			break;
		case 'q':
			option_quiet = true;
			break;
		case 'd':
			option_debug = true;
			break;
		case 'm':
			option_monitor = true;
			break;
		case 'l':
			option_list = true;
			break;
		case 'p':
			option_prefix = optarg;
			break;
		case 's':
			option_string = optarg;
			break;
		case 'h':
			usage((*argv)[0]);
			exit(EXIT_SUCCESS);
		default:
			exit(EXIT_FAILURE);
		}
	}

	/* Leave the program name and the arguments that are not options */
	for (i = optind; i < *argc; i++)
		(*argv)[i - optind + 1] = (*argv)[i];
	*argc -= optind - 1;
	(*argv)[*argc] = NULL;

	if (option_version) {
		printf("%s\n", VERSION);
		exit(EXIT_SUCCESS);
	}

	mainloop_init();

	tester_name = strrchr(*argv[0], '/');
	if (!tester_name)
		tester_name = strdup(*argv[0]);
	else
		tester_name = strdup(++tester_name);

	test_list = queue_new();
	test_current = NULL;
}

static struct io *ios[2];

static bool io_disconnected(struct io *io, void *user_data)
{
	if (io == ios[0]) {
		io_destroy(ios[0]);
		ios[0] = NULL;
	} else if (io == ios[1]) {
		io_destroy(ios[1]);
		ios[1] = NULL;
	}

	return false;
}

static const struct iovec *test_get_iov(struct test_case *test)
{
	const struct iovec *iov;

	if (!test || !test->iov || !test->iovcnt)
		return NULL;

	iov = test->iov;

	test->iov++;
	test->iovcnt--;

	return iov;
}

static bool test_io_send(struct io *io, void *user_data)
{
	struct test_case *test = tester_get_test();
	const struct iovec *iov = test_get_iov(test);
	ssize_t len;

	if (!iov)
		return false;

	/* IOV_NULL following an expected PDU means there is no response to
	 * it, e.g. a Write Command: wait for the next PDU instead, unless
	 * followed by another IOV_NULL chaining the PDUs to send.
	 */
	if (!iov->iov_base) {
		/* Nothing left to send or to expect */
		if (!test->iovcnt) {
			if (test->io_complete_func)
				test->io_complete_func(test->test_data);
			return false;
		}

		if (test->iov->iov_base)
			return false;

		test_get_iov(test);
		return test_io_send(io, user_data);
	}

	len = io_send(io, iov, 1);

	tester_monitor('<', 0x0004, 0x0000, iov->iov_base, len);

	if (len != (ssize_t) iov->iov_len)
		abort();

	if (!test->iovcnt && test->io_complete_func) {
		test->io_complete_func(test->test_data);
	} else if (test->iovcnt && !test->iov->iov_base) {
		test_get_iov(test);
		return test_io_send(io, user_data);
	}

	return false;
}

static bool test_io_recv(struct io *io, void *user_data)
{
	struct test_case *test = tester_get_test();
	const struct iovec *iov = test_get_iov(test);
	unsigned char buf[512];
	int fd;
	ssize_t len;

	fd = io_get_fd(io);

	len = read(fd, buf, sizeof(buf));

	if (len <= 0)
		abort();

	tester_monitor('>', 0x0004, 0x0000, buf, len);

	if (!iov)
		return true;

	if (test->iovcnt && !iov->iov_base)
		iov = test_get_iov(test);

	if ((size_t)len != iov->iov_len || memcmp(buf, iov->iov_base, len))
		tester_monitor('!', 0x0004, 0x0000, iov->iov_base,
							iov->iov_len);

	if (len != (ssize_t) iov->iov_len)
		abort();

	if (memcmp(buf, iov->iov_base, len))
		abort();

	if (test->iovcnt)
		io_set_write_handler(io, test_io_send, NULL, NULL);
	else if (test->io_complete_func)
		test->io_complete_func(test->test_data);

	return true;
}

static void setup_io(void)
{
	int fd[2], err;

	io_destroy(ios[0]);
	io_destroy(ios[1]);

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fd);
	if (err < 0) {
		tester_warn("socketpair: %s (%d)", strerror(errno), errno);
		return;
	}

	ios[0] = io_new(fd[0]);
	if (!ios[0]) {
		tester_warn("io_new: %p", ios[0]);
		return;
	}

	io_set_close_on_destroy(ios[0], true);
	io_set_disconnect_handler(ios[0], io_disconnected, NULL, NULL);

	ios[1] = io_new(fd[1]);
	if (!ios[1]) {
		tester_warn("io_new: %p", ios[1]);
		return;
	}

	io_set_close_on_destroy(ios[1], true);
	io_set_disconnect_handler(ios[1], io_disconnected, NULL, NULL);
	io_set_read_handler(ios[1], test_io_recv, NULL, NULL);
}

struct io *tester_setup_io(const struct iovec *iov, int iovcnt)
{
	struct test_case *test = tester_get_test();

	if (!ios[0] || !ios[1]) {
		setup_io();
		if (!ios[0] || !ios[1]) {
			tester_warn("Unable to setup IO");
			return NULL;
		}
	}

	test->iov = iov;
	test->iovcnt = iovcnt;

	return ios[0];
}

void tester_shutdown_io(void)
{
	io_shutdown(ios[0]);
	io_shutdown(ios[1]);
}

void tester_io_send(void)
{
	struct test_case *test = tester_get_test();

	if (test->iovcnt)
		io_set_write_handler(ios[1], test_io_send, NULL, NULL);
}

void tester_io_set_complete_func(tester_data_func_t func)
{
	struct test_case *test = tester_get_test();

	test->io_complete_func = func;
}

int tester_run(void)
{
	int ret;

	if (option_list) {
		mainloop_quit();
		return EXIT_SUCCESS;
	}

	timeout_add(0, start_tester, NULL, NULL);

	mainloop_run_with_signal(signal_callback, NULL);

	ret = tester_summarize();

	queue_destroy(test_list, test_destroy);

	if (option_monitor)
		bt_log_close();

	io_destroy(ios[0]);
	io_destroy(ios[1]);

	return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

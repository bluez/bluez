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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "monitor/display.h"
#include "monitor/find.h"

/*
 * A capture runs for as long as it is left running, so the oldest frames
 * are dropped once this many are held rather than letting the monitor be
 * killed for using too much memory.
 */
#define FIND_MAX_FRAMES 200000

/* How often the pager is checked for having been closed */
#define FIND_POLL_MSEC 100

struct find_frame {
	char *text;
	size_t len;
	uint64_t seq;
};

/*
 * The frames are held in a ring, so that the oldest can be dropped once it
 * is full without having to move the rest.
 */
static struct find_frame *frames;
static unsigned int num_frames;		/* Held right now */
static unsigned int max_frames;		/* Allocated */
static unsigned int first_frame;	/* Oldest, within the ring */
static uint64_t next_seq;

static bool enabled;
static bool store;	/* Keep the frames for handing to the pager */
static bool records;	/* Separate the frames with a NUL */
static bool printed;	/* Something has been written out already */
static bool print0;
static bool use_pager;
static bool raw_mode;
static int poll_id = -1;
static struct termios saved_term;

static pid_t pager_pid;
static int saved_stdout = -1;
static uint64_t pager_seq;	/* Frames from here are yet to be printed */

static char *capture_buf;
static size_t capture_len;
static FILE *capture;

static struct find_frame *frame_at(unsigned int n)
{
	return &frames[(first_frame + n) % max_frames];
}

static void frame_free(struct find_frame *frame)
{
	free(frame->text);
	memset(frame, 0, sizeof(*frame));
}

/* Make room for one more frame, dropping the oldest once the ring is full */
static struct find_frame *frame_next(void)
{
	struct find_frame *frame;

	if (num_frames == FIND_MAX_FRAMES) {
		frame = &frames[first_frame];
		frame_free(frame);
		first_frame = (first_frame + 1) % max_frames;
		return frame;
	}

	if (num_frames == max_frames) {
		unsigned int size = max_frames ? max_frames * 2 : 1024;
		void *tmp;

		if (size > FIND_MAX_FRAMES)
			size = FIND_MAX_FRAMES;

		tmp = realloc(frames, size * sizeof(*frames));
		if (!tmp)
			return NULL;

		frames = tmp;
		max_frames = size;
	}

	frame = &frames[(first_frame + num_frames) % max_frames];
	num_frames++;

	return frame;
}

void find_frame_begin(void)
{
	if (!enabled)
		return;

	capture_buf = NULL;
	capture_len = 0;

	capture = open_memstream(&capture_buf, &capture_len);
	if (!capture)
		return;

	display_set_output(capture);
}

void find_frame_end(void)
{
	struct find_frame *frame;

	if (!enabled || !capture)
		return;

	display_set_output(NULL);
	fclose(capture);
	capture = NULL;

	/* A frame that was filtered out produces no output */
	if (!capture_len) {
		free(capture_buf);
		capture_buf = NULL;
		return;
	}

	/*
	 * Keep the trace on the terminal while the pager is not up. What
	 * arrives while it is up is printed once it closes, so that the
	 * trace on the terminal has no gap.
	 */
	if (!pager_pid) {
		const char nul = '\0';
		size_t len = capture_len;

		/*
		 * Only what is read as records is written as records. While
		 * capturing this is the trace on the terminal, which keeps
		 * its newlines or the next frame carries on the same line.
		 * The pager is given its own copy.
		 */
		if (records && !store) {
			/*
			 * The newline ending the frame is what separates
			 * the lines within it, so leave it out of a record
			 * or it shows as a blank line at the end of the
			 * entry.
			 */
			if (len && capture_buf[len - 1] == '\n')
				len--;

			if (printed)
				fwrite(&nul, 1, 1, stdout);
		}

		fwrite(capture_buf, 1, len, stdout);
		fflush(stdout);
		printed = true;
	}

	if (!store) {
		free(capture_buf);
		capture_buf = NULL;
		return;
	}

	frame = frame_next();
	if (!frame) {
		free(capture_buf);
		capture_buf = NULL;
		return;
	}

	frame->text = capture_buf;
	frame->len = capture_len;
	frame->seq = next_seq++;
	capture_buf = NULL;
}

static void term_restore(void);

/*
 * Leaving the terminal not echoing what is typed would make the shell
 * unusable, so put it back however the monitor happens to be leaving.
 * tcsetattr() may be called from a signal handler.
 */
static void fatal_signal(int sig)
{
	term_restore();

	signal(sig, SIG_DFL);
	raise(sig);
}

static void term_hooks(void)
{
	static const int fatal[] = { SIGSEGV, SIGBUS, SIGABRT, SIGQUIT,
								SIGHUP };
	struct sigaction sa;
	unsigned int i;

	atexit(term_restore);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = fatal_signal;
	sa.sa_flags = SA_RESETHAND;

	for (i = 0; i < ARRAY_SIZE(fatal); i++)
		sigaction(fatal[i], &sa, NULL);
}

/*
 * Read the keys as they are typed rather than a line at a time. Signals are
 * left enabled so that Ctrl-C still interrupts the capture as it always has.
 */
static void term_raw(void)
{
	struct termios term;

	if (raw_mode)
		return;

	if (tcgetattr(STDIN_FILENO, &saved_term) < 0)
		return;

	term = saved_term;
	term.c_lflag &= ~(ICANON | ECHO);
	term.c_cc[VMIN] = 1;
	term.c_cc[VTIME] = 0;

	if (tcsetattr(STDIN_FILENO, TCSANOW, &term) < 0)
		return;

	raw_mode = true;

	term_hooks();
}

static void term_restore(void)
{
	if (!raw_mode)
		return;

	tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
	raw_mode = false;
}

/*
 * Hand the frames over as a file rather than through a pipe, so that
 * filling it cannot block the monitor and cost the capture any packets.
 * They are separated by a NUL so that a pager able to take records, such
 * as fzf with --read0, sees a whole frame as one entry instead of matching
 * the individual lines within it.
 */
static int frames_to_file(void)
{
	unsigned int i;
	int fd;

	fd = memfd_create("btmon-frames", MFD_CLOEXEC);
	if (fd < 0)
		return -1;

	for (i = 0; i < num_frames; i++) {
		const struct find_frame *frame = frame_at(i);
		const char nul = '\0';
		size_t len = frame->len;

		if (records) {
			if (i && write(fd, &nul, 1) < 0)
				break;

			/* Leave out the newline ending the frame */
			if (len && frame->text[len - 1] == '\n')
				len--;
		}

		if (write(fd, frame->text, len) < 0)
			break;
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static void pager_close(void)
{
	unsigned int i;

	if (!pager_pid)
		return;

	pager_pid = 0;

	/* Put the monitor back in charge of the terminal */
	if (saved_stdout >= 0) {
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdout);
		saved_stdout = -1;
	}

	term_raw();

	/* Print whatever arrived while the pager was up */
	for (i = 0; i < num_frames; i++) {
		const struct find_frame *frame = frame_at(i);

		if (frame->seq >= pager_seq)
			fwrite(frame->text, 1, frame->len, stdout);
	}

	fflush(stdout);
}

static void pager_open(void)
{
	const char *pager;
	int fd;

	if (pager_pid || !num_frames || !use_pager || pager_disabled())
		return;

	fd = frames_to_file();
	if (fd < 0)
		return;

	pager = pager_command();

	fflush(stdout);

	/* The pager reads the terminal from here on */
	term_restore();
	mainloop_remove_fd(STDIN_FILENO);

	saved_stdout = dup(STDOUT_FILENO);

	pager_pid = fork();
	if (pager_pid < 0) {
		pager_pid = 0;
		close(fd);
		close(saved_stdout);
		saved_stdout = -1;
		term_raw();
		return;
	}

	if (!pager_pid) {
		dup2(fd, STDIN_FILENO);
		close(fd);

		if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
			_exit(EXIT_FAILURE);

		if (pager) {
			execlp(pager, pager, NULL);
			execl("/bin/sh", "sh", "-c", pager, NULL);
		}

		execlp("pager", "pager", NULL);
		execlp("less", "less", NULL);
		execlp("more", "more", NULL);

		_exit(EXIT_FAILURE);
	}

	close(fd);

	pager_seq = next_seq;
}

static void key_callback(int fd, uint32_t events, void *user_data)
{
	char buf[32];
	ssize_t len, i;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_quit();
		return;
	}

	len = read(STDIN_FILENO, buf, sizeof(buf));
	if (len <= 0)
		return;

	/*
	 * Anything else typed at a running capture is left alone, so that
	 * the terminal behaves as it did before.
	 */
	for (i = 0; i < len; i++) {
		if (buf[i] == 0x12) {	/* Ctrl-R */
			pager_open();
			return;
		}
	}
}

static void arm_keys(void)
{
	mainloop_add_fd(STDIN_FILENO, EPOLLIN, key_callback, NULL, NULL);
}

/*
 * The pager runs on its own so that the monitor keeps draining the socket
 * while it is up, as anything not read in time is dropped by the kernel.
 */
static void poll_callback(int id, void *user_data)
{
	if (pager_pid && waitpid(pager_pid, NULL, WNOHANG) == pager_pid) {
		pager_close();
		arm_keys();
	}

	mainloop_modify_timeout(id, FIND_POLL_MSEC);
}

void find_set_print0(void)
{
	print0 = true;
}

/*
 * A frame spans several lines, so a pager that works on records rather
 * than lines has to be told where one ends. The request is already in
 * PAGER, so take it from there as well as from the command line.
 */
static bool want_records(void)
{
	const char *pager;

	if (print0)
		return true;

	/*
	 * Only separate the frames if something is actually going to read
	 * them as records. Nothing does when the output is redirected or
	 * the pager has been turned off.
	 */
	if (!use_pager || pager_disabled() || !isatty(STDOUT_FILENO))
		return false;

	pager = pager_command();

	return pager && strstr(pager, "--read0");
}

void find_setup(bool live, bool pager)
{
	use_pager = pager;
	records = want_records();

	if (live && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
		enabled = true;
		store = true;

		term_raw();
		arm_keys();

		poll_id = mainloop_add_timeout(FIND_POLL_MSEC, poll_callback,
								NULL, NULL);
		return;
	}

	/*
	 * Nothing is kept when only the separators are wanted, but the
	 * output still has to be seen to know where a frame ends.
	 */
	if (records)
		enabled = true;
}

void find_cleanup(void)
{
	unsigned int i;

	if (pager_pid) {
		kill(pager_pid, SIGTERM);
		waitpid(pager_pid, NULL, 0);
		pager_pid = 0;
	}

	if (saved_stdout >= 0) {
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdout);
		saved_stdout = -1;
	}

	term_restore();

	if (poll_id >= 0) {
		mainloop_remove_timeout(poll_id);
		poll_id = -1;
	}

	for (i = 0; i < num_frames; i++)
		frame_free(frame_at(i));

	free(frames);
	frames = NULL;
	num_frames = 0;
	max_frames = 0;
	first_frame = 0;
	enabled = false;
}

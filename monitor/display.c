// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <termios.h>

#include "display.h"

static pid_t pager_pid = 0;
static FILE *display_out;

/*
 * Redirect the decoding output, so that a caller can capture a frame and
 * decide what to do with it. Passing NULL restores the normal output.
 */
void display_set_output(FILE *fp)
{
	display_out = fp;
}

void display_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(display_out ? display_out : stdout, fmt, ap);
	va_end(ap);
}
int default_pager_num_columns = FALLBACK_TERMINAL_WIDTH;
enum monitor_color setting_monitor_color = COLOR_AUTO;

void set_monitor_color(enum monitor_color color)
{
	setting_monitor_color = color;
}

bool use_color(void)
{
	static int cached_use_color = -1;

	if (setting_monitor_color == COLOR_ALWAYS)
		cached_use_color = 1;
	else if (setting_monitor_color == COLOR_NEVER)
		cached_use_color = 0;
	else if (__builtin_expect(!!(cached_use_color < 0), 0))
		cached_use_color = isatty(STDOUT_FILENO) > 0 || pager_pid > 0;

	return cached_use_color;
}

void set_default_pager_num_columns(int num_columns)
{
	default_pager_num_columns = num_columns;
}

int num_columns(void)
{
	static int cached_num_columns = -1;

	if (__builtin_expect(!!(cached_num_columns < 0), 0)) {
		struct winsize ws;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0 ||
								ws.ws_col == 0)
			cached_num_columns = default_pager_num_columns;
		else
			cached_num_columns = ws.ws_col;
	}

	return cached_num_columns;
}

static void close_pipe(int p[])
{
	if (p[0] >= 0)
		close(p[0]);
	if (p[1] >= 0)
		close(p[1]);
}

static void wait_for_terminate(pid_t pid)
{
	siginfo_t dummy;

	for (;;) {
		memset(&dummy, 0, sizeof(dummy));

		if (waitid(P_PID, pid, &dummy, WEXITED) < 0) {
			if (errno == EINTR)
				continue;
			return;
		}

		return;
	}
}

/* Look for a command in PATH, so that it can be preferred if present */
static bool have_command(const char *name)
{
	const char *path = getenv("PATH");
	char *dirs, *dir, *save = NULL;
	bool found = false;

	if (!path)
		return false;

	dirs = strdup(path);
	if (!dirs)
		return false;

	for (dir = strtok_r(dirs, ":", &save); dir;
					dir = strtok_r(NULL, ":", &save)) {
		char file[PATH_MAX];

		if (snprintf(file, sizeof(file), "%s/%s", dir, name) < 0)
			continue;

		if (!access(file, X_OK)) {
			found = true;
			break;
		}
	}

	free(dirs);

	return found;
}

bool pager_disabled(void)
{
	const char *pager = getenv("PAGER");

	return pager && (!*pager || !strcmp(pager, "cat"));
}

/*
 * What a fuzzy finder needs to make sense of a trace: an entry has to be a
 * whole frame rather than a line of one, the colours have to be rendered
 * instead of shown, and the most recent frame is the one usually being
 * looked for.
 */
static const char * const fzf_options[] = {
	"--ansi",
	"--read0",
	"--tac",
	NULL
};

#define FZF_COMMAND "fzf --ansi --read0 --tac"

/* Match a whole option, so a longer one starting the same is not it */
static bool has_option(const char *cmd, const char *opt)
{
	size_t len = strlen(opt);
	const char *p = cmd;

	while ((p = strstr(p, opt))) {
		char next = p[len];

		if ((p == cmd || isspace(p[-1])) &&
				(!next || isspace(next) || next == '='))
			return true;

		p += len;
	}

	return false;
}

const char *pager_command(void)
{
	static char cmd[512];
	const char *pager = getenv("PAGER");
	size_t pos = 0;
	int i, n;

	if (!pager || !*pager)
		return have_command("fzf") ? FZF_COMMAND : NULL;

	if (!strstr(pager, "fzf"))
		return pager;

	n = snprintf(cmd, sizeof(cmd), "%s", pager);
	if (n < 0 || (size_t)n >= sizeof(cmd))
		return pager;

	pos = n;

	for (i = 0; fzf_options[i]; i++) {
		if (has_option(pager, fzf_options[i]))
			continue;

		n = snprintf(cmd + pos, sizeof(cmd) - pos, " %s",
							fzf_options[i]);
		/* Leave it as given rather than pass something truncated */
		if (n < 0 || (size_t)n >= sizeof(cmd) - pos)
			return pager;

		pos += n;
	}

	return cmd;
}

void open_pager(void)
{
	const char *pager;
	pid_t parent_pid;
	int fd[2];

	if (pager_pid > 0)
		return;

	if (pager_disabled())
		return;

	pager = pager_command();

	if (!(isatty(STDOUT_FILENO) > 0))
		return;

	num_columns();

	if (pipe(fd) < 0) {
		perror("Failed to create pager pipe");
		return;
	}

	parent_pid = getpid();

	pager_pid = fork();
	if (pager_pid < 0) {
		perror("Failed to fork pager");
		close_pipe(fd);
		return;
	}

	if (pager_pid == 0) {
		dup2(fd[0], STDIN_FILENO);
		close_pipe(fd);

		setenv("LESS", "FRSX", 0);

		if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
			_exit(EXIT_FAILURE);

		if (getppid() != parent_pid)
			_exit(EXIT_SUCCESS);

		if (pager) {
			execlp(pager, pager, NULL);
			execl("/bin/sh", "sh", "-c", pager, NULL);
		}

		execlp("pager", "pager", NULL);
		execlp("less", "less", NULL);
		execlp("more", "more", NULL);

		_exit(EXIT_FAILURE);
	}

	if (dup2(fd[1], STDOUT_FILENO) < 0) {
		perror("Failed to duplicate pager pipe");
		return;
	}

	close_pipe(fd);
}

void close_pager(void)
{
	if (pager_pid <= 0)
		return;

	fclose(stdout);
	kill(pager_pid, SIGCONT);
	wait_for_terminate(pager_pid);
	pager_pid = 0;
}

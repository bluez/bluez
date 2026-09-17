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

#include "monitor/display.h"
#include "monitor/find.h"

static bool enabled;
static bool records;	/* Separate the frames with a NUL */
static bool printed;	/* Something has been written out already */
static bool print0;

static char *capture_buf;
static size_t capture_len;
static FILE *capture;

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

	pager = getenv("PAGER");

	return pager && strstr(pager, "--read0");
}

void find_setup(void)
{
	records = want_records();

	/*
	 * Nothing is kept, but the output still has to be seen to know
	 * where one frame ends and the next begins.
	 */
	if (records)
		enabled = true;
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

	if (records) {
		const char nul = '\0';
		size_t len = capture_len;

		/*
		 * The newline ending the frame is what separates the lines
		 * within it, so leave it out of a record or it shows as a
		 * blank line at the end of the entry.
		 */
		if (len && capture_buf[len - 1] == '\n')
			len--;

		if (printed)
			fwrite(&nul, 1, 1, stdout);

		fwrite(capture_buf, 1, len, stdout);
	} else {
		fwrite(capture_buf, 1, capture_len, stdout);
	}

	fflush(stdout);
	printed = true;

	free(capture_buf);
	capture_buf = NULL;
}

void find_cleanup(void)
{
	enabled = false;
}

/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#include <errno.h>

char *expand_name(char *dst, int size, char *str, int dev_id);

char *get_host_name(void);

void init_title(int argc, char *argv[], char *env[], const char *name);
void set_title(const char *ftm, ...);

/* IO cancelation */
extern volatile sig_atomic_t __io_canceled;

static inline void io_init(void)
{
	__io_canceled = 0;
}

static inline void io_cancel(void)
{
	__io_canceled = 1;
}

/* Read exactly len bytes (Signal safe)*/
static inline int read_n(int fd, void *buf, int len)
{
	register int w, t = 0;

	while (!__io_canceled && len > 0) {
		if ((w = read(fd, buf, len)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w;
		buf += w;
		t += w;
	}

	return t;
}

/* Write exactly len bytes (Signal safe)*/
static inline int write_n(int fd, void *buf, int len)
{
	register int w, t = 0;

	while (!__io_canceled && len > 0) {
		if ((w = write(fd, buf, len)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w;
		buf += w;
		t += w;
	}

	return t;
}

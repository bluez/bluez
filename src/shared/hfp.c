/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include "src/shared/util.h"
#include "src/shared/ringbuf.h"
#include "src/shared/io.h"
#include "src/shared/hfp.h"

struct hfp_gw {
	int ref_count;
	int fd;
	bool close_on_unref;
	struct io *io;
	struct ringbuf *read_buf;
	struct ringbuf *write_buf;
	bool writer_active;
	bool permissive_syntax;
	bool result_pending;
	hfp_command_func_t command_callback;
	hfp_destroy_func_t command_destroy;
	void *command_data;
	hfp_debug_func_t debug_callback;
	hfp_destroy_func_t debug_destroy;
	void *debug_data;
};

static void write_watch_destroy(void *user_data)
{
	struct hfp_gw *hfp = user_data;

	hfp->writer_active = false;
}

static bool can_write_data(struct io *io, void *user_data)
{
	struct hfp_gw *hfp = user_data;
	ssize_t bytes_written;

	bytes_written = ringbuf_write(hfp->write_buf, hfp->fd);
	if (bytes_written < 0)
		return false;

	if (ringbuf_len(hfp->write_buf) > 0)
		return true;

	return false;
}

static void wakeup_writer(struct hfp_gw *hfp)
{
	if (hfp->writer_active)
		return;

	if (!ringbuf_len(hfp->write_buf))
		return;

	if (!io_set_write_handler(hfp->io, can_write_data,
					hfp, write_watch_destroy))
		return;

	hfp->writer_active = true;
}

static void process_input(struct hfp_gw *hfp)
{
	char *str, *ptr;
	size_t len, count;

	str = ringbuf_peek(hfp->read_buf, 0, &len);
	if (!str)
		return;

	ptr = memchr(str, '\r', len);
	if (!ptr) {
		char *str2;
		size_t len2;

		str2 = ringbuf_peek(hfp->read_buf, len, &len2);
		if (!str2)
			return;

		ptr = memchr(str2, '\r', len2);
		if (!ptr)
			return;

		*ptr = '\0';
		count = asprintf(&ptr, "%s%s", str, str2);
		str = ptr;
	} else {
		count = ptr - str;
		*ptr = '\0';
	}

	hfp->result_pending = true;

	if (hfp->command_callback)
		hfp->command_callback(str, hfp->command_data);
	else
		hfp_gw_send_result(hfp, HFP_RESULT_ERROR);

	len = ringbuf_drain(hfp->read_buf, count + 1);

	if (str == ptr)
		free(ptr);
}

static void read_watch_destroy(void *user_data)
{
}

static bool can_read_data(struct io *io, void *user_data)
{
	struct hfp_gw *hfp = user_data;
	ssize_t bytes_read;

	bytes_read = ringbuf_read(hfp->read_buf, hfp->fd);
	if (bytes_read < 0)
		return false;

	if (hfp->result_pending)
		return true;

	process_input(hfp);

	return true;
}

struct hfp_gw *hfp_gw_new(int fd)
{
	struct hfp_gw *hfp;

	if (fd < 0)
		return NULL;

	hfp = new0(struct hfp_gw, 1);
	if (!hfp)
		return NULL;

	hfp->fd = fd;
	hfp->close_on_unref = false;

	hfp->read_buf = ringbuf_new(4096);
	if (!hfp->read_buf) {
		free(hfp);
		return NULL;
	}

	hfp->write_buf = ringbuf_new(4096);
	if (!hfp->write_buf) {
		ringbuf_free(hfp->read_buf);
		free(hfp);
		return NULL;
	}

	hfp->io = io_new(fd);
	if (!hfp->io) {
		ringbuf_free(hfp->write_buf);
		ringbuf_free(hfp->read_buf);
		free(hfp);
		return NULL;
	}

	if (!io_set_read_handler(hfp->io, can_read_data,
					hfp, read_watch_destroy)) {
		io_destroy(hfp->io);
		ringbuf_free(hfp->write_buf);
		ringbuf_free(hfp->read_buf);
		free(hfp);
		return NULL;
	}

	hfp->writer_active = false;
	hfp->permissive_syntax = false;
	hfp->result_pending = false;

	return hfp_gw_ref(hfp);
}

struct hfp_gw *hfp_gw_ref(struct hfp_gw *hfp)
{
	if (!hfp)
		return NULL;

	__sync_fetch_and_add(&hfp->ref_count, 1);

	return hfp;
}

void hfp_gw_unref(struct hfp_gw *hfp)
{
	if (!hfp)
		return;

	if (__sync_sub_and_fetch(&hfp->ref_count, 1))
		return;

	hfp_gw_set_command_handler(hfp, NULL, NULL, NULL);

	io_set_write_handler(hfp->io, NULL, NULL, NULL);
	io_set_read_handler(hfp->io, NULL, NULL, NULL);

	io_destroy(hfp->io);
	hfp->io = NULL;

	if (hfp->close_on_unref)
		close(hfp->fd);

	hfp_gw_set_debug(hfp, NULL, NULL, NULL);

	ringbuf_free(hfp->read_buf);
	hfp->read_buf = NULL;

	ringbuf_free(hfp->write_buf);
	hfp->write_buf = NULL;

	free(hfp);
}

static void read_tracing(const void *buf, size_t count, void *user_data)
{
	struct hfp_gw *hfp = user_data;

	util_hexdump('>', buf, count, hfp->debug_callback, hfp->debug_data);
}

static void write_tracing(const void *buf, size_t count, void *user_data)
{
	struct hfp_gw *hfp = user_data;

	util_hexdump('<', buf, count, hfp->debug_callback, hfp->debug_data);
}

bool hfp_gw_set_debug(struct hfp_gw *hfp, hfp_debug_func_t callback,
				void *user_data, hfp_destroy_func_t destroy)
{
	if (!hfp)
		return false;

	if (hfp->debug_destroy)
		hfp->debug_destroy(hfp->debug_data);

	hfp->debug_callback = callback;
	hfp->debug_destroy = destroy;
	hfp->debug_data = user_data;

	if (hfp->debug_callback) {
		ringbuf_set_input_tracing(hfp->read_buf, read_tracing, hfp);
		ringbuf_set_input_tracing(hfp->write_buf, write_tracing, hfp);
	} else {
		ringbuf_set_input_tracing(hfp->read_buf, NULL, NULL);
		ringbuf_set_input_tracing(hfp->write_buf, NULL, NULL);
	}

	return true;
}

bool hfp_gw_set_close_on_unref(struct hfp_gw *hfp, bool do_close)
{
	if (!hfp)
		return false;

	hfp->close_on_unref = do_close;

	return true;
}

bool hfp_gw_set_permissive_syntax(struct hfp_gw *hfp, bool permissive)
{
	if (!hfp)
		return false;

	hfp->permissive_syntax = permissive;

	return true;
}

bool hfp_gw_send_result(struct hfp_gw *hfp, enum hfp_result result)
{
	const char *str;

	if (!hfp)
		return false;

	switch (result) {
	case HFP_RESULT_OK:
		str = "OK";
		break;
	case HFP_RESULT_ERROR:
		str = "ERROR";
		break;
	default:
		return false;
	}

	if (ringbuf_printf(hfp->write_buf, "\r\n%s\r\n", str) < 0)
		return false;

	wakeup_writer(hfp);

	hfp->result_pending = false;

	return true;
}

bool hfp_gw_send_error(struct hfp_gw *hfp, enum hfp_error error)
{
	if (!hfp)
		return false;

	if (ringbuf_printf(hfp->write_buf, "\r\n+CME ERROR: %u\r\n", error) < 0)
		return false;

	wakeup_writer(hfp);

	hfp->result_pending = false;

	return true;
}

bool hfp_gw_send_info(struct hfp_gw *hfp, const char *format, ...)
{
	va_list ap;
	char *fmt;
	int len;

	if (!hfp || !format)
		return false;

	if (asprintf(&fmt, "\r\n%s\r\n", format) < 0)
		return false;

	va_start(ap, format);
	len = ringbuf_vprintf(hfp->write_buf, fmt, ap);
	va_end(ap);

	free(fmt);

	if (len < 0)
		return false;

	if (hfp->result_pending)
		return true;

	wakeup_writer(hfp);

	return true;
}

bool hfp_gw_set_command_handler(struct hfp_gw *hfp,
				hfp_command_func_t callback,
				void *user_data, hfp_destroy_func_t destroy)
{
	if (!hfp)
		return false;

	if (hfp->command_destroy)
		hfp->command_destroy(hfp->command_data);

	hfp->command_callback = callback;
	hfp->command_destroy = destroy;
	hfp->command_data = user_data;

	return true;
}

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
#include <ctype.h>

#include "src/shared/util.h"
#include "src/shared/ringbuf.h"
#include "src/shared/queue.h"
#include "src/shared/io.h"
#include "src/shared/hfp.h"

struct hfp_gw {
	int ref_count;
	int fd;
	bool close_on_unref;
	struct io *io;
	struct ringbuf *read_buf;
	struct ringbuf *write_buf;
	struct queue *cmd_handlers;
	bool writer_active;
	bool result_pending;
	hfp_command_func_t command_callback;
	hfp_destroy_func_t command_destroy;
	void *command_data;
	hfp_debug_func_t debug_callback;
	hfp_destroy_func_t debug_destroy;
	void *debug_data;

	hfp_disconnect_func_t disconnect_callback;
	hfp_destroy_func_t disconnect_destroy;
	void *disconnect_data;

	bool in_disconnect;
	bool destroyed;
};

struct cmd_handler {
	char *prefix;
	void *user_data;
	hfp_destroy_func_t destroy;
	hfp_result_func_t callback;
};

struct hfp_gw_result {
	const char *data;
	unsigned int offset;
};

static void destroy_cmd_handler(void *data)
{
	struct cmd_handler *handler = data;

	if (handler->destroy)
		handler->destroy(handler->user_data);

	free(handler->prefix);

	free(handler);
}

static bool match_handler_prefix(const void *a, const void *b)
{
	const struct cmd_handler *handler = a;
	const char *prefix = b;

	if (strlen(handler->prefix) != strlen(prefix))
		return false;

	if (memcmp(handler->prefix, prefix, strlen(prefix)))
		return false;

	return true;
}

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

static void skip_whitespace(struct hfp_gw_result *result)
{
	while (result->data[result->offset] == ' ')
		result->offset++;
}

static bool call_prefix_handler(struct hfp_gw *hfp, const char *data)
{
	struct cmd_handler *handler;
	const char *separators = ";?=\0";
	struct hfp_gw_result result;
	enum hfp_gw_cmd_type type;
	char lookup_prefix[18];
	uint8_t pref_len = 0;
	const char *prefix;
	int i;

	result.offset = 0;
	result.data = data;

	skip_whitespace(&result);

	if (strlen(data + result.offset) < 3)
		return false;

	if (strncmp(data + result.offset, "AT", 2))
		if (strncmp(data + result.offset, "at", 2))
			return false;

	result.offset += 2;
	prefix = data + result.offset;

	if (isalpha(prefix[0])) {
		lookup_prefix[pref_len++] = toupper(prefix[0]);
	} else {
		pref_len = strcspn(prefix, separators);
		if (pref_len > 17 || pref_len < 2)
			return false;

		for (i = 0; i < pref_len; i++)
			lookup_prefix[i] = toupper(prefix[i]);
	}

	lookup_prefix[pref_len] = '\0';
	result.offset += pref_len;

	if (lookup_prefix[0] == 'D') {
		type = HFP_GW_CMD_TYPE_SET;
		goto done;
	}

	if (data[result.offset] == '=') {
		result.offset++;
		if (data[result.offset] == '?') {
			result.offset++;
			type = HFP_GW_CMD_TYPE_TEST;
		} else {
			type = HFP_GW_CMD_TYPE_SET;
		}
		goto done;
	}

	if (data[result.offset] == '?') {
		result.offset++;
		type = HFP_GW_CMD_TYPE_READ;
		goto done;
	}

	type = HFP_GW_CMD_TYPE_COMMAND;

done:

	handler = queue_find(hfp->cmd_handlers, match_handler_prefix,
								lookup_prefix);
	if (!handler)
		return false;

	handler->callback(&result, type, handler->user_data);

	return true;
}

static void next_field(struct hfp_gw_result *result)
{
	if (result->data[result->offset] == ',')
		result->offset++;
}

bool hfp_gw_result_get_number_default(struct hfp_gw_result *result,
						unsigned int *val,
						unsigned int default_val)
{
	skip_whitespace(result);

	if (result->data[result->offset] == ',') {
		if (val)
			*val = default_val;

		result->offset++;
		return true;
	}

	return hfp_gw_result_get_number(result, val);
}

bool hfp_gw_result_get_number(struct hfp_gw_result *result, unsigned int *val)
{
	unsigned int i;
	int tmp = 0;

	skip_whitespace(result);

	i = result->offset;

	while (result->data[i] >= '0' && result->data[i] <= '9')
		tmp = tmp * 10 + result->data[i++] - '0';

	if (i == result->offset)
		return false;

	if (val)
		*val = tmp;
	result->offset = i;

	skip_whitespace(result);
	next_field(result);

	return true;
}

bool hfp_gw_result_open_container(struct hfp_gw_result *result)
{
	skip_whitespace(result);

	/* The list shall be preceded by a left parenthesis "(") */
	if (result->data[result->offset] != '(')
		return false;

	result->offset++;

	return true;
}

bool hfp_gw_result_close_container(struct hfp_gw_result *result)
{
	skip_whitespace(result);

	/* The list shall be followed by a right parenthesis (")" V250 5.7.3.1*/
	if (result->data[result->offset] != ')')
		return false;

	result->offset++;

	return true;
}

bool hfp_gw_result_get_string(struct hfp_gw_result *result, char *buf,
								uint8_t len)
{
	int i = 0;
	const char *data = result->data;
	unsigned int offset;

	skip_whitespace(result);

	if (data[result->offset] != '"')
		return false;

	offset = result->offset;
	offset++;

	while (data[offset] != '\0' && data[offset] != '"') {
		if (i == len)
			return false;

		buf[i++] = data[offset];
		offset++;
	}

	if (i == len)
		return false;

	buf[i] = '\0';

	if (data[offset] == '"')
		offset++;
	else
		return false;

	result->offset = offset;

	skip_whitespace(result);
	next_field(result);

	return true;
}

bool hfp_gw_result_get_unquoted_string(struct hfp_gw_result *result, char *buf,
								uint8_t len)
{
	const char *data = result->data;
	unsigned int offset;
	int i = 0;
	char c;

	skip_whitespace(result);

	c = data[result->offset];
	if (c == '"' || c == ')' || c == '(')
		return false;

	offset = result->offset;

	while (data[offset] != '\0' && data[offset] != ',' &&
							data[offset] != ')') {
		if (i == len)
			return false;

		buf[i++] = data[offset];
		offset++;
	}

	if (i == len)
		return false;

	buf[i] = '\0';

	result->offset = offset;

	next_field(result);

	return true;
}

bool hfp_gw_result_has_next(struct hfp_gw_result *result)
{
	return result->data[result->offset] != '\0';
}

static void process_input(struct hfp_gw *hfp)
{
	char *str, *ptr;
	size_t len, count;
	bool free_ptr = false;

	str = ringbuf_peek(hfp->read_buf, 0, &len);
	if (!str)
		return;

	ptr = memchr(str, '\r', len);
	if (!ptr) {
		char *str2;
		size_t len2;

		/* If there is no more data in ringbuffer,
		 * it's just an incomplete command.
		 */
		if (len == ringbuf_len(hfp->read_buf))
			return;

		str2 = ringbuf_peek(hfp->read_buf, len, &len2);
		if (!str2)
			return;

		ptr = memchr(str2, '\r', len2);
		if (!ptr)
			return;

		*ptr = '\0';
		count = asprintf(&ptr, "%s%s", str, str2);
		free_ptr = true;
		str = ptr;
	} else {
		count = ptr - str;
		*ptr = '\0';
	}

	hfp->result_pending = true;

	if (!call_prefix_handler(hfp, str)) {
		if (hfp->command_callback)
			hfp->command_callback(str, hfp->command_data);
		else
			hfp_gw_send_result(hfp, HFP_RESULT_ERROR);
	}

	len = ringbuf_drain(hfp->read_buf, count + 1);

	if (free_ptr)
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

	hfp->cmd_handlers = queue_new();
	if (!hfp->cmd_handlers) {
		io_destroy(hfp->io);
		ringbuf_free(hfp->write_buf);
		ringbuf_free(hfp->read_buf);
		free(hfp);
		return NULL;
	}

	if (!io_set_read_handler(hfp->io, can_read_data,
					hfp, read_watch_destroy)) {
		queue_destroy(hfp->cmd_handlers,
						destroy_cmd_handler);
		io_destroy(hfp->io);
		ringbuf_free(hfp->write_buf);
		ringbuf_free(hfp->read_buf);
		free(hfp);
		return NULL;
	}

	hfp->writer_active = false;
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
	io_set_disconnect_handler(hfp->io, NULL, NULL, NULL);

	io_destroy(hfp->io);
	hfp->io = NULL;

	if (hfp->close_on_unref)
		close(hfp->fd);

	hfp_gw_set_debug(hfp, NULL, NULL, NULL);

	ringbuf_free(hfp->read_buf);
	hfp->read_buf = NULL;

	ringbuf_free(hfp->write_buf);
	hfp->write_buf = NULL;

	queue_destroy(hfp->cmd_handlers, destroy_cmd_handler);
	hfp->cmd_handlers = NULL;

	if (!hfp->in_disconnect) {
		free(hfp);
		return;
	}

	hfp->destroyed = true;
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

bool hfp_gw_register(struct hfp_gw *hfp, hfp_result_func_t callback,
						const char *prefix,
						void *user_data,
						hfp_destroy_func_t destroy)
{
	struct cmd_handler *handler;

	handler = new0(struct cmd_handler, 1);
	if (!handler)
		return false;

	handler->callback = callback;
	handler->user_data = user_data;

	handler->prefix = strdup(prefix);
	if (!handler->prefix) {
		free(handler);
		return false;
	}

	if (queue_find(hfp->cmd_handlers, match_handler_prefix,
							handler->prefix)) {
		destroy_cmd_handler(handler);
		return false;
	}

	handler->destroy = destroy;

	return queue_push_tail(hfp->cmd_handlers, handler);
}

bool hfp_gw_unregister(struct hfp_gw *hfp, const char *prefix)
{
	struct cmd_handler *handler;
	char *lookup_prefix;

	lookup_prefix = strdup(prefix);
	if (!lookup_prefix)
		return false;

	handler = queue_remove_if(hfp->cmd_handlers, match_handler_prefix,
								lookup_prefix);
	free(lookup_prefix);

	if (!handler)
		return false;

	destroy_cmd_handler(handler);

	return true;
}

static void disconnect_watch_destroy(void *user_data)
{
	struct hfp_gw *hfp = user_data;

	if (hfp->disconnect_destroy)
		hfp->disconnect_destroy(hfp->disconnect_data);

	if (hfp->destroyed)
		free(hfp);
}

static bool io_disconnected(struct io *io, void *user_data)
{
	struct hfp_gw *hfp = user_data;

	hfp->in_disconnect = true;

	if (hfp->disconnect_callback)
		hfp->disconnect_callback(hfp->disconnect_data);

	hfp->in_disconnect = false;

	return false;
}

bool hfp_gw_set_disconnect_handler(struct hfp_gw *hfp,
					hfp_disconnect_func_t callback,
					void *user_data,
					hfp_destroy_func_t destroy)
{
	if (!hfp)
		return false;

	if (hfp->disconnect_destroy)
		hfp->disconnect_destroy(hfp->disconnect_data);

	if (!io_set_disconnect_handler(hfp->io, io_disconnected, hfp,
						disconnect_watch_destroy)) {
		hfp->disconnect_callback = NULL;
		hfp->disconnect_destroy = NULL;
		hfp->disconnect_data = NULL;
		return false;
	}

	hfp->disconnect_callback = callback;
	hfp->disconnect_destroy = destroy;
	hfp->disconnect_data = user_data;

	return true;
}

bool hfp_gw_disconnect(struct hfp_gw *hfp)
{
	if (!hfp)
		return false;

	return io_shutdown(hfp->io);
}

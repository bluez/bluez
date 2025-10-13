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
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>

#include "src/shared/util.h"
#include "src/shared/ringbuf.h"
#include "src/shared/queue.h"
#include "src/shared/io.h"
#include "src/shared/hfp.h"

#define DBG(_hfp, fmt, arg...) \
	hfp_debug(_hfp->debug_callback, _hfp->debug_data, "%s:%s() " fmt, \
						__FILE__, __func__, ## arg)

#define HFP_HF_FEATURES	(HFP_HF_FEAT_CLIP | HFP_HF_FEAT_ESCO_S4_T2)

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

typedef void (*ciev_func_t)(uint8_t val, void *user_data);

struct indicator {
	uint8_t index;
	uint32_t min;
	uint32_t max;
	uint32_t val;
	ciev_func_t cb;
};

struct hfp_hf {
	int ref_count;
	int fd;
	bool close_on_unref;
	struct io *io;
	struct ringbuf *read_buf;
	struct ringbuf *write_buf;

	bool writer_active;
	struct queue *cmd_queue;

	struct queue *event_handlers;

	hfp_debug_func_t debug_callback;
	hfp_destroy_func_t debug_destroy;
	void *debug_data;

	hfp_disconnect_func_t disconnect_callback;
	hfp_destroy_func_t disconnect_destroy;
	void *disconnect_data;

	bool in_disconnect;
	bool destroyed;

	struct hfp_hf_callbacks *callbacks;
	void *callbacks_data;

	uint32_t features;
	struct indicator ag_ind[HFP_INDICATOR_LAST];
	bool service;
	uint8_t signal;
	bool roaming;
	uint8_t battchg;

	struct queue *calls;
	char *dialing_number;
};

struct cmd_handler {
	char *prefix;
	void *user_data;
	hfp_destroy_func_t destroy;
	hfp_result_func_t callback;
};

struct hfp_context {
	const char *data;
	unsigned int offset;
};

struct cmd_response {
	hfp_response_func_t resp_cb;
	struct hfp_context *response;
	char *resp_data;
	void *user_data;
};

struct event_handler {
	char *prefix;
	void *user_data;
	hfp_destroy_func_t destroy;
	hfp_hf_result_func_t callback;
};

struct hf_call {
	uint id;
	enum hfp_call_status status;
	char *line_id;
	uint type;

	struct hfp_hf *hfp;
};

static void hfp_debug(hfp_debug_func_t debug_func, void *debug_data,
						const char *format, ...)
{
	va_list ap;

	if (!debug_func || !format)
		return;

	va_start(ap, format);
	util_debug_va(debug_func, debug_data, format, ap);
	va_end(ap);
}

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

	if (strcmp(handler->prefix, prefix) != 0)
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

static void skip_whitespace(struct hfp_context *context)
{
	while (context->data[context->offset] == ' ')
		context->offset++;
}

static void handle_unknown_at_command(struct hfp_gw *hfp,
							const char *data)
{
	if (hfp->command_callback) {
		hfp->result_pending = true;
		hfp->command_callback(data, hfp->command_data);
	} else {
		hfp_gw_send_result(hfp, HFP_RESULT_ERROR);
	}
}

static bool handle_at_command(struct hfp_gw *hfp, const char *data)
{
	struct cmd_handler *handler;
	const char *separators = ";?=\0";
	struct hfp_context context;
	enum hfp_gw_cmd_type type;
	char lookup_prefix[18];
	uint8_t pref_len = 0;
	const char *prefix;
	int i;

	context.offset = 0;
	context.data = data;

	skip_whitespace(&context);

	if (strlen(data + context.offset) < 3)
		return false;

	if (strncmp(data + context.offset, "AT", 2))
		if (strncmp(data + context.offset, "at", 2))
			return false;

	context.offset += 2;
	prefix = data + context.offset;

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
	context.offset += pref_len;

	if (lookup_prefix[0] == 'D') {
		type = HFP_GW_CMD_TYPE_SET;
		goto done;
	}

	if (data[context.offset] == '=') {
		context.offset++;
		if (data[context.offset] == '?') {
			context.offset++;
			type = HFP_GW_CMD_TYPE_TEST;
		} else {
			type = HFP_GW_CMD_TYPE_SET;
		}
		goto done;
	}

	if (data[context.offset] == '?') {
		context.offset++;
		type = HFP_GW_CMD_TYPE_READ;
		goto done;
	}

	type = HFP_GW_CMD_TYPE_COMMAND;

done:

	handler = queue_find(hfp->cmd_handlers, match_handler_prefix,
								lookup_prefix);
	if (!handler) {
		handle_unknown_at_command(hfp, data);
		return true;
	}

	hfp->result_pending = true;
	handler->callback(&context, type, handler->user_data);

	return true;
}

static void next_field(struct hfp_context *context)
{
	if (context->data[context->offset] == ',')
		context->offset++;
}

bool hfp_context_get_number_default(struct hfp_context *context,
						unsigned int *val,
						unsigned int default_val)
{
	skip_whitespace(context);

	if (context->data[context->offset] == ',') {
		if (val)
			*val = default_val;

		context->offset++;
		return true;
	}

	return hfp_context_get_number(context, val);
}

bool hfp_context_get_number(struct hfp_context *context,
							unsigned int *val)
{
	unsigned int i;
	int tmp = 0;

	skip_whitespace(context);

	i = context->offset;

	while (context->data[i] >= '0' && context->data[i] <= '9')
		tmp = tmp * 10 + context->data[i++] - '0';

	if (i == context->offset)
		return false;

	if (val)
		*val = tmp;
	context->offset = i;

	skip_whitespace(context);
	next_field(context);

	return true;
}

bool hfp_context_open_container(struct hfp_context *context)
{
	skip_whitespace(context);

	/* The list shall be preceded by a left parenthesis "(") */
	if (context->data[context->offset] != '(')
		return false;

	context->offset++;

	return true;
}

bool hfp_context_close_container(struct hfp_context *context)
{
	skip_whitespace(context);

	/* The list shall be followed by a right parenthesis (")" V250 5.7.3.1*/
	if (context->data[context->offset] != ')')
		return false;

	context->offset++;

	next_field(context);

	return true;
}

bool hfp_context_get_string(struct hfp_context *context, char *buf,
								uint8_t len)
{
	int i = 0;
	const char *data = context->data;
	unsigned int offset;

	skip_whitespace(context);

	if (data[context->offset] != '"')
		return false;

	offset = context->offset;
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

	context->offset = offset;

	skip_whitespace(context);
	next_field(context);

	return true;
}

bool hfp_context_get_unquoted_string(struct hfp_context *context,
							char *buf, uint8_t len)
{
	const char *data = context->data;
	unsigned int offset;
	int i = 0;
	char c;

	skip_whitespace(context);

	c = data[context->offset];
	if (c == '"' || c == ')' || c == '(')
		return false;

	offset = context->offset;

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

	context->offset = offset;

	next_field(context);

	return true;
}

bool hfp_context_has_next(struct hfp_context *context)
{
	return context->data[context->offset] != '\0';
}

void hfp_context_skip_field(struct hfp_context *context)
{
	const char *data = context->data;
	unsigned int offset = context->offset;

	while (data[offset] != '\0' && data[offset] != ',')
		offset++;

	context->offset = offset;
	next_field(context);
}

bool hfp_context_get_range(struct hfp_context *context, uint32_t *min,
								uint32_t *max)
{
	uint32_t l, h;
	uint32_t start;

	start = context->offset;

	if (!hfp_context_get_number(context, &l))
		goto failed;

	if (context->data[context->offset] != '-')
		goto failed;

	context->offset++;

	if (!hfp_context_get_number(context, &h))
		goto failed;

	*min = l;
	*max = h;

	next_field(context);

	return true;

failed:
	context->offset = start;
	return false;
}

static void process_input(struct hfp_gw *hfp)
{
	char *str, *ptr;
	size_t len, count;
	bool free_ptr = false;
	bool read_again;

	do {
		str = ringbuf_peek(hfp->read_buf, 0, &len);
		if (!str)
			return;

		ptr = memchr(str, '\r', len);
		if (!ptr) {
			char *str2;
			size_t len2;

			/*
			 * If there is no more data in ringbuffer,
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

			count = len2 + len;
			ptr = malloc(count);
			if (!ptr)
				return;

			memcpy(ptr, str, len);
			memcpy(ptr + len, str2, len2);

			free_ptr = true;
			str = ptr;
		} else {
			count = ptr - str;
			*ptr = '\0';
		}

		if (!handle_at_command(hfp, str))
			/*
			 * Command is not handled that means that was some
			 * trash. Let's skip that and keep reading from ring
			 * buffer.
			 */
			read_again = true;
		else
			/*
			 * Command has been handled. If we are waiting for a
			 * result from upper layer, we can stop reading. If we
			 * already reply i.e. ERROR on unknown command, then we
			 * can keep reading ring buffer. Actually ring buffer
			 * should be empty but lets just look there.
			 */
			read_again = !hfp->result_pending;

		ringbuf_drain(hfp->read_buf, count + 1);

		if (free_ptr)
			free(ptr);

	} while (read_again);
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

	if (!io_set_read_handler(hfp->io, can_read_data, hfp,
							read_watch_destroy)) {
		queue_destroy(hfp->cmd_handlers, destroy_cmd_handler);
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
	case HFP_RESULT_RING:
	case HFP_RESULT_NO_CARRIER:
	case HFP_RESULT_BUSY:
	case HFP_RESULT_NO_ANSWER:
	case HFP_RESULT_DELAYED:
	case HFP_RESULT_REJECTED:
	case HFP_RESULT_CME_ERROR:
	case HFP_RESULT_NO_DIALTONE:
	case HFP_RESULT_CONNECT:
	default:
		return false;
	}

	if (ringbuf_printf(hfp->write_buf, "\r\n%s\r\n", str) < 0)
		return false;

	wakeup_writer(hfp);

	/*
	 * There might be already something to read in the ring buffer.
	 * If so, let's read it.
	 */
	if (hfp->result_pending) {
		hfp->result_pending = false;
		process_input(hfp);
	}

	return true;
}

bool hfp_gw_send_error(struct hfp_gw *hfp, enum hfp_error error)
{
	if (!hfp)
		return false;

	if (ringbuf_printf(hfp->write_buf, "\r\n+CME ERROR: %u\r\n", error) < 0)
		return false;

	wakeup_writer(hfp);

	/*
	 * There might be already something to read in the ring buffer.
	 * If so, let's read it.
	 */
	if (hfp->result_pending) {
		hfp->result_pending = false;
		process_input(hfp);
	}

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

static bool match_handler_event_prefix(const void *a, const void *b)
{
	const struct event_handler *handler = a;
	const char *prefix = b;

	if (strcmp(handler->prefix, prefix) != 0)
		return false;

	return true;
}

static void destroy_event_handler(void *data)
{
	struct event_handler *handler = data;

	if (handler->destroy)
		handler->destroy(handler->user_data);

	free(handler->prefix);

	free(handler);
}

static bool hf_can_write_data(struct io *io, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	ssize_t bytes_written;

	bytes_written = ringbuf_write(hfp->write_buf, hfp->fd);
	if (bytes_written < 0)
		return false;

	if (ringbuf_len(hfp->write_buf) > 0)
		return true;

	return false;
}

static void hf_write_watch_destroy(void *user_data)
{
	struct hfp_hf *hfp = user_data;

	hfp->writer_active = false;
}

static void hf_skip_whitespace(struct hfp_context *context)
{
	while (context->data[context->offset] == ' ')
		context->offset++;
}

static bool is_response(const char *prefix, enum hfp_result *result,
						enum hfp_error *cme_err,
						struct hfp_context *context)
{
	if (strcmp(prefix, "OK") == 0) {
		*result = HFP_RESULT_OK;
		/*
		 * Set cme_err to 0 as this is not valid when result is not
		 * CME ERROR
		 */
		*cme_err = 0;
		return true;
	}

	if (strcmp(prefix, "ERROR") == 0) {
		*result = HFP_RESULT_ERROR;
		*cme_err = 0;
		return true;
	}

	if (strcmp(prefix, "NO CARRIER") == 0) {
		*result = HFP_RESULT_NO_CARRIER;
		*cme_err = 0;
		return true;
	}

	if (strcmp(prefix, "NO ANSWER") == 0) {
		*result = HFP_RESULT_NO_ANSWER;
		*cme_err = 0;
		return true;
	}

	if (strcmp(prefix, "BUSY") == 0) {
		*result = HFP_RESULT_BUSY;
		*cme_err = 0;
		return true;
	}

	if (strcmp(prefix, "DELAYED") == 0) {
		*result = HFP_RESULT_DELAYED;
		*cme_err = 0;
		return true;
	}

	if (strcmp(prefix, "BLACKLISTED") == 0) {
		*result = HFP_RESULT_REJECTED;
		*cme_err = 0;
		return true;
	}

	if (strcmp(prefix, "+CME ERROR") == 0) {
		uint32_t val;

		*result = HFP_RESULT_CME_ERROR;

		if (hfp_context_get_number(context, &val) &&
					val <= HFP_ERROR_NETWORK_NOT_ALLOWED)
			*cme_err = val;
		else
			*cme_err = HFP_ERROR_AG_FAILURE;

		return true;
	}

	return false;
}

static void hf_wakeup_writer(struct hfp_hf *hfp)
{
	if (hfp->writer_active)
		return;

	if (!ringbuf_len(hfp->write_buf))
		return;

	if (!io_set_write_handler(hfp->io, hf_can_write_data,
					hfp, hf_write_watch_destroy))
		return;

	hfp->writer_active = true;
}

static void hf_call_prefix_handler(struct hfp_hf *hfp, const char *data)
{
	struct event_handler *handler;
	const char *separators = ";:\0";
	struct hfp_context context;
	enum hfp_result result;
	enum hfp_error cme_err;
	char lookup_prefix[18] = {};
	uint8_t pref_len = 0;
	const char *prefix;
	int i;

	context.offset = 0;
	context.data = data;

	hf_skip_whitespace(&context);

	if (strlen(data + context.offset) < 2)
		return;

	prefix = data + context.offset;

	pref_len = strcspn(prefix, separators);
	if (pref_len > 17 || pref_len < 2)
		return;

	for (i = 0; i < pref_len; i++)
		lookup_prefix[i] = toupper(prefix[i]);

	lookup_prefix[pref_len] = '\0';
	context.offset += pref_len + 1;

	if (is_response(lookup_prefix, &result, &cme_err, &context)) {
		struct cmd_response *cmd;

		cmd = queue_peek_head(hfp->cmd_queue);
		if (!cmd)
			return;

		cmd->resp_cb(result, cme_err, cmd->user_data);

		queue_remove(hfp->cmd_queue, cmd);
		free(cmd);

		hf_wakeup_writer(hfp);
		return;
	}

	handler = queue_find(hfp->event_handlers, match_handler_event_prefix,
								lookup_prefix);
	if (!handler)
		return;

	handler->callback(&context, handler->user_data);
}

static char *find_cr_lf(char *str, size_t len)
{
	char *ptr;
	size_t count, offset;

	offset = 0;

	ptr = memchr(str, '\r', len);
	while (ptr) {
		/*
		 * Check if there is more data after '\r'. If so check for
		 * '\n'
		 */
		count = ptr - str;
		if ((count < (len - 1)) && *(ptr + 1) == '\n')
			return ptr;

		/* There is only '\r'? Let's try to find next one */
		offset += count + 1;

		if (offset >= len)
			return NULL;

		ptr = memchr(str + offset, '\r', len - offset);
	}

	return NULL;
}

static void hf_process_input(struct hfp_hf *hfp)
{
	char *str, *ptr, *str2, *tmp;
	size_t len, count, offset, len2;
	bool free_tmp = false;

	str = ringbuf_peek(hfp->read_buf, 0, &len);
	if (!str)
		return;

	offset = 0;

	ptr = find_cr_lf(str, len);
	while (ptr) {
		count = ptr - (str + offset);
		if (count == 0) {
			/* 2 is for <cr><lf> */
			offset += 2;
		} else {
			*ptr = '\0';
			hf_call_prefix_handler(hfp, str + offset);
			offset += count + 2;
		}

		ptr = find_cr_lf(str + offset, len - offset);
	}

	/*
	 * Just check if there is no wrapped data in ring buffer.
	 * Should not happen too often
	 */
	if (len == ringbuf_len(hfp->read_buf))
		goto done;

	str2 = ringbuf_peek(hfp->read_buf, len, &len2);
	if (!str2)
		goto done;

	ptr = find_cr_lf(str2, len2);
	if (!ptr) {
		/* Might happen that we wrap between \r and \n */
		ptr = memchr(str2, '\n', len2);
		if (!ptr)
			goto done;
	}

	count = ptr - str2;

	if (count) {
		*ptr = '\0';

		tmp = malloc(len + count);
		if (!tmp)
			goto done;

		/* "str" here is not a string so we need to use memcpy */
		memcpy(tmp, str, len);
		memcpy(tmp + len, str2, count);

		free_tmp = true;
	} else {
		str[len-1] = '\0';
		tmp = str;
	}

	hf_call_prefix_handler(hfp, tmp);
	offset += count;

done:
	ringbuf_drain(hfp->read_buf, offset);

	if (free_tmp)
		free(tmp);
}

static bool hf_can_read_data(struct io *io, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	ssize_t bytes_read;

	bytes_read = ringbuf_read(hfp->read_buf, hfp->fd);
	if (bytes_read < 0)
		return false;

	hf_process_input(hfp);

	return true;
}

struct hfp_hf *hfp_hf_new(int fd)
{
	struct hfp_hf *hfp;

	if (fd < 0)
		return NULL;

	hfp = new0(struct hfp_hf, 1);
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

	hfp->event_handlers = queue_new();
	hfp->cmd_queue = queue_new();
	hfp->calls = queue_new();
	hfp->writer_active = false;

	if (!io_set_read_handler(hfp->io, hf_can_read_data, hfp,
							read_watch_destroy)) {
		queue_destroy(hfp->event_handlers,
						destroy_event_handler);
		io_destroy(hfp->io);
		ringbuf_free(hfp->write_buf);
		ringbuf_free(hfp->read_buf);
		free(hfp);
		return NULL;
	}

	return hfp_hf_ref(hfp);
}

struct hfp_hf *hfp_hf_ref(struct hfp_hf *hfp)
{
	if (!hfp)
		return NULL;

	__sync_fetch_and_add(&hfp->ref_count, 1);

	return hfp;
}

static void remove_call_cb(void *user_data)
{
	struct hf_call *call = user_data;
	struct hfp_hf *hfp = call->hfp;

	if (hfp->callbacks && hfp->callbacks->call_removed)
		hfp->callbacks->call_removed(call->id, hfp->callbacks_data);

	free(call->line_id);
	free(call);
}

void hfp_hf_unref(struct hfp_hf *hfp)
{
	if (!hfp)
		return;

	if (__sync_sub_and_fetch(&hfp->ref_count, 1))
		return;

	io_set_write_handler(hfp->io, NULL, NULL, NULL);
	io_set_read_handler(hfp->io, NULL, NULL, NULL);
	io_set_disconnect_handler(hfp->io, NULL, NULL, NULL);

	io_destroy(hfp->io);
	hfp->io = NULL;

	if (hfp->close_on_unref)
		close(hfp->fd);

	hfp_hf_set_debug(hfp, NULL, NULL, NULL);

	ringbuf_free(hfp->read_buf);
	hfp->read_buf = NULL;

	ringbuf_free(hfp->write_buf);
	hfp->write_buf = NULL;

	queue_destroy(hfp->event_handlers, destroy_event_handler);
	hfp->event_handlers = NULL;

	queue_destroy(hfp->cmd_queue, free);
	hfp->cmd_queue = NULL;

	queue_destroy(hfp->calls, remove_call_cb);
	hfp->calls = NULL;

	if (hfp->dialing_number) {
		free(hfp->dialing_number);
		hfp->dialing_number = NULL;
	}

	if (!hfp->in_disconnect) {
		free(hfp);
		return;
	}

	hfp->destroyed = true;
}

static void hf_read_tracing(const void *buf, size_t count,
							void *user_data)
{
	struct hfp_hf *hfp = user_data;

	util_hexdump('>', buf, count, hfp->debug_callback, hfp->debug_data);
}

static void hf_write_tracing(const void *buf, size_t count,
							void *user_data)
{
	struct hfp_hf *hfp = user_data;

	util_hexdump('<', buf, count, hfp->debug_callback, hfp->debug_data);
}

bool hfp_hf_set_debug(struct hfp_hf *hfp, hfp_debug_func_t callback,
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
		ringbuf_set_input_tracing(hfp->read_buf, hf_read_tracing, hfp);
		ringbuf_set_input_tracing(hfp->write_buf, hf_write_tracing,
									hfp);
	} else {
		ringbuf_set_input_tracing(hfp->read_buf, NULL, NULL);
		ringbuf_set_input_tracing(hfp->write_buf, NULL, NULL);
	}

	return true;
}

bool hfp_hf_set_close_on_unref(struct hfp_hf *hfp, bool do_close)
{
	if (!hfp)
		return false;

	hfp->close_on_unref = do_close;

	return true;
}

bool hfp_hf_send_command(struct hfp_hf *hfp, hfp_response_func_t resp_cb,
				void *user_data, const char *format, ...)
{
	va_list ap;
	char *fmt;
	int len;
	struct cmd_response *cmd;

	if (!hfp || !format || !resp_cb)
		return false;

	if (asprintf(&fmt, "%s\r", format) < 0)
		return false;

	cmd = new0(struct cmd_response, 1);

	va_start(ap, format);
	len = ringbuf_vprintf(hfp->write_buf, fmt, ap);
	va_end(ap);

	free(fmt);

	if (len < 0) {
		free(cmd);
		return false;
	}

	cmd->resp_cb = resp_cb;
	cmd->user_data = user_data;

	if (!queue_push_tail(hfp->cmd_queue, cmd)) {
		ringbuf_drain(hfp->write_buf, len);
		free(cmd);
		return false;
	}

	hf_wakeup_writer(hfp);

	return true;
}

bool hfp_hf_register(struct hfp_hf *hfp, hfp_hf_result_func_t callback,
						const char *prefix,
						void *user_data,
						hfp_destroy_func_t destroy)
{
	struct event_handler *handler;

	if (!callback)
		return false;

	handler = new0(struct event_handler, 1);
	handler->callback = callback;
	handler->user_data = user_data;

	handler->prefix = strdup(prefix);
	if (!handler->prefix) {
		free(handler);
		return false;
	}

	if (queue_find(hfp->event_handlers, match_handler_event_prefix,
							handler->prefix)) {
		destroy_event_handler(handler);
		return false;
	}

	handler->destroy = destroy;

	return queue_push_tail(hfp->event_handlers, handler);
}

bool hfp_hf_unregister(struct hfp_hf *hfp, const char *prefix)
{
	struct cmd_handler *handler;

	/* Cast to void as queue_remove needs that */
	handler = queue_remove_if(hfp->event_handlers,
						match_handler_event_prefix,
						(void *) prefix);

	if (!handler)
		return false;

	destroy_event_handler(handler);

	return true;
}

static void hf_disconnect_watch_destroy(void *user_data)
{
	struct hfp_hf *hfp = user_data;

	if (hfp->disconnect_destroy)
		hfp->disconnect_destroy(hfp->disconnect_data);

	if (hfp->destroyed)
		free(hfp);
}

static bool hf_io_disconnected(struct io *io, void *user_data)
{
	struct hfp_hf *hfp = user_data;

	hfp->in_disconnect = true;

	if (hfp->disconnect_callback)
		hfp->disconnect_callback(hfp->disconnect_data);

	hfp->in_disconnect = false;

	return false;
}

bool hfp_hf_set_disconnect_handler(struct hfp_hf *hfp,
						hfp_disconnect_func_t callback,
						void *user_data,
						hfp_destroy_func_t destroy)
{
	if (!hfp)
		return false;

	if (hfp->disconnect_destroy)
		hfp->disconnect_destroy(hfp->disconnect_data);

	if (!io_set_disconnect_handler(hfp->io, hf_io_disconnected, hfp,
						hf_disconnect_watch_destroy)) {
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

bool hfp_hf_disconnect(struct hfp_hf *hfp)
{
	if (!hfp)
		return false;

	return io_shutdown(hfp->io);
}

static bool call_id_match(const void *data, const void *match_data)
{
	const struct hf_call *call = data;
	uint id = PTR_TO_UINT(match_data);

	return (call->id == id);
}

static uint next_call_index(struct hfp_hf *hfp)
{
	for (uint i = 1; i < UINT_MAX; i++) {
		if (!queue_find(hfp->calls, call_id_match, UINT_TO_PTR(i)))
			return i;
	}

	return 0;
}

static struct hf_call *call_new(struct hfp_hf *hfp, unsigned int id,
						enum hfp_call_status status,
						char *number)
{
	struct hf_call *call;

	call = new0(struct hf_call, 1);
	call->id = id;
	call->status = status;
	if (number)
		call->line_id = strdup(number);
	call->hfp = hfp;
	queue_push_tail(hfp->calls, call);

	if (hfp->callbacks && hfp->callbacks->call_added)
		hfp->callbacks->call_added(call->id, call->status,
						hfp->callbacks_data);

	return call;
}

static void ciev_service_cb(uint8_t val, void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "%u", val);

	if (val < hfp->ag_ind[HFP_INDICATOR_SERVICE].min ||
			val > hfp->ag_ind[HFP_INDICATOR_SERVICE].max) {
		DBG(hfp, "hf: Incorrect state: %u", val);
		return;
	}

	hfp->service = val;
	if (hfp->callbacks && hfp->callbacks->update_indicator)
		hfp->callbacks->update_indicator(HFP_INDICATOR_SERVICE, val,
							hfp->callbacks_data);
}

static bool update_call_to_active(struct hfp_hf *hfp)
{
	const struct queue_entry *entry;
	struct hf_call *call;

	for (entry = queue_get_entries(hfp->calls); entry;
					entry = entry->next) {
		call = entry->data;

		if (call->status == CALL_STATUS_DIALING ||
			call->status == CALL_STATUS_ALERTING ||
			call->status == CALL_STATUS_INCOMING) {
			call->status = CALL_STATUS_ACTIVE;
			if (hfp->callbacks &&
				hfp->callbacks->call_status_updated)
				hfp->callbacks->call_status_updated(
					call->id,
					call->status,
					hfp->callbacks_data);
			return true;
		}
	}

	return false;
}

static void ciev_call_cb(uint8_t val, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	uint id;

	DBG(hfp, "%u", val);

	if (val < hfp->ag_ind[HFP_INDICATOR_CALL].min ||
			val > hfp->ag_ind[HFP_INDICATOR_CALL].max) {
		DBG(hfp, "hf: Incorrect call state: %u", val);
		return;
	}

	switch (val) {
	case CIND_CALL_NONE:
		/* Remove all calls */
		queue_remove_all(hfp->calls, NULL, hfp, remove_call_cb);
		break;
	case CIND_CALL_IN_PROGRESS:
		{
			/* Find incoming, dialing or alerting call to change
			 * it to active
			 */
			if (update_call_to_active(hfp))
				return;

			/* else create new already active call */
			id = next_call_index(hfp);
			if (id == 0) {
				DBG(hfp, "hf: No new call index available");
				return;
			}
			call_new(hfp, id, CALL_STATUS_ACTIVE, NULL);
		}
		break;
	default:
		DBG(hfp, "hf: Unsupported call state: %u", val);
	}
}

static bool call_outgoing_match(const void *data, const void *match_data)
{
	const struct hf_call *call = data;

	return (call->status == CALL_STATUS_DIALING ||
				    call->status == CALL_STATUS_ALERTING);
}

static bool call_incoming_match(const void *data, const void *match_data)
{
	const struct hf_call *call = data;

	return (call->status == CALL_STATUS_INCOMING);
}

static bool call_setup_match(const void *data, const void *match_data)
{
	return (call_outgoing_match(data, match_data) ||
				    call_incoming_match(data, match_data));
}

static bool call_active_match(const void *data, const void *match_data)
{
	const struct hf_call *call = data;

	return (call->status == CALL_STATUS_ACTIVE);
}

static void bsir_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	unsigned int val;

	DBG(hfp, "");

	if (!hfp_context_get_number(context, &val))
		return;

	if (hfp->callbacks && hfp->callbacks->update_inband_ring)
		hfp->callbacks->update_inband_ring(!!val, hfp->callbacks_data);
}

static void ciev_callsetup_cb(uint8_t val, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	struct hf_call *call;
	uint id;
	enum hfp_call_status status;

	DBG(hfp, "%u", val);

	if (val < hfp->ag_ind[HFP_INDICATOR_CALLSETUP].min ||
			val > hfp->ag_ind[HFP_INDICATOR_CALLSETUP].max) {
		DBG(hfp, "hf: Incorrect call setup state: %u", val);
		return;
	}

	switch (val) {
	case CIND_CALLSETUP_NONE:
		/* remove call in setup phase */
		queue_remove_all(hfp->calls, call_setup_match, hfp,
							remove_call_cb);
		break;
	case CIND_CALLSETUP_INCOMING:
		if (queue_length(hfp->calls) != 0) {
			DBG(hfp, "hf: Call already exists");
			return;
		}

		id = next_call_index(hfp);
		if (id == 0) {
			DBG(hfp, "hf: No new call index available");
			return;
		}
		call_new(hfp, id, CALL_STATUS_INCOMING, NULL);
		break;
	case CIND_CALLSETUP_DIALING:
	case CIND_CALLSETUP_ALERTING:
		if (val == CIND_CALLSETUP_DIALING)
			status = CALL_STATUS_DIALING;
		else
			status = CALL_STATUS_ALERTING;

		if (queue_find(hfp->calls, call_active_match, NULL)) {
			DBG(hfp, "hf: Error: active call");
			return;
		}

		call = queue_find(hfp->calls, call_outgoing_match, NULL);
		if (call && call->status != status) {
			call->status = status;
			if (hfp->callbacks &&
				hfp->callbacks->call_status_updated)
				hfp->callbacks->call_status_updated(call->id,
							call->status,
							hfp->callbacks_data);
			return;
		}

		id = next_call_index(hfp);
		if (id == 0) {
			DBG(hfp, "hf: No new call index available");
			return;
		}
		call_new(hfp, id, status, hfp->dialing_number);
		if (hfp->dialing_number) {
			free(hfp->dialing_number);
			hfp->dialing_number = NULL;
		}
		break;
	}
}

static void ciev_callheld_cb(uint8_t val, void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "%u", val);

	if (val < hfp->ag_ind[HFP_INDICATOR_CALLHELD].min ||
			val > hfp->ag_ind[HFP_INDICATOR_CALLHELD].max) {
		DBG(hfp, "hf: Incorrect call held state: %u", val);
		return;
	}
}

static void ciev_signal_cb(uint8_t val, void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "%u", val);

	if (val < hfp->ag_ind[HFP_INDICATOR_SIGNAL].min ||
			val > hfp->ag_ind[HFP_INDICATOR_SIGNAL].max) {
		DBG(hfp, "hf: Incorrect signal value: %u", val);
		return;
	}

	hfp->signal = val;
	if (hfp->callbacks && hfp->callbacks->update_indicator)
		hfp->callbacks->update_indicator(HFP_INDICATOR_SIGNAL, val,
							hfp->callbacks_data);
}

static void ciev_roam_cb(uint8_t val, void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "%u", val);

	if (val < hfp->ag_ind[HFP_INDICATOR_ROAM].min ||
			val > hfp->ag_ind[HFP_INDICATOR_ROAM].max) {
		DBG(hfp, "hf: Incorrect roaming state: %u", val);
		return;
	}

	hfp->roaming = val;
	if (hfp->callbacks && hfp->callbacks->update_indicator)
		hfp->callbacks->update_indicator(HFP_INDICATOR_ROAM, val,
							hfp->callbacks_data);
}

static void ciev_battchg_cb(uint8_t val, void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "%u", val);

	if (val < hfp->ag_ind[HFP_INDICATOR_BATTCHG].min ||
			val > hfp->ag_ind[HFP_INDICATOR_BATTCHG].max) {
		DBG(hfp, "hf: Incorrect battery charge value: %u", val);
		return;
	}

	hfp->battchg = val;
	if (hfp->callbacks && hfp->callbacks->update_indicator)
		hfp->callbacks->update_indicator(HFP_INDICATOR_BATTCHG, val,
							hfp->callbacks_data);
}

static void set_indicator_value(uint8_t index, unsigned int val,
	struct indicator *ag_ind, struct hfp_hf *hfp)
{
	int i;

	for (i = 0; i < HFP_INDICATOR_LAST; i++) {
		if (index != ag_ind[i].index)
			continue;

		ag_ind[i].val = val;
		ag_ind[i].cb(val, hfp);
		return;
	}
}

static void ciev_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	unsigned int index, val;

	DBG(hfp, "");

	if (!hfp_context_get_number(context, &index))
		return;

	if (!hfp_context_get_number(context, &val))
		return;

	set_indicator_value(index, val, hfp->ag_ind, hfp);
}

static void cops_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	unsigned int mode, val;
	char name[255];

	DBG(hfp, "");

	if (!hfp_context_get_number(context, &mode))
		return;

	if (!hfp_context_get_number(context, &val))
		return;

	if (!hfp_context_get_string(context, name, sizeof(name))) {
		DBG(hfp, "hf: Could not get string");
		return;
	}

	if (hfp->callbacks && hfp->callbacks->update_operator)
		hfp->callbacks->update_operator(name, hfp->callbacks_data);
}

static void clip_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	char number[255];
	unsigned int type;
	struct hf_call *call;

	DBG(hfp, "");

	if (!hfp_context_get_string(context, number, sizeof(number))) {
		DBG(hfp, "hf: Could not get string");
		return;
	}

	if (!hfp_context_get_number(context, &type))
		return;

	call = queue_find(hfp->calls, call_incoming_match, NULL);
	if (!call) {
		DBG(hfp, "hf: no incoming call");
		return;
	}

	if (call->line_id && strcmp(call->line_id, number) == 0 &&
		call->type == type)
		return;

	if (call->line_id)
		free(call->line_id);
	call->line_id = strdup(number);
	call->type = type;

	if (hfp->callbacks && hfp->callbacks->call_line_id_updated)
		hfp->callbacks->call_line_id_updated(call->id, call->line_id,
							call->type,
							hfp->callbacks_data);
}

static void clip_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "");

	if (result != HFP_RESULT_OK) {
		DBG(hfp, "hf: CLIP error: %d", result);
		goto failed;
	}

	if (hfp->callbacks->session_ready)
		hfp->callbacks->session_ready(HFP_RESULT_OK, 0,
						hfp->callbacks_data);

	return;

failed:
	if (hfp->callbacks->session_ready)
		hfp->callbacks->session_ready(result, cme_err,
						hfp->callbacks_data);
}

static void cops_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "");

	if (result != HFP_RESULT_OK) {
		DBG(hfp, "hf: COPS? error: %d", result);
		goto failed;
	}

	/* SLC creation done, continue with default setup */
	if (!hfp_hf_send_command(hfp, clip_resp, hfp,
		"AT+CLIP=1")) {
		DBG(hfp, "hf: Could not send AT+CLIP=1");
		result = HFP_RESULT_ERROR;
		goto failed;
	}

	return;

failed:
	if (hfp->callbacks->session_ready)
		hfp->callbacks->session_ready(result, cme_err,
						hfp->callbacks_data);
}

static void cops_conf_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "");

	if (result != HFP_RESULT_OK) {
		DBG(hfp, "hf: COPS= error: %d", result);
		goto failed;
	}

	/* SLC creation done, continue with default setup */
	if (!hfp_hf_send_command(hfp, cops_resp, hfp,
		"AT+COPS?")) {
		DBG(hfp, "hf: Could not send AT+COPS?");
		result = HFP_RESULT_ERROR;
		goto failed;
	}

	return;

failed:
	if (hfp->callbacks->session_ready)
		hfp->callbacks->session_ready(result, cme_err,
						hfp->callbacks_data);
}

static void slc_cmer_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "");

	if (result != HFP_RESULT_OK) {
		DBG(hfp, "hf: CMER error: %d", result);
		goto failed;
	}

	/* SLC creation done, continue with default setup */
	if (!hfp_hf_send_command(hfp, cops_conf_resp, hfp,
		"AT+COPS=3,0")) {
		DBG(hfp, "hf: Could not send AT+COPS=3,0");
		result = HFP_RESULT_ERROR;
		goto failed;
	}

	/* Register unsolicited results handlers */
	if (hfp->features & HFP_AG_FEAT_IN_BAND_RING_TONE)
		hfp_hf_register(hfp, bsir_cb, "+BSIR", hfp, NULL);
	hfp_hf_register(hfp, ciev_cb, "+CIEV", hfp, NULL);
	hfp_hf_register(hfp, clip_cb, "+CLIP", hfp, NULL);
	hfp_hf_register(hfp, cops_cb, "+COPS", hfp, NULL);

	return;

failed:
	if (hfp->callbacks->session_ready)
		hfp->callbacks->session_ready(result, cme_err,
						hfp->callbacks_data);
}

static void slc_cind_status_cb(struct hfp_context *context,
	void *user_data)
{
	struct hfp_hf *hfp = user_data;
	uint8_t index = 1;

	while (hfp_context_has_next(context)) {
		uint32_t val;

		if (!hfp_context_get_number(context, &val)) {
			DBG(hfp, "hf: Error on CIND status response");
			return;
		}

		set_indicator_value(index++, val, hfp->ag_ind, hfp);
	}
}

static void slc_cind_status_resp(enum hfp_result result,
	enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "");

	hfp_hf_unregister(hfp, "+CIND");

	if (result != HFP_RESULT_OK) {
		DBG(hfp, "hf: CIND error: %d", result);
		goto failed;
	}

	/* Continue with SLC creation */
	if (!hfp_hf_send_command(hfp, slc_cmer_resp, hfp,
		"AT+CMER=3,0,0,1")) {
		DBG(hfp, "hf: Could not send AT+CMER");
		result = HFP_RESULT_ERROR;
		goto failed;
	}

	return;

failed:
	if (hfp->callbacks->session_ready)
		hfp->callbacks->session_ready(result, cme_err,
						hfp->callbacks_data);
}

static void set_indicator_parameters(struct hfp_hf *hfp, uint8_t index,
	const char *indicator,
	unsigned int min,
	unsigned int max)
{
	struct indicator *ag_ind = hfp->ag_ind;

	DBG(hfp, "%s, %i", indicator, index);

	if (strcmp("service", indicator) == 0) {
		if (min != 0 || max != 1) {
			DBG(hfp, "hf: Invalid min/max values for service,"
				" expected (0,1) got (%u,%u)", min, max);
			return;
		}
		ag_ind[HFP_INDICATOR_SERVICE].index = index;
		ag_ind[HFP_INDICATOR_SERVICE].min = min;
		ag_ind[HFP_INDICATOR_SERVICE].max = max;
		ag_ind[HFP_INDICATOR_SERVICE].cb = ciev_service_cb;
		return;
	}

	if (strcmp("call", indicator) == 0) {
		if (min != 0 || max != 1) {
			DBG(hfp, "hf: Invalid min/max values for call,"
				" expected (0,1) got (%u,%u)", min, max);
			return;
		}
		ag_ind[HFP_INDICATOR_CALL].index = index;
		ag_ind[HFP_INDICATOR_CALL].min = min;
		ag_ind[HFP_INDICATOR_CALL].max = max;
		ag_ind[HFP_INDICATOR_CALL].cb = ciev_call_cb;
		return;
	}

	if (strcmp("callsetup", indicator) == 0) {
		if (min != 0 || max != 3) {
			DBG(hfp, "hf: Invalid min/max values for callsetup,"
				" expected (0,3) got (%u,%u)", min, max);
			return;
		}
		ag_ind[HFP_INDICATOR_CALLSETUP].index = index;
		ag_ind[HFP_INDICATOR_CALLSETUP].min = min;
		ag_ind[HFP_INDICATOR_CALLSETUP].max = max;
		ag_ind[HFP_INDICATOR_CALLSETUP].cb = ciev_callsetup_cb;
		return;
	}

	if (strcmp("callheld", indicator) == 0) {
		if (min != 0 || max != 2) {
			DBG(hfp, "hf: Invalid min/max values for callheld,"
				" expected (0,2) got (%u,%u)", min, max);
			return;
		}
		ag_ind[HFP_INDICATOR_CALLHELD].index = index;
		ag_ind[HFP_INDICATOR_CALLHELD].min = min;
		ag_ind[HFP_INDICATOR_CALLHELD].max = max;
		ag_ind[HFP_INDICATOR_CALLHELD].cb = ciev_callheld_cb;
		return;
	}

	if (strcmp("signal", indicator) == 0) {
		if (min != 0 || max != 5) {
			DBG(hfp, "hf: Invalid min/max values for signal,"
				" expected (0,5) got (%u,%u)", min, max);
			return;
		}
		ag_ind[HFP_INDICATOR_SIGNAL].index = index;
		ag_ind[HFP_INDICATOR_SIGNAL].min = min;
		ag_ind[HFP_INDICATOR_SIGNAL].max = max;
		ag_ind[HFP_INDICATOR_SIGNAL].cb = ciev_signal_cb;
		return;
	}

	if (strcmp("roam", indicator) == 0) {
		if (min != 0 || max != 1) {
			DBG(hfp, "hf: Invalid min/max values for roam,"
				" expected (0,1) got (%u,%u)", min, max);
			return;
		}
		ag_ind[HFP_INDICATOR_ROAM].index = index;
		ag_ind[HFP_INDICATOR_ROAM].min = min;
		ag_ind[HFP_INDICATOR_ROAM].max = max;
		ag_ind[HFP_INDICATOR_ROAM].cb = ciev_roam_cb;
		return;
	}

	if (strcmp("battchg", indicator) == 0) {
		if (min != 0 || max != 5) {
			DBG(hfp, "hf: Invalid min/max values for battchg,"
				" expected (0,5) got (%u,%u)", min, max);
			return;
		}
		ag_ind[HFP_INDICATOR_BATTCHG].index = index;
		ag_ind[HFP_INDICATOR_BATTCHG].min = min;
		ag_ind[HFP_INDICATOR_BATTCHG].max = max;
		ag_ind[HFP_INDICATOR_BATTCHG].cb = ciev_battchg_cb;
		return;
	}

	DBG(hfp, "hf: Unknown indicator: %s", indicator);
}

static void slc_cind_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	int index = 1;

	DBG(hfp, "");

	while (hfp_context_has_next(context)) {
		char name[255];
		unsigned int min, max;

		/* e.g ("callsetup",(0-3)) */
		if (!hfp_context_open_container(context))
			break;

		if (!hfp_context_get_string(context, name, sizeof(name))) {
			DBG(hfp, "hf: Could not get string");
			goto failed;
		}

		if (!hfp_context_open_container(context)) {
			DBG(hfp, "hf: Could not open container");
			goto failed;
		}

		if (!hfp_context_get_range(context, &min, &max)) {
			if (!hfp_context_get_number(context, &min)) {
				DBG(hfp, "hf: Could not get number");
				goto failed;
			}

			if (!hfp_context_get_number(context, &max)) {
				DBG(hfp, "hf: Could not get number");
				goto failed;
			}
		}

		if (!hfp_context_close_container(context)) {
			DBG(hfp, "hf: Could not close container");
			goto failed;
		}

		if (!hfp_context_close_container(context)) {
			DBG(hfp, "hf: Could not close container");
			goto failed;
		}

		set_indicator_parameters(hfp, index, name, min, max);
		index++;
	}

	return;

failed:
	DBG(hfp, "hf: Error on CIND response");
}

static void slc_cind_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "");

	hfp_hf_unregister(hfp, "+CIND");

	if (result != HFP_RESULT_OK) {
		DBG(hfp, "hf: CIND error: %d", result);
		goto failed;
	}

	/* Continue with SLC creation */
	if (!hfp_hf_register(hfp, slc_cind_status_cb, "+CIND", hfp,
			NULL)) {
		DBG(hfp, "hf: Could not register +CIND");
		result = HFP_RESULT_ERROR;
		goto failed;
	}

	if (!hfp_hf_send_command(hfp, slc_cind_status_resp, hfp,
			"AT+CIND?")) {
		DBG(hfp, "hf: Could not send AT+CIND?");
		result = HFP_RESULT_ERROR;
		goto failed;
	}

	return;

failed:
	if (hfp->callbacks->session_ready)
		hfp->callbacks->session_ready(result, cme_err,
						hfp->callbacks_data);
}

static void slc_brsf_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_hf *hfp = user_data;
	unsigned int feat;

	DBG(hfp, "");

	if (hfp_context_get_number(context, &feat))
		hfp->features = feat;
}

static void slc_brsf_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_hf *hfp = user_data;

	DBG(hfp, "");

	hfp_hf_unregister(hfp, "+BRSF");

	if (result != HFP_RESULT_OK) {
		DBG(hfp, "BRSF error: %d", result);
		goto failed;
	}

	/* Continue with SLC creation */
	if (!hfp_hf_register(hfp, slc_cind_cb, "+CIND", hfp, NULL)) {
		DBG(hfp, "hf: Could not register for +CIND");
		result = HFP_RESULT_ERROR;
		goto failed;
	}

	if (!hfp_hf_send_command(hfp, slc_cind_resp, hfp, "AT+CIND=?")) {
		DBG(hfp, "hf: Could not send AT+CIND command");
		result = HFP_RESULT_ERROR;
		goto failed;
	}

	return;

failed:
	if (hfp->callbacks->session_ready)
		hfp->callbacks->session_ready(result, cme_err,
						hfp->callbacks_data);
}

bool hfp_hf_session_register(struct hfp_hf *hfp,
				struct hfp_hf_callbacks *callbacks,
				void *callbacks_data)
{
	if (!hfp)
		return false;

	hfp->callbacks = callbacks;
	hfp->callbacks_data = callbacks_data;

	return true;
}

bool hfp_hf_session(struct hfp_hf *hfp)
{
	if (!hfp)
		return false;

	DBG(hfp, "");

	if (!hfp_hf_register(hfp, slc_brsf_cb, "+BRSF", hfp, NULL))
		return false;

	return hfp_hf_send_command(hfp, slc_brsf_resp, hfp,
					"AT+BRSF=%u", HFP_HF_FEATURES);
}

const char *hfp_hf_call_get_number(struct hfp_hf *hfp, uint id)
{
	struct hf_call *call;

	if (!hfp)
		return NULL;

	DBG(hfp, "");

	call = queue_find(hfp->calls, call_id_match, UINT_TO_PTR(id));
	if (!call) {
		DBG(hfp, "hf: no call with id: %u", id);
		return NULL;
	}

	return call->line_id;
}

bool hfp_hf_dial(struct hfp_hf *hfp, const char *number,
				hfp_response_func_t resp_cb,
				void *user_data)
{
	const char *c;
	int count = 0;

	if (!hfp)
		return false;

	DBG(hfp, "");

	if (number == NULL || strlen(number) == 0)
		return hfp_hf_send_command(hfp, resp_cb, user_data,
								"AT+BLDN");

	if (number[0] == '>') {
		for (c = number + 1; *c != '\0'; c++) {
			if (!(*c >= '0' && *c <= '9'))
				return false;
			count++;
		}
		if (count < 1 || count > 10)
			return false;
	} else {
		for (c = number; *c != '\0'; c++) {
			if (!(*c >= '0' && *c <= '9') &&
				!(*c >= 'A' && *c <= 'D') &&
				*c != '#' && *c != '*' &&
				*c != '+' && *c != ',')
				return false;
			count++;
		}
		if (count < 1 || count > 80)
			return false;
	}

	if (hfp->dialing_number)
		free(hfp->dialing_number);
	hfp->dialing_number = strdup(number);

	return hfp_hf_send_command(hfp, resp_cb, user_data, "ATD%s;", number);
}

bool hfp_hf_call_answer(struct hfp_hf *hfp, uint id,
				hfp_response_func_t resp_cb,
				void *user_data)
{
	struct hf_call *call;

	if (!hfp)
		return false;

	DBG(hfp, "");

	call = queue_find(hfp->calls, call_id_match, UINT_TO_PTR(id));
	if (!call) {
		DBG(hfp, "hf: no call with id: %u", id);
		return false;
	}

	if (call->status != CALL_STATUS_INCOMING) {
		DBG(hfp, "hf: %d not in incoming call state: %u",
							id, call->status);
		return false;
	}

	return hfp_hf_send_command(hfp, resp_cb, user_data, "ATA");
}

bool hfp_hf_call_hangup(struct hfp_hf *hfp, uint id,
				hfp_response_func_t resp_cb,
				void *user_data)
{
	struct hf_call *call;

	if (!hfp)
		return false;

	DBG(hfp, "");

	call = queue_find(hfp->calls, call_id_match, UINT_TO_PTR(id));
	if (!call) {
		DBG(hfp, "hf: no call with id: %u", id);
		return false;
	}

	if (call_setup_match(call, NULL) || call_active_match(call, NULL)) {
		return hfp_hf_send_command(hfp, resp_cb, user_data,
								"AT+CHUP");
	}

	return false;
}

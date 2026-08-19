// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026 Matthias Kurz
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "message-stream.h"

#define MESSAGE_HEADER_LENGTH 4

struct fastpair_message_stream {
	GByteArray *buffer;
	fastpair_message_func_t callback;
	void *user_data;
};

struct fastpair_message_stream *
fastpair_message_stream_new(fastpair_message_func_t callback, void *user_data)
{
	struct fastpair_message_stream *stream;

	if (!callback)
		return NULL;

	stream = g_new0(struct fastpair_message_stream, 1);
	stream->buffer = g_byte_array_new();
	stream->callback = callback;
	stream->user_data = user_data;

	return stream;
}

void fastpair_message_stream_free(struct fastpair_message_stream *stream)
{
	if (!stream)
		return;

	g_byte_array_unref(stream->buffer);
	g_free(stream);
}

bool fastpair_message_stream_feed(struct fastpair_message_stream *stream,
					  const void *data, size_t length)
{
	const uint8_t *bytes = data;

	if (!stream || (!data && length))
		return false;

	if (length > G_MAXUINT || stream->buffer->len > G_MAXUINT - length)
		return false;

	if (!length)
		return true;

	g_byte_array_append(stream->buffer, bytes, length);

	while (stream->buffer->len >= MESSAGE_HEADER_LENGTH) {
		const uint8_t *header = stream->buffer->data;
		uint16_t payload_length;
		guint frame_length;

		payload_length = ((uint16_t) header[2] << 8) | header[3];
		frame_length = MESSAGE_HEADER_LENGTH + payload_length;
		if (stream->buffer->len < frame_length)
			break;

		stream->callback(header[0], header[1],
				stream->buffer->data + MESSAGE_HEADER_LENGTH,
				payload_length, stream->user_data);
		g_byte_array_remove_range(stream->buffer, 0, frame_length);
	}

	return true;
}

bool fastpair_message_get_batteries(uint8_t group, uint8_t code,
				    const uint8_t *payload, uint16_t length,
				    struct fastpair_battery *batteries)
{
	unsigned int i;

	if (group != FASTPAIR_DEVICE_INFORMATION_GROUP ||
			code != FASTPAIR_BATTERY_UPDATE_CODE ||
			length != FASTPAIR_BATTERY_COUNT ||
			!payload || !batteries)
		return false;

	for (i = 0; i < FASTPAIR_BATTERY_COUNT; i++) {
		uint8_t percentage = payload[i] & 0x7f;
		bool case_unavailable;
		bool level_valid = percentage <= 100;
		bool status_valid;

		batteries[i].percentage = level_valid ? percentage :
						FASTPAIR_BATTERY_UNKNOWN;

		/*
		 * Battery Notification retains the status bit for an unknown
		 * level (0bS1111111). The TWS requirements separately define
		 * 0xff as invalid when the case level is unsupported. Do not
		 * infer charging from that sentinel. Reserved levels have no
		 * defined charging state.
		 */
		case_unavailable = i == FASTPAIR_BATTERY_COUNT - 1 &&
						payload[i] == 0xff;
		status_valid = level_valid ||
				(percentage == 0x7f && !case_unavailable);
		if (!status_valid)
			batteries[i].charging = FASTPAIR_CHARGING_UNKNOWN;
		else
			batteries[i].charging = !!(payload[i] & 0x80);
	}

	return true;
}

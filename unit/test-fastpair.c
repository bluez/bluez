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

#include <stdint.h>
#include <string.h>

#include <glib.h>

#include "src/shared/tester.h"

#include "profiles/fastpair/message-stream.h"

struct expected_message {
	uint8_t group;
	uint8_t code;
	uint16_t length;
	const uint8_t *payload;
};

struct parse_context {
	const struct expected_message *messages;
	unsigned int count;
	unsigned int seen;
};

static void message_cb(uint8_t group, uint8_t code, const uint8_t *payload,
			uint16_t length, void *user_data)
{
	struct parse_context *context = user_data;
	const struct expected_message *expected;

	g_assert_cmpuint(context->seen, <, context->count);
	expected = &context->messages[context->seen++];
	g_assert_cmpuint(group, ==, expected->group);
	g_assert_cmpuint(code, ==, expected->code);
	g_assert_cmpuint(length, ==, expected->length);
	if (length)
		g_assert_cmpmem(payload, length, expected->payload,
						expected->length);
}

static void test_complete_message(const void *data)
{
	static const uint8_t payload[] = { 0x60, 0x00, 0x5c };
	static const uint8_t frame[] = {
		0x03, 0x03, 0x00, sizeof(payload), 0x60, 0x00, 0x5c,
	};
	static const struct expected_message messages[] = {
		{ 0x03, 0x03, sizeof(payload), payload },
	};
	struct parse_context context = {
		.messages = messages,
		.count = G_N_ELEMENTS(messages),
	};
	struct fastpair_message_stream *stream;

	stream = fastpair_message_stream_new(message_cb, &context);
	g_assert_nonnull(stream);
	g_assert_true(fastpair_message_stream_feed(stream, frame,
							 sizeof(frame)));
	g_assert_cmpuint(context.seen, ==, context.count);

	fastpair_message_stream_free(stream);
	tester_test_passed();
}

static void test_fragmented_messages(const void *data)
{
	static const uint8_t battery[] = { 0x60, 0x00, 0x5c };
	static const uint8_t other[] = { 0xaa, 0xbb };
	static const uint8_t frames[] = {
		0x03, 0x03, 0x00, sizeof(battery), 0x60, 0x00, 0x5c,
		0x01, 0x02, 0x00, sizeof(other), 0xaa, 0xbb,
	};
	static const struct expected_message messages[] = {
		{ 0x03, 0x03, sizeof(battery), battery },
		{ 0x01, 0x02, sizeof(other), other },
	};
	struct parse_context context = {
		.messages = messages,
		.count = G_N_ELEMENTS(messages),
	};
	struct fastpair_message_stream *stream;

	stream = fastpair_message_stream_new(message_cb, &context);
	g_assert_nonnull(stream);
	/* Split after the first byte of the first payload. */
	g_assert_true(fastpair_message_stream_feed(stream, frames, 5));
	g_assert_cmpuint(context.seen, ==, 0);
	g_assert_true(fastpair_message_stream_feed(stream, frames + 5,
						     sizeof(frames) - 5));
	g_assert_cmpuint(context.seen, ==, context.count);

	fastpair_message_stream_free(stream);
	tester_test_passed();
}

static void test_coalesced_partial_message(const void *data)
{
	static const uint8_t battery[] = { 0x60, 0x00, 0x5c };
	static const uint8_t other[] = { 0xaa, 0xbb };
	static const uint8_t frames[] = {
		0x03, 0x03, 0x00, sizeof(battery), 0x60, 0x00, 0x5c,
		0x01, 0x02, 0x00, sizeof(other), 0xaa, 0xbb,
	};
	static const struct expected_message messages[] = {
		{ 0x03, 0x03, sizeof(battery), battery },
		{ 0x01, 0x02, sizeof(other), other },
	};
	struct parse_context context = {
		.messages = messages,
		.count = G_N_ELEMENTS(messages),
	};
	struct fastpair_message_stream *stream;
	size_t first_feed = 4 + sizeof(battery) + 2;

	stream = fastpair_message_stream_new(message_cb, &context);
	g_assert_nonnull(stream);
	g_assert_true(fastpair_message_stream_feed(stream, frames, first_feed));
	g_assert_cmpuint(context.seen, ==, 1);
	g_assert_true(fastpair_message_stream_feed(stream, frames + first_feed,
						sizeof(frames) - first_feed));
	g_assert_cmpuint(context.seen, ==, context.count);

	fastpair_message_stream_free(stream);
	tester_test_passed();
}

static void test_invalid_input(const void *data)
{
	static const uint8_t frame[] = { 0x01, 0x02, 0x00, 0x00 };
	struct parse_context context = {};
	struct fastpair_message_stream *stream;

	g_assert_false(fastpair_message_stream_feed(NULL, frame,
							sizeof(frame)));

	stream = fastpair_message_stream_new(message_cb, &context);
	g_assert_nonnull(stream);
	g_assert_false(fastpair_message_stream_feed(stream, NULL, 1));
	g_assert_true(fastpair_message_stream_feed(stream, NULL, 0));

	fastpair_message_stream_free(stream);
	tester_test_passed();
}

static void test_zero_length_message(const void *data)
{
	static const uint8_t frame[] = { 0x01, 0x02, 0x00, 0x00 };
	static const struct expected_message messages[] = {
		{ 0x01, 0x02, 0, NULL },
	};
	struct parse_context context = {
		.messages = messages,
		.count = G_N_ELEMENTS(messages),
	};
	struct fastpair_message_stream *stream;

	stream = fastpair_message_stream_new(message_cb, &context);
	g_assert_nonnull(stream);
	g_assert_true(fastpair_message_stream_feed(stream, frame,
							 sizeof(frame)));
	g_assert_cmpuint(context.seen, ==, context.count);

	fastpair_message_stream_free(stream);
	tester_test_passed();
}

static void test_maximum_length_message(const void *data)
{
	struct expected_message message;
	struct parse_context context = {
		.messages = &message,
		.count = 1,
	};
	struct fastpair_message_stream *stream;
	uint8_t *frame;
	size_t frame_length = 4 + UINT16_MAX;

	frame = g_malloc(frame_length);
	frame[0] = 0x01;
	frame[1] = 0x02;
	frame[2] = 0xff;
	frame[3] = 0xff;
	memset(frame + 4, 0xa5, UINT16_MAX);

	message.group = frame[0];
	message.code = frame[1];
	message.length = UINT16_MAX;
	message.payload = frame + 4;

	stream = fastpair_message_stream_new(message_cb, &context);
	g_assert_nonnull(stream);
	g_assert_true(fastpair_message_stream_feed(stream, frame, 1024));
	g_assert_cmpuint(context.seen, ==, 0);
	g_assert_true(fastpair_message_stream_feed(stream, frame + 1024,
						frame_length - 1024));
	g_assert_cmpuint(context.seen, ==, context.count);

	fastpair_message_stream_free(stream);
	g_free(frame);
	tester_test_passed();
}

static void test_battery_message(const void *data)
{
	static const uint8_t payload[] = { 0x60, 0xaa, 0x7f };
	static const uint8_t unknown[] = { 0xff, 0x7f, 0xff };
	static const uint8_t reserved[] = { 0x65, 0xe5, 0x65 };
	struct fastpair_battery batteries[FASTPAIR_BATTERY_COUNT];

	g_assert_true(fastpair_message_get_batteries(0x03, 0x03,
						      payload, sizeof(payload),
						      batteries));
	g_assert_cmpuint(batteries[0].percentage, ==, 96);
	g_assert_false(batteries[0].charging);
	g_assert_cmpuint(batteries[1].percentage, ==, 42);
	g_assert_true(batteries[1].charging);
	g_assert_cmpuint(batteries[2].percentage, ==,
						FASTPAIR_BATTERY_UNKNOWN);
	g_assert_cmpint(batteries[2].charging, ==, 0);

	g_assert_true(fastpair_message_get_batteries(0x03, 0x03,
					unknown, sizeof(unknown),
					batteries));
	g_assert_cmpuint(batteries[0].percentage, ==,
						FASTPAIR_BATTERY_UNKNOWN);
	g_assert_cmpint(batteries[0].charging, ==, 1);
	g_assert_cmpuint(batteries[1].percentage, ==,
						FASTPAIR_BATTERY_UNKNOWN);
	g_assert_cmpint(batteries[1].charging, ==, 0);
	g_assert_cmpuint(batteries[2].percentage, ==,
						FASTPAIR_BATTERY_UNKNOWN);
	g_assert_cmpint(batteries[2].charging, ==,
						FASTPAIR_CHARGING_UNKNOWN);

	g_assert_true(fastpair_message_get_batteries(0x03, 0x03,
					reserved, sizeof(reserved),
					batteries));
	for (unsigned int i = 0; i < FASTPAIR_BATTERY_COUNT; i++) {
		g_assert_cmpuint(batteries[i].percentage, ==,
						FASTPAIR_BATTERY_UNKNOWN);
		g_assert_cmpint(batteries[i].charging, ==,
						FASTPAIR_CHARGING_UNKNOWN);
	}

	g_assert_false(fastpair_message_get_batteries(0x03, 0x02,
						       payload, sizeof(payload),
						       batteries));
	g_assert_false(fastpair_message_get_batteries(0x03, 0x03, payload,
						       sizeof(payload) - 1,
						       batteries));
	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	tester_add("/fastpair/complete-message", NULL, NULL,
				test_complete_message, NULL);
	tester_add("/fastpair/fragmented-messages", NULL, NULL,
				test_fragmented_messages, NULL);
	tester_add("/fastpair/coalesced-partial-message", NULL, NULL,
				test_coalesced_partial_message, NULL);
	tester_add("/fastpair/invalid-input", NULL, NULL,
				test_invalid_input, NULL);
	tester_add("/fastpair/zero-length-message", NULL, NULL,
				test_zero_length_message, NULL);
	tester_add("/fastpair/maximum-length-message", NULL, NULL,
				test_maximum_length_message, NULL);
	tester_add("/fastpair/battery-message", NULL, NULL,
				test_battery_message, NULL);

	return tester_run();
}

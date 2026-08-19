/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026 Matthias Kurz
 *
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FASTPAIR_MESSAGE_STREAM_UUID \
	"df21fe2c-2515-4fdb-8886-f12c4d67927c"

#define FASTPAIR_DEVICE_INFORMATION_GROUP 0x03
#define FASTPAIR_BATTERY_UPDATE_CODE 0x03
#define FASTPAIR_BATTERY_COUNT 3
#define FASTPAIR_BATTERY_UNKNOWN UINT8_MAX
#define FASTPAIR_CHARGING_UNKNOWN (-1)

struct fastpair_message_stream;

struct fastpair_battery {
	uint8_t percentage;
	int charging;
};

typedef void (*fastpair_message_func_t)(uint8_t group, uint8_t code,
					const uint8_t *payload, uint16_t length,
					void *user_data);

struct fastpair_message_stream *
fastpair_message_stream_new(fastpair_message_func_t callback, void *user_data);
void fastpair_message_stream_free(struct fastpair_message_stream *stream);
bool fastpair_message_stream_feed(struct fastpair_message_stream *stream,
					  const void *data, size_t length);

bool fastpair_message_get_batteries(uint8_t group, uint8_t code,
				    const uint8_t *payload, uint16_t length,
				    struct fastpair_battery *batteries);

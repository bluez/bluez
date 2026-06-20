// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef BLUEZ_A2DP_HELPERS_H
#define BLUEZ_A2DP_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <dbus/dbus.h>

bool a2dp_parse_capabilities_array(DBusMessageIter *value,
					uint8_t **caps, int *size);
bool a2dp_parse_persisted_endpoint(const char *value, uint8_t *type,
					uint8_t *codec,
					bool *delay_reporting,
					uint8_t *caps, size_t caps_len,
					size_t *size);

#endif /* BLUEZ_A2DP_HELPERS_H */

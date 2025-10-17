/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <linux/uhid.h>
#include <bluetooth/bluetooth.h>

struct bt_uhid;

enum {
	BT_UHID_NONE = 0,
	BT_UHID_KEYBOARD,
	BT_UHID_MOUSE,
	BT_UHID_GAMING,
	BT_UHID_TABLET
};

static inline uint8_t bt_uhid_icon_to_type(const char *icon)
{
	if (!icon)
		return BT_UHID_NONE;

	if (!strcmp(icon, "input-keyboard"))
		return BT_UHID_KEYBOARD;
	else if (!strcmp(icon, "input-mouse"))
		return BT_UHID_MOUSE;
	else if (!strcmp(icon, "input-gaming"))
		return BT_UHID_GAMING;
	else if (!strcmp(icon, "input-tablet"))
		return BT_UHID_TABLET;
	else
		return BT_UHID_NONE;
}

struct bt_uhid *bt_uhid_new_default(void);
struct bt_uhid *bt_uhid_new(int fd);

struct bt_uhid *bt_uhid_ref(struct bt_uhid *uhid);
void bt_uhid_unref(struct bt_uhid *uhid);

bool bt_uhid_set_close_on_unref(struct bt_uhid *uhid, bool do_close);

typedef void (*bt_uhid_callback_t)(struct uhid_event *ev, void *user_data);
unsigned int bt_uhid_register(struct bt_uhid *uhid, uint32_t event,
				bt_uhid_callback_t func, void *user_data);
bool bt_uhid_unregister(struct bt_uhid *uhid, unsigned int id);
bool bt_uhid_unregister_all(struct bt_uhid *uhid);

int bt_uhid_send(struct bt_uhid *uhid, const struct uhid_event *ev);
int bt_uhid_create(struct bt_uhid *uhid, const char *name, bdaddr_t *src,
			bdaddr_t *dst, uint32_t vendor, uint32_t product,
			uint32_t version, uint32_t country, uint8_t type,
			void *rd_data, size_t rd_size);
bool bt_uhid_created(struct bt_uhid *uhid);
bool bt_uhid_started(struct bt_uhid *uhid);
int bt_uhid_input(struct bt_uhid *uhid, uint8_t number, const void *data,
			size_t size);
int bt_uhid_set_report_reply(struct bt_uhid *uhid, uint32_t id, uint8_t status);
int bt_uhid_get_report_reply(struct bt_uhid *uhid, uint32_t id, uint8_t number,
				uint8_t status, const void *data, size_t size);
int bt_uhid_destroy(struct bt_uhid *uhid, bool force);
int bt_uhid_replay(struct bt_uhid *uhid);

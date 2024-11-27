// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024 Intel Corporation
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/shell.h"
#include "src/shared/hci.h"
#include "monitor/bt.h"
#include "hci.h"

static struct bt_hci *hci;
static struct queue *events;

struct hci_event {
	uint8_t event;
	unsigned int id;
};

static void hci_open(int argc, char *argv[])
{
	long index;
	char *endptr = NULL;

	if (hci) {
		bt_shell_printf("HCI channel already open\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	index = strtol(argv[1], &endptr, 0);
	if (!endptr || *endptr != '\0' || index < 0 || index > UINT16_MAX) {
		bt_shell_printf("Invalid index: %s\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!strcasecmp(argv[2], "raw")) {
		hci = bt_hci_new_raw_device(index);
		if (!hci) {
			bt_shell_printf("Unable to open raw channel\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	} else if (!strcasecmp(argv[2], "user")) {
		hci = bt_hci_new_user_channel(index);
		if (!hci) {
			bt_shell_printf("Unable to open user channel\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	} else {
		bt_shell_printf("Invalid channel: %s\n", argv[2]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("HCI index %ld %s channel opened\n", index, argv[2]);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static uint8_t *str2bytearray(char *arg, size_t *val_len)
{
	uint8_t value[UINT8_MAX];
	char *entry;
	unsigned int i;

	for (i = 0; (entry = strsep(&arg, " \t")) != NULL; i++) {
		long val;
		char *endptr = NULL;

		if (*entry == '\0')
			continue;

		if (i >= G_N_ELEMENTS(value)) {
			bt_shell_printf("Too much data\n");
			return NULL;
		}

		val = strtol(entry, &endptr, 0);
		if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
			bt_shell_printf("Invalid value at index %d\n", i);
			return NULL;
		}

		value[i] = val;
	}

	*val_len = i;

	return util_memdup(value, i);
}

static void hci_cmd_complete(const void *data, uint8_t size, void *user_data)
{
	bt_shell_printf("HCI Command complete:\n");
	bt_shell_hexdump(data, size);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void hci_cmd(int argc, char *argv[])
{
	long opcode;
	struct iovec iov = {};
	char *endptr = NULL;
	unsigned int ret;

	if (!hci) {
		bt_shell_printf("HCI channel not open\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	opcode = strtol(argv[1], &endptr, 0);
	if (!endptr || *endptr != '\0' || opcode < 0 || opcode > UINT16_MAX) {
		bt_shell_printf("Invalid opcode: %s\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (argc > 2) {
		iov.iov_base = str2bytearray(argv[2], &iov.iov_len);
		if (!iov.iov_base) {
			bt_shell_printf("Invalid parameters: %s\n", argv[2]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	ret = bt_hci_send(hci, opcode, iov.iov_base, iov.iov_len,
				hci_cmd_complete, NULL, NULL);

	free(iov.iov_base);

	if (!ret)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void hci_send(int argc, char *argv[])
{
	uint8_t type;
	long handle;
	struct iovec iov = {};
	char *endptr = NULL;
	bool ret;

	if (!hci) {
		bt_shell_printf("HCI channel not open\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!strcasecmp(argv[1], "acl")) {
		type = BT_H4_ACL_PKT;
	} else if (!strcasecmp(argv[1], "sco")) {
		type = BT_H4_SCO_PKT;
	} else if (!strcasecmp(argv[1], "iso")) {
		type = BT_H4_ISO_PKT;
	} else {
		bt_shell_printf("Invalid type: %s\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	handle = strtol(argv[2], &endptr, 0);
	if (!endptr || *endptr != '\0' || handle < 0 || handle > UINT16_MAX) {
		bt_shell_printf("Invalid handle: %s\n", argv[2]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (argc > 3) {
		iov.iov_base = str2bytearray(argv[3], &iov.iov_len);
		if (!iov.iov_base) {
			bt_shell_printf("Invalid data: %s\n", argv[3]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	ret = bt_hci_send_data(hci, type, handle, iov.iov_base, iov.iov_len);

	free(iov.iov_base);

	return bt_shell_noninteractive_quit(ret ? EXIT_SUCCESS : EXIT_FAILURE);
}

static bool match_event(const void *data, const void *match_data)
{
	const struct hci_event *evt = data;
	uint8_t event = PTR_TO_UINT(match_data);

	return evt->event == event;
}

static void hci_evt_received(const void *data, uint8_t size, void *user_data)
{
	struct hci_event *evt = user_data;

	bt_shell_printf("HCI Event 0x%02x received:\n", evt->event);
	bt_shell_hexdump(data, size);
}

static void hci_register(int argc, char *argv[])
{
	struct hci_event *evt;
	long event;
	char *endptr = NULL;

	if (!hci) {
		bt_shell_printf("HCI channel not open\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	event = strtol(argv[1], &endptr, 0);
	if (!endptr || *endptr != '\0' || event < 0 || event > UINT8_MAX) {
		bt_shell_printf("Invalid event: %s\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!events)
		events = queue_new();

	evt = queue_find(events, match_event, UINT_TO_PTR(event));
	if (evt) {
		bt_shell_printf("Event already registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	evt = new0(struct hci_event, 1);
	evt->event = event;
	evt->id = bt_hci_register(hci, event, hci_evt_received, evt, NULL);

	if (!evt->id) {
		free(evt);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("HCI Event 0x%02x registered\n", (uint8_t)event);

	queue_push_tail(events, evt);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void hci_unregister(int argc, char *argv[])
{
	struct hci_event *evt;
	long event;
	char *endptr = NULL;

	if (!hci) {
		bt_shell_printf("HCI channel not open\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	event = strtol(argv[1], &endptr, 0);
	if (!endptr || *endptr != '\0' || event < 0 || event > UINT8_MAX) {
		bt_shell_printf("Invalid event: %s\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	evt = queue_find(events, match_event, UINT_TO_PTR(event));
	if (!evt) {
		bt_shell_printf("Event not registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_hci_unregister(hci, evt->id);
	queue_remove(events, evt);
	free(evt);

	bt_shell_printf("HCI Event 0x%02x unregistered\n", (uint8_t)event);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void hci_close(int argc, char *argv[])
{
	if (!hci) {
		bt_shell_printf("HCI channel not open\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_hci_unref(hci);
	hci = NULL;

	bt_shell_printf("HCI channel closed\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static const struct bt_shell_menu hci_menu = {
	.name = "hci",
	.desc = "HCI Submenu",
	.entries = {
	{ "open",        "<index> <chan=raw,user>", hci_open,
					"Open HCI channel" },
	{ "cmd",         "<opcode> [parameters...]", hci_cmd,
					"Send HCI command" },
	{ "send",        "<type=acl,sco,iso> <handle> [data...]", hci_send,
					"Send HCI data" },
	{ "register",    "<event>", hci_register,
					"Register HCI event handler" },
	{ "unregister",  "<event>", hci_unregister,
					"Unregister HCI event handler" },
	{ "close",         NULL, hci_close, "Close HCI channel" },
	{} },
};

void hci_add_submenu(void)
{
	bt_shell_add_submenu(&hci_menu);
}

void hci_remove_submenu(void)
{
	if (!hci)
		return;

	if (events) {
		queue_destroy(events, free);
		events = NULL;
	}

	bt_hci_unref(hci);
	hci = NULL;
}

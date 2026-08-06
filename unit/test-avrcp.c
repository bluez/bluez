// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Red Hat Inc.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>

#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/log.h"

#include "profiles/audio/avrcp-parse.h"

static void avrcp_element_name_oob(gconstpointer data)
{
	char name[255];
	uint16_t namesize;
	gboolean ret;

	/* Crafting a malicious payload.
	 * Actual packet length (len) = 14 bytes */
	uint8_t malicious_packet[14] = {0};

	/* Specify namesize = 1000 (0x03E8 in Big Endian) at offset 11 */
	malicious_packet[11] = 0x03;
	malicious_packet[12] = 0xE8;

	/* Launching the PoC. We transmit a 14-byte packet, but namesize=1000... */
	ret = parse_media_element_name(malicious_packet, sizeof(malicious_packet),
				       name, &namesize);
	if (ret)
		tester_test_passed();
	else
		tester_test_failed();
}

static void avrcp_folder_name_oob(gconstpointer data)
{
	char name[255];
	gboolean ret;

	/* Crafting a malicious payload.
	 * Actual packet length (len) = 14 bytes */
	uint8_t malicious_packet[14] = {0};

	/* Specify namesize = 1000 (0x03E8 in Big Endian) at offset 12 */
	malicious_packet[12] = 0x03;
	malicious_packet[13] = 0xE8;

	/* Launching the PoC. We transmit a 14-byte packet, but namesize=1000... */
	ret = parse_media_folder_name(malicious_packet, sizeof(malicious_packet),
				      name);
	if (ret)
		tester_test_passed();
	else
		tester_test_failed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	tester_add("/avrcp-element-name-oob", NULL, NULL, avrcp_element_name_oob, NULL);
	tester_add("/avrcp-folder-name-oob", NULL, NULL, avrcp_folder_name_oob, NULL);

	return tester_run();
}

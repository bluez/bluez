/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <getopt.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "monitor/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/mgmt.h"

static bool use_bredr = false;
static bool use_le = false;
static bool use_sc = false;
static bool use_sconly = false;
static bool use_debug = false;
static bool provide_p192 = false;
static bool provide_p256 = false;

static struct mgmt *mgmt;
static uint16_t index1 = MGMT_INDEX_NONE;
static uint16_t index2 = MGMT_INDEX_NONE;
static bdaddr_t bdaddr1;
static bdaddr_t bdaddr2;

static void new_link_key_event(uint16_t index, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_ev_new_link_key *ev = param;
	char str[18];
	int i;

	ba2str(&ev->key.addr.bdaddr, str);

	printf("[Index %u]\n", index);
	printf("  New link key: %s\n", str);
	printf("  Type: %u\n", ev->key.type);
	printf("  Key: ");
	for (i = 0; i < 16; i++)
		printf("%02x", ev->key.val[i]);
	printf("\n");
}

static void new_long_term_key_event(uint16_t index, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_ev_new_long_term_key *ev = param;
	char str[18];
	int i;

	ba2str(&ev->key.addr.bdaddr, str);

	printf("[Index %u]\n", index);
	printf("  New long term key: %s\n", str);
	printf("  Type: %u\n", ev->key.type);
	printf("  Key: ");
	for (i = 0; i < 16; i++)
		printf("%02x", ev->key.val[i]);
	printf("\n");
}

static void pair_device_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	uint16_t index = PTR_TO_UINT(user_data);

	if (status) {
		fprintf(stderr, "Pair device from index %u failed: %s\n",
						index, mgmt_errstr(status));
	}

	mainloop_quit();
}

static void pair_device(uint16_t index, const bdaddr_t *bdaddr)
{
	struct mgmt_cp_pair_device cp;
	char str[18];

	ba2str(bdaddr, str);

	printf("[Index %u]\n", index);
	printf("  Starting pairing: %s\n", str);

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.addr.bdaddr, bdaddr);
	if (use_bredr)
		cp.addr.type = BDADDR_BREDR;
	else
		cp.addr.type = BDADDR_LE_PUBLIC;
	cp.io_cap = 0x03;

	mgmt_send(mgmt, MGMT_OP_PAIR_DEVICE, index, sizeof(cp), &cp,
						pair_device_complete,
						UINT_TO_PTR(index), NULL);
}

static void add_remote_oob_data_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_addr_info *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);
	char str[18];

	if (status) {
		fprintf(stderr, "Adding OOB data for index %u failed: %s\n",
						index, mgmt_errstr(status));
	}

	ba2str(&rp->bdaddr, str);

	printf("[Index %u]\n", index);
	printf("  Remote data added: %s\n", str);

	if (index == index1) {
		uint8_t val = 0x01;

		mgmt_send(mgmt, MGMT_OP_SET_CONNECTABLE, index2, 1, &val,
							NULL, NULL, NULL);

		if (use_le)
			mgmt_send(mgmt, MGMT_OP_SET_ADVERTISING, index2,
						1, &val, NULL, NULL, NULL);

		pair_device(index1, &bdaddr2);
	}
}

static void add_remote_oob_data(uint16_t index, const bdaddr_t *bdaddr,
				const uint8_t *hash192, const uint8_t *rand192,
				const uint8_t *hash256, const uint8_t *rand256)
{
	struct mgmt_cp_add_remote_oob_data cp;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.addr.bdaddr, bdaddr);
	if (use_bredr)
		cp.addr.type = BDADDR_BREDR;
	else
		cp.addr.type = BDADDR_LE_PUBLIC;
	if (hash192 && rand192) {
		memcpy(cp.hash192, hash192, 16);
		memcpy(cp.rand192, rand192, 16);
	} else {
		memset(cp.hash192, 0, 16);
		memset(cp.rand192, 0, 16);
	}
	if (hash256 && rand256) {
		memcpy(cp.hash256, hash256, 16);
		memcpy(cp.rand256, rand256, 16);
	} else {
		memset(cp.hash256, 0, 16);
		memset(cp.rand256, 0, 16);
	}

	mgmt_send(mgmt, MGMT_OP_ADD_REMOTE_OOB_DATA, index, sizeof(cp), &cp,
						add_remote_oob_data_complete,
						UINT_TO_PTR(index), NULL);
}

static void read_oob_data_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_local_oob_ext_data *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);
	const uint8_t *hash192, *rand192, *hash256, *rand256;
	int i;

	if (status) {
		fprintf(stderr, "Reading OOB data for index %u failed: %s\n",
						index, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("[Index %u]\n", index);

	if (provide_p192) {
		hash192 = rp->hash192;
		rand192 = rp->randomizer192;
	} else {
		hash192 = NULL;
		rand192 = NULL;
	}

	printf("  Hash C from P-192: ");
	for (i = 0; i < 16; i++)
		printf("%02x", rp->hash192[i]);
	printf("\n");

	printf("  Randomizer R with P-192: ");
	for (i = 0; i < 16; i++)
		printf("%02x", rp->randomizer192[i]);
	printf("\n");

	if (len < sizeof(*rp)) {
		hash256 = NULL;
		rand256 = NULL;
		goto done;
	}

	if (provide_p256) {
		hash256 = rp->hash256;
		rand256 = rp->randomizer256;
	} else {
		hash256 = NULL;
		rand256 = NULL;
	}

	printf("  Hash C from P-256: ");
	for (i = 0; i < 16; i++)
		printf("%02x", rp->hash256[i]);
	printf("\n");

	printf("  Randomizer R with P-256: ");
	for (i = 0; i < 16; i++)
		printf("%02x", rp->randomizer256[i]);
	printf("\n");

done:
	if (index == index1)
		add_remote_oob_data(index2, &bdaddr1,
					hash192, rand192, hash256, rand256);
	else if (index == index2)
		add_remote_oob_data(index1, &bdaddr2,
					hash192, rand192, hash256, rand256);
}

static void set_powered_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	uint16_t index = PTR_TO_UINT(user_data);
	uint32_t settings;
	uint8_t val;

	if (status) {
		fprintf(stderr, "Powering on for index %u failed: %s\n",
						index, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	settings = get_le32(param);

	if (!(settings & MGMT_SETTING_POWERED)) {
		fprintf(stderr, "Controller is not powered\n");
		mainloop_quit();
		return;
	}

	if (use_debug) {
		if (index == index1) {
			val = 0x02;
			mgmt_send(mgmt, MGMT_OP_SET_DEBUG_KEYS, index, 1, &val,
							NULL, NULL, NULL);
		} else if (index == index2) {
			val = 0x01;
			mgmt_send(mgmt, MGMT_OP_SET_DEBUG_KEYS, index, 1, &val,
							NULL, NULL, NULL);
		}
	}

	if (use_bredr && (provide_p192 || provide_p256)) {
		mgmt_send(mgmt, MGMT_OP_READ_LOCAL_OOB_DATA, index, 0, NULL,
						read_oob_data_complete,
						UINT_TO_PTR(index), NULL);
	} else {
		if (index == index1)
			add_remote_oob_data(index2, &bdaddr1,
						NULL, NULL, NULL, NULL);
		else if (index == index2)
			add_remote_oob_data(index1, &bdaddr2,
						NULL, NULL, NULL, NULL);
	}
}

static void clear_link_keys(uint16_t index)
{
	struct mgmt_cp_load_link_keys cp;

	memset(&cp, 0, sizeof(cp));
	cp.debug_keys = 0x00;
	cp.key_count = cpu_to_le16(0);

	mgmt_send(mgmt, MGMT_OP_LOAD_LINK_KEYS, index,
					sizeof(cp), &cp, NULL, NULL, NULL);
}

static void clear_long_term_keys(uint16_t index)
{
	struct mgmt_cp_load_long_term_keys cp;

	memset(&cp, 0, sizeof(cp));
	cp.key_count = cpu_to_le16(0);

	mgmt_send(mgmt, MGMT_OP_LOAD_LONG_TERM_KEYS, index,
					sizeof(cp), &cp, NULL, NULL, NULL);
}

static void clear_remote_oob_data(uint16_t index)
{
	struct mgmt_cp_remove_remote_oob_data cp;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.addr.bdaddr, BDADDR_ANY);
	cp.addr.type = BDADDR_BREDR;

	mgmt_send(mgmt, MGMT_OP_REMOVE_REMOTE_OOB_DATA, index,
					sizeof(cp), &cp, NULL, NULL, NULL);
}

static void read_info(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_info *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);
	uint32_t supported_settings;
	uint8_t val;
	char str[18];

	if (status) {
		fprintf(stderr, "Reading info for index %u failed: %s\n",
						index, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	ba2str(&rp->bdaddr, str);

	printf("[Index %u]\n", index);
	printf("  Address: %s\n", str);

	if (index == index1)
		bacpy(&bdaddr1, &rp->bdaddr);
	else if (index == index2)
		bacpy(&bdaddr2, &rp->bdaddr);

	supported_settings = le32_to_cpu(rp->supported_settings);

	if (use_bredr && !(supported_settings & MGMT_SETTING_BREDR)) {
		fprintf(stderr, "BR/EDR support missing\n");
		mainloop_quit();
		return;
	}

	if (use_bredr && !(supported_settings & MGMT_SETTING_SSP)) {
		fprintf(stderr, "Secure Simple Pairing support missing\n");
		mainloop_quit();
		return;
	}

	if (use_le && !(supported_settings & MGMT_SETTING_LE)) {
		fprintf(stderr, "Low Energy support missing\n");
		mainloop_quit();
		return;
	}

	if (use_sc && !(supported_settings & MGMT_SETTING_SECURE_CONN)) {
		fprintf(stderr, "Secure Connections support missing\n");
		mainloop_quit();
		return;
	}

	if (use_sconly && !(supported_settings & MGMT_SETTING_SECURE_CONN)) {
		fprintf(stderr, "Secure Connections Only support missing\n");
		mainloop_quit();
		return;
	}

	if (use_debug && !(supported_settings & MGMT_SETTING_DEBUG_KEYS)) {
		fprintf(stderr, "Debug keys support missing\n");
		mainloop_quit();
		return;
	}

	mgmt_register(mgmt, MGMT_EV_NEW_LINK_KEY, index,
						new_link_key_event,
						UINT_TO_PTR(index), NULL);

	mgmt_register(mgmt, MGMT_EV_NEW_LONG_TERM_KEY, index,
						new_long_term_key_event,
						UINT_TO_PTR(index), NULL);

	val = 0x00;
	mgmt_send(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
						NULL, NULL, NULL);

	clear_link_keys(index);
	clear_long_term_keys(index);
	clear_remote_oob_data(index);

	if (use_bredr) {
		val = 0x01;
		mgmt_send(mgmt, MGMT_OP_SET_BREDR, index, 1, &val,
							NULL, NULL, NULL);

		val = 0x00;
		mgmt_send(mgmt, MGMT_OP_SET_LE, index, 1, &val,
							NULL, NULL, NULL);

		val = 0x01;
		mgmt_send(mgmt, MGMT_OP_SET_SSP, index, 1, &val,
							NULL, NULL, NULL);
	} else if (use_le) {
		val = 0x01;
		mgmt_send(mgmt, MGMT_OP_SET_LE, index, 1, &val,
							NULL, NULL, NULL);

		val = 0x00;
		mgmt_send(mgmt, MGMT_OP_SET_BREDR, index, 1, &val,
							NULL, NULL, NULL);
	} else {
		fprintf(stderr, "Invalid transport for pairing\n");
		mainloop_quit();
		return;
	}

	if (use_sc) {
		val = 0x01;
		mgmt_send(mgmt, MGMT_OP_SET_SECURE_CONN, index, 1, &val,
							NULL, NULL, NULL);
	} else if (use_sconly) {
		val = 0x02;
		mgmt_send(mgmt, MGMT_OP_SET_SECURE_CONN, index, 1, &val,
							NULL, NULL, NULL);
	} else {
		val = 0x00;
		mgmt_send(mgmt, MGMT_OP_SET_SECURE_CONN, index, 1, &val,
							NULL, NULL, NULL);
	}

	val = 0x00;
	mgmt_send(mgmt, MGMT_OP_SET_DEBUG_KEYS, index, 1, &val,
						NULL, NULL, NULL);

	val = 0x01;
	mgmt_send(mgmt, MGMT_OP_SET_BONDABLE, index, 1, &val,
						NULL, NULL, NULL);

	val = 0x01;
	mgmt_send(mgmt, MGMT_OP_SET_POWERED, index, 1, &val,
						set_powered_complete,
						UINT_TO_PTR(index), NULL);
}

static void read_index_list(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t count;
	int i;

	if (status) {
		fprintf(stderr, "Reading index list failed: %s\n",
						mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	count = le16_to_cpu(rp->num_controllers);

	if (count < 2) {
		fprintf(stderr, "At least 2 controllers are required\n");
		mainloop_quit();
		return;
	}

	for (i = 0; i < count; i++) {
		uint16_t index = cpu_to_le16(rp->index[i]);

		if (index < index1)
			index1 = index;
	}

	for (i = 0; i < count; i++) {
		uint16_t index = cpu_to_le16(rp->index[i]);

		if (index < index2 && index > index1)
			index2 = index;
	}

	printf("Selecting index %u for initiator\n", index1);
	printf("Selecting index %u for acceptor\n", index2);

	mgmt_send(mgmt, MGMT_OP_READ_INFO, index1, 0, NULL,
				read_info, UINT_TO_PTR(index1), NULL);
	mgmt_send(mgmt, MGMT_OP_READ_INFO, index2, 0, NULL,
				read_info, UINT_TO_PTR(index2), NULL);
}

static void signal_callback(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	}
}

static void usage(void)
{
	printf("oobtest - Out-of-band pairing testing\n"
		"Usage:\n");
	printf("\toobtest [options]\n");
	printf("options:\n"
		"\t-B, --bredr            Use BR/EDR transport\n"
		"\t-L, --le               Use LE transport\n"
		"\t-S, --sc               Use Secure Connections\n"
		"\t-O, --sconly           Use Secure Connections Only\n"
		"\t-D, --debug            Use Pairing debug keys\n"
		"\t-1, --p192             Provide P-192 OOB data\n"
		"\t-2, --p256             Provide P-256 OOB data\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "bredr",   no_argument,       NULL, 'B' },
	{ "le",      no_argument,       NULL, 'L' },
	{ "sc",      no_argument,       NULL, 'S' },
	{ "sconly",  no_argument,       NULL, 'O' },
	{ "debug",   no_argument,       NULL, 'D' },
	{ "p192",    no_argument,       NULL, '1' },
	{ "p256",    no_argument,       NULL, '2' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc ,char *argv[])
{
	sigset_t mask;
	int exit_status;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "BLSOD12vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'B':
			use_bredr = true;
			break;
		case 'L':
			use_le = true;
			break;
		case 'S':
			use_sc = true;
			break;
		case 'O':
			use_sconly = true;
			break;
		case 'D':
			use_debug = true;
			break;
		case '1':
			provide_p192 = true;
			break;
		case '2':
			provide_p256 = true;
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind > 0) {
		fprintf(stderr, "Invalid command line parameters\n");
		return EXIT_FAILURE;
	}

	if (use_bredr == use_le) {
		fprintf(stderr, "Specify either --bredr or --le\n");
		return EXIT_FAILURE;
	}

	if (use_sc && use_sconly) {
		fprintf(stderr, "Only --sc or --sconly can be used\n");
		return EXIT_FAILURE;
	}

	mainloop_init();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_callback, NULL, NULL);

	mgmt = mgmt_new_default();
	if (!mgmt) {
		fprintf(stderr, "Failed to open management socket\n");
		return EXIT_FAILURE;
	}

	if (!mgmt_send(mgmt, MGMT_OP_READ_INDEX_LIST,
					MGMT_INDEX_NONE, 0, NULL,
					read_index_list, NULL, NULL)) {
		fprintf(stderr, "Failed to read index list\n");
		exit_status = EXIT_FAILURE;
		goto done;
	}

	exit_status = mainloop_run();

done:
	mgmt_unref(mgmt);

	return exit_status;
}

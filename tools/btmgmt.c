/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <getopt.h>
#include <stdbool.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "src/uuid-helper.h"
#include "lib/mgmt.h"

#include "monitor/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/mgmt.h"
#include "src/shared/gap.h"

static bool monitor = false;
static bool discovery = false;
static bool resolve_names = true;

static int pending = 0;

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

static size_t convert_hexstr(const char *hexstr, uint8_t *buf, size_t buflen)
{
	size_t i, len;

	len = MIN((strlen(hexstr) / 2), buflen);
	memset(buf, 0, len);

	for (i = 0; i < len; i++)
		sscanf(hexstr + (i * 2), "%02hhX", &buf[i]);

	return len;
}

static bool load_identity(uint16_t index, struct mgmt_irk_info *irk)
{
	char identity_path[PATH_MAX];
	char *addr, *key;
	unsigned int type;
	int n;
	FILE *fp;

	snprintf(identity_path, sizeof(identity_path),
			"/sys/kernel/debug/bluetooth/hci%u/identity", index);

	fp = fopen(identity_path, "r");
	if (!fp) {
		perror("Failed to open identity file");
		return false;
	}

	n = fscanf(fp, "%m[0-9a-f:] (type %u) %m[0-9a-f]", &addr, &type, &key);

	fclose(fp);

	if (n != 3)
		return false;

	str2ba(addr, &irk->addr.bdaddr);
	convert_hexstr(key, irk->val, sizeof(irk->val));

	free(addr);
	free(key);

	switch (type) {
	case 0:
		irk->addr.type = BDADDR_LE_PUBLIC;
		break;
	case 1:
		irk->addr.type = BDADDR_LE_RANDOM;
		break;
	default:
		fprintf(stderr, "Invalid address type %u\n", type);
		return false;
	}

	return true;
}

static void controller_error(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	const struct mgmt_ev_controller_error *ev = param;

	if (len < sizeof(*ev)) {
		fprintf(stderr,
			"Too short (%u bytes) controller error event\n", len);
		return;
	}

	if (monitor)
		printf("hci%u error 0x%02x\n", index, ev->error_code);
}

static void index_added(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	if (monitor)
		printf("hci%u added\n", index);
}

static void index_removed(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	if (monitor)
		printf("hci%u removed\n", index);
}

static void unconf_index_added(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	if (monitor)
		printf("hci%u added (unconfigured)\n", index);
}

static void unconf_index_removed(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	if (monitor)
		printf("hci%u removed (unconfigured)\n", index);
}

static const char *options_str[] = {
				"external",
				"public-address",
};

static void print_options(uint32_t options)
{
	unsigned i;

	for (i = 0; i < NELEM(options_str); i++) {
		if ((options & (1 << i)) != 0)
			printf("%s ", options_str[i]);
	}
}

static void new_config_options(uint16_t index, uint16_t len,
					const void *param, void *user_data)
{
	const uint32_t *ev = param;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "Too short new_config_options event (%u)\n", len);
		return;
	}

	if (monitor) {
		printf("hci%u new_config_options: ", index);
		print_options(get_le32(ev));
		printf("\n");
	}
}

static const char *settings_str[] = {
				"powered",
				"connectable",
				"fast-connectable",
				"discoverable",
				"bondable",
				"link-security",
				"ssp",
				"br/edr",
				"hs",
				"le",
				"advertising",
				"secure-conn",
				"debug-keys",
				"privacy",
				"configuration",
};

static void print_settings(uint32_t settings)
{
	unsigned i;

	for (i = 0; i < NELEM(settings_str); i++) {
		if ((settings & (1 << i)) != 0)
			printf("%s ", settings_str[i]);
	}
}

static void new_settings(uint16_t index, uint16_t len,
					const void *param, void *user_data)
{
	const uint32_t *ev = param;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "Too short new_settings event (%u)\n", len);
		return;
	}

	if (monitor) {
		printf("hci%u new_settings: ", index);
		print_settings(get_le32(ev));
		printf("\n");
	}
}

static void discovering(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_discovering *ev = param;

	if (len < sizeof(*ev)) {
		fprintf(stderr, "Too short (%u bytes) discovering event\n",
									len);
		return;
	}

	if (ev->discovering == 0 && discovery) {
		mainloop_quit();
		return;
	}

	if (monitor)
		printf("hci%u type %u discovering %s\n", index,
				ev->type, ev->discovering ? "on" : "off");
}

static void new_link_key(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_new_link_key *ev = param;

	if (len != sizeof(*ev)) {
		fprintf(stderr, "Invalid new_link_key length (%u bytes)\n",
									len);
		return;
	}

	if (monitor) {
		char addr[18];
		ba2str(&ev->key.addr.bdaddr, addr);
		printf("hci%u new_link_key %s type 0x%02x pin_len %d "
				"store_hint %u\n", index, addr, ev->key.type,
				ev->key.pin_len, ev->store_hint);
	}
}

static const char *typestr(uint8_t type)
{
	const char *str[] = { "BR/EDR", "LE Public", "LE Random" };

	if (type <= BDADDR_LE_RANDOM)
		return str[type];

	return "(unknown)";
}

static void connected(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_device_connected *ev = param;
	uint16_t eir_len;

	if (len < sizeof(*ev)) {
		fprintf(stderr,
			"Invalid connected event length (%u bytes)\n", len);
		return;
	}

	eir_len = get_le16(&ev->eir_len);
	if (len != sizeof(*ev) + eir_len) {
		fprintf(stderr, "Invalid connected event length "
			"(%u bytes, eir_len %u bytes)\n", len, eir_len);
		return;
	}

	if (monitor) {
		char addr[18];
		ba2str(&ev->addr.bdaddr, addr);
		printf("hci%u %s type %s connected eir_len %u\n", index, addr,
					typestr(ev->addr.type), eir_len);
	}
}

static void disconnected(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_device_disconnected *ev = param;

	if (len < sizeof(struct mgmt_addr_info)) {
		fprintf(stderr,
			"Invalid disconnected event length (%u bytes)\n", len);
		return;
	}

	if (monitor) {
		char addr[18];
		uint8_t reason;

		if (len < sizeof(*ev))
			reason = MGMT_DEV_DISCONN_UNKNOWN;
		else
			reason = ev->reason;

		ba2str(&ev->addr.bdaddr, addr);
		printf("hci%u %s type %s disconnected with reason %u\n",
				index, addr, typestr(ev->addr.type), reason);
	}
}

static void conn_failed(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_connect_failed *ev = param;

	if (len != sizeof(*ev)) {
		fprintf(stderr,
			"Invalid connect_failed event length (%u bytes)\n", len);
		return;
	}

	if (monitor) {
		char addr[18];
		ba2str(&ev->addr.bdaddr, addr);
		printf("hci%u %s type %s connect failed (status 0x%02x, %s)\n",
				index, addr, typestr(ev->addr.type), ev->status,
				mgmt_errstr(ev->status));
	}
}

static void auth_failed(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_auth_failed *ev = param;

	if (len != sizeof(*ev)) {
		fprintf(stderr,
			"Invalid auth_failed event length (%u bytes)\n", len);
		return;
	}

	if (monitor) {
		char addr[18];
		ba2str(&ev->addr.bdaddr, addr);
		printf("hci%u %s auth failed with status 0x%02x (%s)\n",
			index, addr, ev->status, mgmt_errstr(ev->status));
	}
}

static void local_name_changed(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_local_name_changed *ev = param;

	if (len != sizeof(*ev)) {
		fprintf(stderr,
			"Invalid local_name_changed length (%u bytes)\n", len);
		return;
	}

	if (monitor)
		printf("hci%u name changed: %s\n", index, ev->name);
}

static void confirm_name_rsp(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_confirm_name *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		fprintf(stderr,
			"confirm_name failed with status 0x%02x (%s)\n",
					status, mgmt_errstr(status));
		return;
	}

	if (len != sizeof(*rp)) {
		fprintf(stderr, "confirm_name rsp length %u instead of %zu\n",
			len, sizeof(*rp));
		return;
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status != 0)
		fprintf(stderr, "confirm_name for %s failed: 0x%02x (%s)\n",
			addr, status, mgmt_errstr(status));
	else
		printf("confirm_name succeeded for %s\n", addr);
}

static char *eir_get_name(const uint8_t *eir, uint16_t eir_len)
{
	uint8_t parsed = 0;

	if (eir_len < 2)
		return NULL;

	while (parsed < eir_len - 1) {
		uint8_t field_len = eir[0];

		if (field_len == 0)
			break;

		parsed += field_len + 1;

		if (parsed > eir_len)
			break;

		/* Check for short of complete name */
		if (eir[1] == 0x09 || eir[1] == 0x08)
			return strndup((char *) &eir[2], field_len - 1);

		eir += field_len + 1;
	}

	return NULL;
}

static unsigned int eir_get_flags(const uint8_t *eir, uint16_t eir_len)
{
	uint8_t parsed = 0;

	if (eir_len < 2)
		return 0;

	while (parsed < eir_len - 1) {
		uint8_t field_len = eir[0];

		if (field_len == 0)
			break;

		parsed += field_len + 1;

		if (parsed > eir_len)
			break;

		/* Check for flags */
		if (eir[1] == 0x01)
			return eir[2];

		eir += field_len + 1;
	}

	return 0;
}

static void device_found(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_device_found *ev = param;
	struct mgmt *mgmt = user_data;
	uint16_t eir_len;
	uint32_t flags;

	if (len < sizeof(*ev)) {
		fprintf(stderr,
			"Too short device_found length (%u bytes)\n", len);
		return;
	}

	flags = btohl(ev->flags);

	eir_len = get_le16(&ev->eir_len);
	if (len != sizeof(*ev) + eir_len) {
		fprintf(stderr, "dev_found: expected %zu bytes, got %u bytes\n",
						sizeof(*ev) + eir_len, len);
		return;
	}

	if (monitor || discovery) {
		char addr[18], *name;

		ba2str(&ev->addr.bdaddr, addr);
		printf("hci%u dev_found: %s type %s rssi %d "
			"flags 0x%04x ", index, addr,
			typestr(ev->addr.type), ev->rssi, flags);

		if (ev->addr.type != BDADDR_BREDR)
			printf("AD flags 0x%02x ",
					eir_get_flags(ev->eir, eir_len));

		name = eir_get_name(ev->eir, eir_len);
		if (name)
			printf("name %s\n", name);
		else
			printf("eir_len %u\n", eir_len);

		free(name);
	}

	if (discovery && (flags & MGMT_DEV_FOUND_CONFIRM_NAME)) {
		struct mgmt_cp_confirm_name cp;

		memset(&cp, 0, sizeof(cp));
		memcpy(&cp.addr, &ev->addr, sizeof(cp.addr));
		if (resolve_names)
			cp.name_known = 0;
		else
			cp.name_known = 1;

		mgmt_reply(mgmt, MGMT_OP_CONFIRM_NAME, index, sizeof(cp), &cp,
						confirm_name_rsp, NULL, NULL);
	}
}

static void pin_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		fprintf(stderr,
			"PIN Code reply failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("PIN Reply successful\n");
}

static int mgmt_pin_reply(struct mgmt *mgmt, uint16_t index,
					const struct mgmt_addr_info *addr,
					const char *pin, size_t len)
{
	struct mgmt_cp_pin_code_reply cp;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, addr, sizeof(cp.addr));
	cp.pin_len = len;
	memcpy(cp.pin_code, pin, len);

	return mgmt_reply(mgmt, MGMT_OP_PIN_CODE_REPLY, index, sizeof(cp), &cp,
							pin_rsp, NULL, NULL);
}

static void pin_neg_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		fprintf(stderr,
			"PIN Neg reply failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("PIN Negative Reply successful\n");
}

static int mgmt_pin_neg_reply(struct mgmt *mgmt, uint16_t index,
					const struct mgmt_addr_info *addr)
{
	struct mgmt_cp_pin_code_neg_reply cp;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, addr, sizeof(cp.addr));

	return mgmt_reply(mgmt, MGMT_OP_PIN_CODE_NEG_REPLY, index,
				sizeof(cp), &cp, pin_neg_rsp, NULL, NULL);
}

static void request_pin(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_pin_code_request *ev = param;
	struct mgmt *mgmt = user_data;
	char pin[18];
	size_t pin_len;

	if (len != sizeof(*ev)) {
		fprintf(stderr,
			"Invalid pin_code request length (%u bytes)\n", len);
		return;
	}

	if (monitor) {
		char addr[18];
		ba2str(&ev->addr.bdaddr, addr);
		printf("hci%u %s request PIN\n", index, addr);
	}

	printf("PIN Request (press enter to reject) >> ");
	fflush(stdout);

	memset(pin, 0, sizeof(pin));

	if (fgets(pin, sizeof(pin), stdin) == NULL || pin[0] == '\n') {
		mgmt_pin_neg_reply(mgmt, index, &ev->addr);
		return;
	}

	pin_len = strlen(pin);
	if (pin[pin_len - 1] == '\n') {
		pin[pin_len - 1] = '\0';
		pin_len--;
	}

	mgmt_pin_reply(mgmt, index, &ev->addr, pin, pin_len);
}

static void confirm_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		fprintf(stderr,
			"User Confirm reply failed. status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("User Confirm Reply successful\n");
}

static int mgmt_confirm_reply(struct mgmt *mgmt, uint16_t index,
					const struct mgmt_addr_info *addr)
{
	struct mgmt_cp_user_confirm_reply cp;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, addr, sizeof(*addr));

	return mgmt_reply(mgmt, MGMT_OP_USER_CONFIRM_REPLY, index,
				sizeof(cp), &cp, confirm_rsp, NULL, NULL);
}

static void confirm_neg_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		fprintf(stderr,
			"Confirm Neg reply failed. status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("User Confirm Negative Reply successful\n");
}

static int mgmt_confirm_neg_reply(struct mgmt *mgmt, uint16_t index,
					const struct mgmt_addr_info *addr)
{
	struct mgmt_cp_user_confirm_reply cp;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, addr, sizeof(*addr));

	return mgmt_reply(mgmt, MGMT_OP_USER_CONFIRM_NEG_REPLY, index,
				sizeof(cp), &cp, confirm_neg_rsp, NULL, NULL);
}


static void user_confirm(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_user_confirm_request *ev = param;
	struct mgmt *mgmt = user_data;
	char rsp[5];
	size_t rsp_len;
	uint32_t val;
	char addr[18];

	if (len != sizeof(*ev)) {
		fprintf(stderr,
			"Invalid user_confirm request length (%u)\n", len);
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	val = get_le32(&ev->value);

	if (monitor)
		printf("hci%u %s User Confirm %06u hint %u\n", index, addr,
							val, ev->confirm_hint);

	if (ev->confirm_hint)
		printf("Accept pairing with %s (yes/no) >> ", addr);
	else
		printf("Confirm value %06u for %s (yes/no) >> ", val, addr);

	fflush(stdout);

	memset(rsp, 0, sizeof(rsp));

	if (fgets(rsp, sizeof(rsp), stdin) == NULL || rsp[0] == '\n') {
		mgmt_confirm_neg_reply(mgmt, index, &ev->addr);
		return;
	}

	rsp_len = strlen(rsp);
	if (rsp[rsp_len - 1] == '\n')
		rsp[rsp_len - 1] = '\0';

	if (rsp[0] == 'y' || rsp[0] == 'Y')
		mgmt_confirm_reply(mgmt, index, &ev->addr);
	else
		mgmt_confirm_neg_reply(mgmt, index, &ev->addr);
}

static void passkey_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		fprintf(stderr,
			"User Passkey reply failed. status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("User Passkey Reply successful\n");
}

static int mgmt_passkey_reply(struct mgmt *mgmt, uint16_t index,
					const struct mgmt_addr_info *addr,
					uint32_t passkey)
{
	struct mgmt_cp_user_passkey_reply cp;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, addr, sizeof(*addr));
	put_le32(passkey, &cp.passkey);

	return mgmt_reply(mgmt, MGMT_OP_USER_PASSKEY_REPLY, index,
				sizeof(cp), &cp, passkey_rsp, NULL, NULL);
}

static void passkey_neg_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		fprintf(stderr,
			"Passkey Neg reply failed. status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("User Passkey Negative Reply successful\n");
}

static int mgmt_passkey_neg_reply(struct mgmt *mgmt, uint16_t index,
					const struct mgmt_addr_info *addr)
{
	struct mgmt_cp_user_passkey_reply cp;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, addr, sizeof(*addr));

	return mgmt_reply(mgmt, MGMT_OP_USER_PASSKEY_NEG_REPLY, index,
				sizeof(cp), &cp, passkey_neg_rsp, NULL, NULL);
}


static void request_passkey(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_user_passkey_request *ev = param;
	struct mgmt *mgmt = user_data;
	char passkey[7];

	if (len != sizeof(*ev)) {
		fprintf(stderr,
			"Invalid passkey request length (%u bytes)\n", len);
		return;
	}

	if (monitor) {
		char addr[18];
		ba2str(&ev->addr.bdaddr, addr);
		printf("hci%u %s request passkey\n", index, addr);
	}

	printf("Passkey Request (press enter to reject) >> ");
	fflush(stdout);

	memset(passkey, 0, sizeof(passkey));

	if (fgets(passkey, sizeof(passkey), stdin) == NULL ||
							passkey[0] == '\n') {
		mgmt_passkey_neg_reply(mgmt, index, &ev->addr);
		return;
	}

	len = strlen(passkey);
	if (passkey[len - 1] == '\n') {
		passkey[len - 1] = '\0';
		len--;
	}

	mgmt_passkey_reply(mgmt, index, &ev->addr, atoi(passkey));
}

static void passkey_notify(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_passkey_notify *ev = param;

	if (len != sizeof(*ev)) {
		fprintf(stderr,
			"Invalid passkey request length (%u bytes)\n", len);
		return;
	}

	if (monitor) {
		char addr[18];
		ba2str(&ev->addr.bdaddr, addr);
		printf("hci%u %s request passkey\n", index, addr);
	}

	printf("Passkey Notify: %06u (entered %u)\n", get_le32(&ev->passkey),
								ev->entered);
}

static void cmd_monitor(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	printf("Monitoring mgmt events...\n");
	monitor = true;
}

static void version_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_version *rp = param;

	if (status != 0) {
		fprintf(stderr, "Reading mgmt version failed with status"
			" 0x%02x (%s)\n", status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small version reply (%u bytes)\n", len);
		goto done;
	}

	printf("MGMT Version %u, revision %u\n", rp->version,
						get_le16(&rp->revision));

done:
	mainloop_quit();
}

static void cmd_version(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	if (mgmt_send(mgmt, MGMT_OP_READ_VERSION, MGMT_INDEX_NONE,
				0, NULL, version_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send read_version cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void commands_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_commands *rp = param;
	uint16_t num_commands, num_events;
	const uint16_t *opcode;
	size_t expected_len;
	int i;

	if (status != 0) {
		fprintf(stderr, "Reading supported commands failed with status"
			" 0x%02x (%s)\n", status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small commands reply (%u bytes)\n", len);
		goto done;
	}

	num_commands = get_le16(&rp->num_commands);
	num_events = get_le16(&rp->num_events);

	expected_len = sizeof(*rp) + num_commands * sizeof(uint16_t) +
						num_events * sizeof(uint16_t);

	if (len < expected_len) {
		fprintf(stderr, "Too small commands reply (%u != %zu)\n",
							len, expected_len);
		goto done;
	}

	opcode = rp->opcodes;

	printf("%u commands:\n", num_commands);
	for (i = 0; i < num_commands; i++) {
		uint16_t op = get_le16(opcode++);
		printf("\t%s (0x%04x)\n", mgmt_opstr(op), op);
	}

	printf("%u events:\n", num_events);
	for (i = 0; i < num_events; i++) {
		uint16_t ev = get_le16(opcode++);
		printf("\t%s (0x%04x)\n", mgmt_evstr(ev), ev);
	}

done:
	mainloop_quit();
}

static void cmd_commands(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	if (mgmt_send(mgmt, MGMT_OP_READ_COMMANDS, MGMT_INDEX_NONE,
				0, NULL, commands_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send read_commands cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void unconf_index_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_unconf_index_list *rp = param;
	uint16_t count;
	unsigned int i;

	if (status != 0) {
		fprintf(stderr,
			"Reading index list failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small index list reply (%u bytes)\n",
									len);
		goto done;
	}

	count = get_le16(&rp->num_controllers);

	if (len < sizeof(*rp) + count * sizeof(uint16_t)) {
		fprintf(stderr,
			"Index count (%u) doesn't match reply length (%u)\n",
								count, len);
		goto done;
	}

	printf("Unconfigured index list with %u item%s\n",
						count, count != 1 ? "s" : "");

	for (i = 0; i < count; i++) {
		uint16_t index;

		index = get_le16(&rp->index[i]);

		printf("\thci%u\n", index);

	}

done:
	mainloop_quit();
}

static void config_info_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_config_info *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);

	if (status != 0) {
		fprintf(stderr,
			"Reading hci%u config failed with status 0x%02x (%s)\n",
					index, status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small info reply (%u bytes)\n", len);
		goto done;
	}

	printf("hci%u:\tmanufacturer %u\n", index, get_le16(&rp->manufacturer));

	printf("\tsupported options: ");
	print_options(get_le32(&rp->supported_options));
	printf("\n");

	printf("\tmissing options: ");
	print_options(get_le32(&rp->missing_options));
	printf("\n");

done:
	mainloop_quit();
}

static void cmd_config(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	void *data;

	if (index == MGMT_INDEX_NONE) {
		if (mgmt_send(mgmt, MGMT_OP_READ_UNCONF_INDEX_LIST,
					MGMT_INDEX_NONE, 0, NULL,
					unconf_index_rsp, mgmt, NULL) == 0) {
			fprintf(stderr, "Unable to send unconf_index_list cmd\n");
			exit(EXIT_FAILURE);
		}

		return;
	}

	data = UINT_TO_PTR(index);

	if (mgmt_send(mgmt, MGMT_OP_READ_CONFIG_INFO, index, 0, NULL,
					config_info_rsp, data, NULL) == 0) {
		fprintf(stderr, "Unable to send read_config_info cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void info_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_info *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);
	char addr[18];

	pending--;

	if (status != 0) {
		fprintf(stderr,
			"Reading hci%u info failed with status 0x%02x (%s)\n",
					index, status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small info reply (%u bytes)\n", len);
		goto done;
	}

	ba2str(&rp->bdaddr, addr);
	printf("hci%u:\taddr %s version %u manufacturer %u"
			" class 0x%02x%02x%02x\n", index,
			addr, rp->version, get_le16(&rp->manufacturer),
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);

	printf("\tsupported settings: ");
	print_settings(get_le32(&rp->supported_settings));

	printf("\n\tcurrent settings: ");
	print_settings(get_le32(&rp->current_settings));

	printf("\n\tname %s\n", rp->name);
	printf("\tshort name %s\n", rp->short_name);

	if (pending > 0)
		return;

done:
	mainloop_quit();
}

static void index_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	struct mgmt *mgmt = user_data;
	uint16_t count;
	unsigned int i;

	if (status != 0) {
		fprintf(stderr,
			"Reading index list failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small index list reply (%u bytes)\n",
									len);
		goto done;
	}

	count = get_le16(&rp->num_controllers);

	if (len < sizeof(*rp) + count * sizeof(uint16_t)) {
		fprintf(stderr,
			"Index count (%u) doesn't match reply length (%u)\n",
								count, len);
		goto done;
	}

	if (monitor)
		printf("Index list with %u item%s\n",
						count, count != 1 ? "s" : "");

	if (count == 0)
		goto done;

	if (monitor && count > 0)
		printf("\t");

	for (i = 0; i < count; i++) {
		uint16_t index;
		void *data;

		index = get_le16(&rp->index[i]);

		if (monitor)
			printf("hci%u ", index);

		data = UINT_TO_PTR(index);

		if (mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
						info_rsp, data, NULL) == 0) {
			fprintf(stderr, "Unable to send read_info cmd\n");
			goto done;
		}

		pending++;
	}

	if (monitor && count > 0)
		printf("\n");

	return;

done:
	mainloop_quit();
}

static void cmd_info(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	void *data;

	if (index == MGMT_INDEX_NONE) {
		if (mgmt_send(mgmt, MGMT_OP_READ_INDEX_LIST,
					MGMT_INDEX_NONE, 0, NULL,
					index_rsp, mgmt, NULL) == 0) {
			fprintf(stderr, "Unable to send index_list cmd\n");
			exit(EXIT_FAILURE);
		}

		return;
	}

	data = UINT_TO_PTR(index);

	if (mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL, info_rsp,
							data, NULL) == 0) {
		fprintf(stderr, "Unable to send read_info cmd\n");
		exit(EXIT_FAILURE);
	}
}

/* Wrapper to get the index and opcode to the response callback */
struct command_data {
	uint16_t id;
	uint16_t op;
	void (*callback) (uint16_t id, uint16_t op, uint8_t status,
					uint16_t len, const void *param);
};

static void cmd_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	struct command_data *data = user_data;

	data->callback(data->op, data->id, status, len, param);
}

static unsigned int send_cmd(struct mgmt *mgmt, uint16_t op, uint16_t id,
				uint16_t len, const void *param,
				void (*cb)(uint16_t id, uint16_t op,
						uint8_t status, uint16_t len,
						const void *param))
{
	struct command_data *data;
	unsigned int send_id;

	data = new0(struct command_data, 1);
	if (!data)
		return 0;

	data->id = id;
	data->op = op;
	data->callback = cb;

	send_id = mgmt_send(mgmt, op, id, len, param, cmd_rsp, data, free);
	if (send_id == 0)
		free(data);

	return send_id;
}

static void setting_rsp(uint16_t op, uint16_t id, uint8_t status, uint16_t len,
							const void *param)
{
	const uint32_t *rp = param;

	if (status != 0) {
		fprintf(stderr,
			"%s for hci%u failed with status 0x%02x (%s)\n",
			mgmt_opstr(op), id, status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small %s response (%u bytes)\n",
							mgmt_opstr(op), len);
		goto done;
	}

	printf("hci%u %s complete, settings: ", id, mgmt_opstr(op));
	print_settings(get_le32(rp));
	printf("\n");

done:
	mainloop_quit();
}

static void cmd_setting(struct mgmt *mgmt, uint16_t index, uint16_t op,
							int argc, char **argv)
{
	uint8_t val;

	if (argc < 2) {
		printf("Specify \"on\" or \"off\"\n");
		exit(EXIT_FAILURE);
	}

	if (strcasecmp(argv[1], "on") == 0 || strcasecmp(argv[1], "yes") == 0)
		val = 1;
	else if (strcasecmp(argv[1], "off") == 0)
		val = 0;
	else
		val = atoi(argv[1]);

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (send_cmd(mgmt, op, index, sizeof(val), &val, setting_rsp) == 0) {
		fprintf(stderr, "Unable to send %s cmd\n", mgmt_opstr(op));
		exit(EXIT_FAILURE);
	}
}

static void cmd_power(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_POWERED, argc, argv);
}

static void cmd_discov(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	struct mgmt_cp_set_discoverable cp;

	if (argc < 2) {
		printf("Usage: btmgmt %s <yes/no/limited> [timeout]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	memset(&cp, 0, sizeof(cp));

	if (strcasecmp(argv[1], "on") == 0 || strcasecmp(argv[1], "yes") == 0)
		cp.val = 1;
	else if (strcasecmp(argv[1], "off") == 0)
		cp.val = 0;
	else if (strcasecmp(argv[1], "limited") == 0)
		cp.val = 2;
	else
		cp.val = atoi(argv[1]);

	if (argc > 2)
		cp.timeout = htobs(atoi(argv[2]));

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (send_cmd(mgmt, MGMT_OP_SET_DISCOVERABLE, index, sizeof(cp), &cp,
							setting_rsp) == 0) {
		fprintf(stderr, "Unable to send set_discoverable cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void cmd_connectable(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_CONNECTABLE, argc, argv);
}

static void cmd_fast_conn(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_FAST_CONNECTABLE, argc, argv);
}

static void cmd_bondable(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_BONDABLE, argc, argv);
}

static void cmd_linksec(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_LINK_SECURITY, argc, argv);
}

static void cmd_ssp(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_SSP, argc, argv);
}

static void cmd_sc(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	uint8_t val;

	if (argc < 2) {
		printf("Specify \"on\" or \"off\" or \"only\"\n");
		exit(EXIT_FAILURE);
	}

	if (strcasecmp(argv[1], "on") == 0 || strcasecmp(argv[1], "yes") == 0)
		val = 1;
	else if (strcasecmp(argv[1], "off") == 0)
		val = 0;
	else if (strcasecmp(argv[1], "only") == 0)
		val = 2;
	else
		val = atoi(argv[1]);

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (send_cmd(mgmt, MGMT_OP_SET_SECURE_CONN, index,
					sizeof(val), &val, setting_rsp) == 0) {
		fprintf(stderr, "Unable to send set_secure_conn cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void cmd_hs(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_HS, argc, argv);
}

static void cmd_le(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_LE, argc, argv);
}

static void cmd_advertising(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_ADVERTISING, argc, argv);
}

static void cmd_bredr(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_BREDR, argc, argv);
}

static void cmd_privacy(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	struct mgmt_cp_set_privacy cp;

	if (argc < 2) {
		printf("Specify \"on\" or \"off\"\n");
		exit(EXIT_FAILURE);
	}

	if (strcasecmp(argv[1], "on") == 0 || strcasecmp(argv[1], "yes") == 0)
		cp.privacy = 0x01;
	else if (strcasecmp(argv[1], "off") == 0)
		cp.privacy = 0x00;
	else
		cp.privacy = atoi(argv[1]);

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (argc > 2) {
		if (convert_hexstr(argv[2], cp.irk,
					sizeof(cp.irk)) != sizeof(cp.irk)) {
			fprintf(stderr, "Invalid key format\n");
			exit(EXIT_FAILURE);
		}
	} else {
		int fd;

		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "open(/dev/urandom): %s\n",
							strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (read(fd, cp.irk, sizeof(cp.irk)) != sizeof(cp.irk)) {
			fprintf(stderr, "Reading from urandom failed\n");
			close(fd);
			exit(EXIT_FAILURE);
		}

		close(fd);
	}

	if (send_cmd(mgmt, MGMT_OP_SET_PRIVACY, index, sizeof(cp), &cp,
							setting_rsp) == 0) {
		fprintf(stderr, "Unable to send Set Privacy command\n");
		exit(EXIT_FAILURE);
	}
}

static void class_rsp(uint16_t op, uint16_t id, uint8_t status, uint16_t len,
							const void *param)
{
	const struct mgmt_ev_class_of_dev_changed *rp = param;

	if (len == 0 && status != 0) {
		fprintf(stderr, "%s failed, status 0x%02x (%s)\n",
				mgmt_opstr(op), status, mgmt_errstr(status));
		goto done;
	}

	if (len != sizeof(*rp)) {
		fprintf(stderr, "Unexpected %s len %u\n", mgmt_opstr(op), len);
		goto done;
	}

	printf("%s succeeded. Class 0x%02x%02x%02x\n", mgmt_opstr(op),
		rp->class_of_dev[2], rp->class_of_dev[1], rp->class_of_dev[0]);

done:
	mainloop_quit();
}

static void cmd_class(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	uint8_t class[2];

	if (argc < 3) {
		printf("Usage: btmgmt %s <major> <minor>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	class[0] = atoi(argv[1]);
	class[1] = atoi(argv[2]);

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (send_cmd(mgmt, MGMT_OP_SET_DEV_CLASS, index, sizeof(class), class,
							class_rsp) == 0) {
		fprintf(stderr, "Unable to send set_dev_class cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void disconnect_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_disconnect *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		fprintf(stderr, "Disconnect failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len != sizeof(*rp)) {
		fprintf(stderr, "Invalid disconnect response length (%u)\n",
									len);
		goto done;
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status == 0)
		printf("%s disconnected\n", addr);
	else
		fprintf(stderr,
			"Disconnecting %s failed with status 0x%02x (%s)\n",
				addr, status, mgmt_errstr(status));

done:
	mainloop_quit();
}

static void disconnect_usage(void)
{
	printf("Usage: btmgmt disconnect [-t type] <remote address>\n");
}

static struct option disconnect_options[] = {
	{ "help",	0, 0, 'h' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_disconnect(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	struct mgmt_cp_disconnect cp;
	uint8_t type = BDADDR_BREDR;
	int opt;

	while ((opt = getopt_long(argc, argv, "+t:h", disconnect_options,
								NULL)) != -1) {
		switch (opt) {
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			disconnect_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		disconnect_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	if (mgmt_send(mgmt, MGMT_OP_DISCONNECT, index, sizeof(cp), &cp,
					disconnect_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send disconnect cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void con_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_get_connections *rp = param;
	uint16_t count, i;

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small (%u bytes) get_connections rsp\n",
									len);
		goto done;
	}

	count = get_le16(&rp->conn_count);
	if (len != sizeof(*rp) + count * sizeof(struct mgmt_addr_info)) {
		fprintf(stderr, "Invalid get_connections length "
					" (count=%u, len=%u)\n", count, len);
		goto done;
	}

	for (i = 0; i < count; i++) {
		char addr[18];

		ba2str(&rp->addr[i].bdaddr, addr);

		printf("%s type %s\n", addr, typestr(rp->addr[i].type));
	}

done:
	mainloop_quit();
}

static void cmd_con(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (mgmt_send(mgmt, MGMT_OP_GET_CONNECTIONS, index, 0, NULL,
						con_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send get_connections cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void find_service_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		fprintf(stderr,
			"Unable to start service discovery. status 0x%02x (%s)\n",
			status, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("Service discovery started\n");
	discovery = true;
}

static void find_service_usage(void)
{
	printf("Usage: btmgmt find-service [-u UUID] [-r RSSI_Threshold] [-l|-b]\n");
}

static struct option find_service_options[] = {
	{ "help",	no_argument, 0, 'h' },
	{ "le-only",	no_argument, 0, 'l' },
	{ "bredr-only",	no_argument, 0, 'b' },
	{ "uuid",	required_argument, 0, 'u' },
	{ "rssi",	required_argument, 0, 'r' },
	{ 0, 0, 0, 0 }
};

static void uuid_to_uuid128(uuid_t *uuid128, const uuid_t *uuid)
{
	if (uuid->type == SDP_UUID16)
		sdp_uuid16_to_uuid128(uuid128, uuid);
	else if (uuid->type == SDP_UUID32)
		sdp_uuid32_to_uuid128(uuid128, uuid);
	else
		memcpy(uuid128, uuid, sizeof(*uuid));
}

#define MAX_UUIDS 4

static void cmd_find_service(struct mgmt *mgmt, uint16_t index, int argc,
			     char **argv)
{
	struct mgmt_cp_start_service_discovery *cp;
	uint8_t buf[sizeof(*cp) + 16 * MAX_UUIDS];
	uuid_t uuid;
	uint128_t uint128;
	uuid_t uuid128;
	uint8_t type;
	int8_t rssi;
	uint16_t count;
	int opt;

	if (index == MGMT_INDEX_NONE)
		index = 0;

	type = 0;
	type |= (1 << BDADDR_BREDR);
	type |= (1 << BDADDR_LE_PUBLIC);
	type |= (1 << BDADDR_LE_RANDOM);
	rssi = 127;
	count = 0;

	if (argc == 1) {
		find_service_usage();
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, "+lbu:r:p:h",
					find_service_options, NULL)) != -1) {
		switch (opt) {
		case 'l':
			type &= ~(1 << BDADDR_BREDR);
			type |= (1 << BDADDR_LE_PUBLIC);
			type |= (1 << BDADDR_LE_RANDOM);
			break;
		case 'b':
			type |= (1 << BDADDR_BREDR);
			type &= ~(1 << BDADDR_LE_PUBLIC);
			type &= ~(1 << BDADDR_LE_RANDOM);
			break;
		case 'u':
			if (count == MAX_UUIDS) {
				printf("Max %u UUIDs supported\n", MAX_UUIDS);
				exit(EXIT_FAILURE);
			}

			if (bt_string2uuid(&uuid, optarg) < 0) {
				printf("Invalid UUID: %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			cp = (void *) buf;
			uuid_to_uuid128(&uuid128, &uuid);
			ntoh128((uint128_t *) uuid128.value.uuid128.data,
				&uint128);
			htob128(&uint128, (uint128_t *) cp->uuids[count++]);
			break;
		case 'r':
			rssi = atoi(optarg);
			break;
		case 'h':
			find_service_usage();
			exit(EXIT_SUCCESS);
		default:
			find_service_usage();
			exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc > 0) {
		find_service_usage();
		exit(EXIT_FAILURE);
	}

	cp = (void *) buf;
	cp->type = type;
	cp->rssi = rssi;
	cp->uuid_count = cpu_to_le16(count);

	if (mgmt_send(mgmt, MGMT_OP_START_SERVICE_DISCOVERY, index,
				sizeof(*cp) + count * 16, cp,
				find_service_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send start_service_discovery cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void find_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		fprintf(stderr,
			"Unable to start discovery. status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		mainloop_quit();
		return;
	}

	printf("Discovery started\n");
	discovery = true;
}

static void find_usage(void)
{
	printf("Usage: btmgmt find [-l|-b]>\n");
}

static struct option find_options[] = {
	{ "help",	0, 0, 'h' },
	{ "le-only",	1, 0, 'l' },
	{ "bredr-only",	1, 0, 'b' },
	{ 0, 0, 0, 0 }
};

static void cmd_find(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_start_discovery cp;
	uint8_t type;
	int opt;

	if (index == MGMT_INDEX_NONE)
		index = 0;

	type = 0;
	type |= (1 << BDADDR_BREDR);
	type |= (1 << BDADDR_LE_PUBLIC);
	type |= (1 << BDADDR_LE_RANDOM);

	while ((opt = getopt_long(argc, argv, "+lbh", find_options,
								NULL)) != -1) {
		switch (opt) {
		case 'l':
			type &= ~(1 << BDADDR_BREDR);
			type |= (1 << BDADDR_LE_PUBLIC);
			type |= (1 << BDADDR_LE_RANDOM);
			break;
		case 'b':
			type |= (1 << BDADDR_BREDR);
			type &= ~(1 << BDADDR_LE_PUBLIC);
			type &= ~(1 << BDADDR_LE_RANDOM);
			break;
		case 'h':
		default:
			find_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	memset(&cp, 0, sizeof(cp));
	cp.type = type;

	if (mgmt_send(mgmt, MGMT_OP_START_DISCOVERY, index, sizeof(cp), &cp,
						find_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send start_discovery cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void name_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Unable to set local name "
						"with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));

	mainloop_quit();
}

static void cmd_name(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_set_local_name cp;

	if (argc < 2) {
		printf("Usage: btmgmt %s <name> [shortname]\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	strncpy((char *) cp.name, argv[1], HCI_MAX_NAME_LENGTH);
	if (argc > 2)
		strncpy((char *) cp.short_name, argv[2],
					MGMT_MAX_SHORT_NAME_LENGTH);

	if (mgmt_send(mgmt, MGMT_OP_SET_LOCAL_NAME, index, sizeof(cp), &cp,
						name_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send set_name cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void pair_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_pair_device *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		fprintf(stderr, "Pairing failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len != sizeof(*rp)) {
		fprintf(stderr, "Unexpected pair_rsp len %u\n", len);
		goto done;
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status != 0) {
		fprintf(stderr,
			"Pairing with %s (%s) failed. status 0x%02x (%s)\n",
			addr, typestr(rp->addr.type), status,
			mgmt_errstr(status));
		goto done;
	}

	printf("Paired with %s (%s)\n", addr, typestr(rp->addr.type));

done:
	mainloop_quit();
}

static void pair_usage(void)
{
	printf("Usage: btmgmt pair [-c cap] [-t type] <remote address>\n");
}

static struct option pair_options[] = {
	{ "help",	0, 0, 'h' },
	{ "capability",	1, 0, 'c' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_pair(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_pair_device cp;
	uint8_t cap = 0x01;
	uint8_t type = BDADDR_BREDR;
	char addr[18];
	int opt;

	while ((opt = getopt_long(argc, argv, "+c:t:h", pair_options,
								NULL)) != -1) {
		switch (opt) {
		case 'c':
			cap = strtol(optarg, NULL, 0);
			break;
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			pair_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		pair_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;
	cp.io_cap = cap;

	ba2str(&cp.addr.bdaddr, addr);
	printf("Pairing with %s (%s)\n", addr, typestr(cp.addr.type));

	if (mgmt_send(mgmt, MGMT_OP_PAIR_DEVICE, index, sizeof(cp), &cp,
						pair_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send pair_device cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void cancel_pair_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_addr_info *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		fprintf(stderr, "Cancel Pairing failed with 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len != sizeof(*rp)) {
		fprintf(stderr, "Unexpected cancel_pair_rsp len %u\n", len);
		goto done;
	}

	ba2str(&rp->bdaddr, addr);

	if (status != 0) {
		fprintf(stderr,
			"Cancel Pairing with %s (%s) failed. 0x%02x (%s)\n",
			addr, typestr(rp->type), status,
			mgmt_errstr(status));
		goto done;
	}

	printf("Pairing Cancelled with %s\n", addr);

done:
	mainloop_quit();
}

static void cancel_pair_usage(void)
{
	printf("Usage: btmgmt cancelpair [-t type] <remote address>\n");
}

static struct option cancel_pair_options[] = {
	{ "help",	0, 0, 'h' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_cancel_pair(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	struct mgmt_addr_info cp;
	uint8_t type = BDADDR_BREDR;
	int opt;

	while ((opt = getopt_long(argc, argv, "+t:h", cancel_pair_options,
								NULL)) != -1) {
		switch (opt) {
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			cancel_pair_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		cancel_pair_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.bdaddr);
	cp.type = type;

	if (mgmt_send(mgmt, MGMT_OP_CANCEL_PAIR_DEVICE, index, sizeof(cp), &cp,
					cancel_pair_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send cancel_pair_device cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void unpair_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_unpair_device *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		fprintf(stderr, "Unpair device failed. status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len != sizeof(*rp)) {
		fprintf(stderr, "Unexpected unpair_device_rsp len %u\n", len);
		goto done;
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status != 0) {
		fprintf(stderr,
			"Unpairing %s failed. status 0x%02x (%s)\n",
				addr, status, mgmt_errstr(status));
		goto done;
	}

	printf("%s unpaired\n", addr);

done:
	mainloop_quit();
}

static void unpair_usage(void)
{
	printf("Usage: btmgmt unpair [-t type] <remote address>\n");
}

static struct option unpair_options[] = {
	{ "help",	0, 0, 'h' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_unpair(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	struct mgmt_cp_unpair_device cp;
	uint8_t type = BDADDR_BREDR;
	int opt;

	while ((opt = getopt_long(argc, argv, "+t:h", unpair_options,
								NULL)) != -1) {
		switch (opt) {
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			unpair_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		unpair_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;
	cp.disconnect = 1;

	if (mgmt_send(mgmt, MGMT_OP_UNPAIR_DEVICE, index, sizeof(cp), &cp,
						unpair_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send unpair_device cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void keys_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Load keys failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	else
		printf("Keys successfully loaded\n");

	mainloop_quit();
}

static void cmd_keys(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_load_link_keys cp;

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));

	if (mgmt_send(mgmt, MGMT_OP_LOAD_LINK_KEYS, index, sizeof(cp), &cp,
						keys_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send load_keys cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void ltks_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Load keys failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	else
		printf("Long term keys successfully loaded\n");

	mainloop_quit();
}

static void cmd_ltks(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_load_long_term_keys cp;

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));

	if (mgmt_send(mgmt, MGMT_OP_LOAD_LONG_TERM_KEYS, index, sizeof(cp), &cp,
						ltks_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send load_ltks cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void irks_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Load IRKs failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	else
		printf("Identity Resolving Keys successfully loaded\n");

	mainloop_quit();
}

static void irks_usage(void)
{
	printf("Usage: btmgmt irks [--local]\n");
}

static struct option irks_options[] = {
	{ "help",	0, 0, 'h' },
	{ "local",	1, 0, 'l' },
	{ 0, 0, 0, 0 }
};

#define MAX_IRKS 4

static void cmd_irks(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_load_irks *cp;
	uint8_t buf[sizeof(*cp) + 23 * MAX_IRKS];
	uint16_t count, local_index;
	int opt;

	if (index == MGMT_INDEX_NONE)
		index = 0;

	cp = (void *) buf;
	count = 0;

	while ((opt = getopt_long(argc, argv, "+l:h",
					irks_options, NULL)) != -1) {
		switch (opt) {
		case 'l':
			if (count >= MAX_IRKS) {
				fprintf(stderr, "Number of IRKs exceeded\n");
				exit(EXIT_FAILURE);
			}
			if (strlen(optarg) > 3 &&
					strncasecmp(optarg, "hci", 3) == 0)
				local_index = atoi(optarg + 3);
			else
				local_index = atoi(optarg);
			if (!load_identity(local_index, &cp->irks[count])) {
				fprintf(stderr, "Unable to load identity\n");
				exit(EXIT_FAILURE);
			}
			count++;
			break;
		case 'h':
			irks_usage();
			exit(EXIT_SUCCESS);
		default:
			irks_usage();
			exit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc > 0) {
		irks_usage();
		exit(EXIT_FAILURE);
	}

	cp->irk_count = cpu_to_le16(count);

	if (mgmt_send(mgmt, MGMT_OP_LOAD_IRKS, index,
					sizeof(*cp) + count * 23, cp,
					irks_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send load_irks cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void block_rsp(uint16_t op, uint16_t id, uint8_t status, uint16_t len,
							const void *param)
{
	const struct mgmt_addr_info *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		fprintf(stderr, "%s failed, status 0x%02x (%s)\n",
				mgmt_opstr(op), status, mgmt_errstr(status));
		goto done;
	}

	if (len != sizeof(*rp)) {
		fprintf(stderr, "Unexpected %s len %u\n", mgmt_opstr(op), len);
		goto done;
	}

	ba2str(&rp->bdaddr, addr);

	if (status != 0) {
		fprintf(stderr, "%s %s (%s) failed. status 0x%02x (%s)\n",
				mgmt_opstr(op), addr, typestr(rp->type),
				status, mgmt_errstr(status));
		goto done;
	}

	printf("%s %s succeeded\n", mgmt_opstr(op), addr);

done:
	mainloop_quit();
}

static void block_usage(void)
{
	printf("Usage: btmgmt block [-t type] <remote address>\n");
}

static struct option block_options[] = {
	{ "help",	0, 0, 'h' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_block(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_block_device cp;
	uint8_t type = BDADDR_BREDR;
	int opt;

	while ((opt = getopt_long(argc, argv, "+t:h", block_options,
							NULL)) != -1) {
		switch (opt) {
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			block_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		block_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	if (send_cmd(mgmt, MGMT_OP_BLOCK_DEVICE, index, sizeof(cp), &cp,
							block_rsp) == 0) {
		fprintf(stderr, "Unable to send block_device cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void unblock_usage(void)
{
	printf("Usage: btmgmt unblock [-t type] <remote address>\n");
}

static void cmd_unblock(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	struct mgmt_cp_unblock_device cp;
	uint8_t type = BDADDR_BREDR;
	int opt;

	while ((opt = getopt_long(argc, argv, "+t:h", block_options,
							NULL)) != -1) {
		switch (opt) {
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			unblock_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		unblock_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	if (send_cmd(mgmt, MGMT_OP_UNBLOCK_DEVICE, index, sizeof(cp), &cp,
							block_rsp) == 0) {
		fprintf(stderr, "Unable to send unblock_device cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void cmd_add_uuid(struct mgmt *mgmt, uint16_t index, int argc,
							char **argv)
{
	struct mgmt_cp_add_uuid cp;
	uint128_t uint128;
	uuid_t uuid, uuid128;

	if (argc < 3) {
		printf("UUID and service hint needed\n");
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (bt_string2uuid(&uuid, argv[1]) < 0) {
		printf("Invalid UUID: %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	memset(&cp, 0, sizeof(cp));

	uuid_to_uuid128(&uuid128, &uuid);
	ntoh128((uint128_t *) uuid128.value.uuid128.data, &uint128);
	htob128(&uint128, (uint128_t *) cp.uuid);

	cp.svc_hint = atoi(argv[2]);

	if (send_cmd(mgmt, MGMT_OP_ADD_UUID, index, sizeof(cp), &cp,
							class_rsp) == 0) {
		fprintf(stderr, "Unable to send add_uuid cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void cmd_remove_uuid(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	struct mgmt_cp_remove_uuid cp;
	uint128_t uint128;
	uuid_t uuid, uuid128;

	if (argc < 2) {
		printf("UUID needed\n");
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (bt_string2uuid(&uuid, argv[1]) < 0) {
		printf("Invalid UUID: %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	memset(&cp, 0, sizeof(cp));

	uuid_to_uuid128(&uuid128, &uuid);
	ntoh128((uint128_t *) uuid128.value.uuid128.data, &uint128);
	htob128(&uint128, (uint128_t *) cp.uuid);

	if (send_cmd(mgmt, MGMT_OP_REMOVE_UUID, index, sizeof(cp), &cp,
							class_rsp) == 0) {
		fprintf(stderr, "Unable to send remove_uuid cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void cmd_clr_uuids(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	char *uuid_any = "00000000-0000-0000-0000-000000000000";
	char *rm_argv[] = { "rm-uuid", uuid_any, NULL };

	cmd_remove_uuid(mgmt, index, 2, rm_argv);
}

static void local_oob_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_local_oob_data *rp = param;
	const struct mgmt_rp_read_local_oob_ext_data *rp_ext = param;
	int i;

	if (status != 0) {
		fprintf(stderr, "Read Local OOB Data failed "
						"with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small (%u bytes) read_local_oob rsp\n",
									len);
		goto done;
	}

	printf("Hash C from P-192: ");
	for (i = 0; i < 16; i++)
		printf("%02x", rp->hash[i]);
	printf("\n");

	printf("Randomizer R with P-192: ");
	for (i = 0; i < 16; i++)
		printf("%02x", rp->randomizer[i]);
	printf("\n");

	if (len < sizeof(*rp_ext))
		goto done;

	printf("Hash C from P-256: ");
	for (i = 0; i < 16; i++)
		printf("%02x", rp_ext->hash256[i]);
	printf("\n");

	printf("Randomizer R with P-256: ");
	for (i = 0; i < 16; i++)
		printf("%02x", rp_ext->randomizer256[i]);
	printf("\n");

done:
	mainloop_quit();
}

static void cmd_local_oob(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (mgmt_send(mgmt, MGMT_OP_READ_LOCAL_OOB_DATA, index, 0, NULL,
					local_oob_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send read_local_oob cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void remote_oob_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_addr_info *rp = param;
	char addr[18];

	if (status != 0) {
		fprintf(stderr, "Add Remote OOB Data failed: 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		return;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small (%u bytes) add_remote_oob rsp\n",
									len);
		return;
	}

	ba2str(&rp->bdaddr, addr);
	printf("Remote OOB data added for %s (%u)\n", addr, rp->type);
}

static void remote_oob_usage(void)
{
	printf("Usage: btmgmt remote-oob [-t <addr_type>] "
		"[-r <rand192>] [-h <hash192>] [-R <rand256>] [-H <hash256>] "
		"<addr>\n");
}

static struct option remote_oob_opt[] = {
	{ "help",	0, 0, 'h' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_remote_oob(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_add_remote_oob_data cp;
	int opt;

	memset(&cp, 0, sizeof(cp));
	cp.addr.type = BDADDR_BREDR;

	while ((opt = getopt_long(argc, argv, "+t:r:R:h:H:",
					remote_oob_opt, NULL)) != -1) {
		switch (opt) {
		case 't':
			cp.addr.type = strtol(optarg, NULL, 0);
			break;
		case 'r':
			convert_hexstr(optarg, cp.rand192, 16);
			break;
		case 'h':
			convert_hexstr(optarg, cp.hash192, 16);
			break;
		case 'R':
			convert_hexstr(optarg, cp.rand256, 16);
			break;
		case 'H':
			convert_hexstr(optarg, cp.hash256, 16);
			break;
		default:
			remote_oob_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		remote_oob_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	str2ba(argv[0], &cp.addr.bdaddr);

	printf("Adding OOB data for %s (%s)\n", argv[0], typestr(cp.addr.type));

	if (mgmt_send(mgmt, MGMT_OP_ADD_REMOTE_OOB_DATA, index,
				sizeof(cp), &cp, remote_oob_rsp,
				NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send add_remote_oob cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void did_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Set Device ID failed "
						"with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	else
		printf("Device ID successfully set\n");

	mainloop_quit();
}

static void did_usage(void)
{
	printf("Usage: btmgmt did <source>:<vendor>:<product>:<version>\n");
	printf("       possible source values: bluetooth, usb\n");
}

static void cmd_did(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_set_device_id cp;
	uint16_t vendor, product, version , source;
	int result;

	if (argc < 2) {
		did_usage();
		exit(EXIT_FAILURE);
	}

	result = sscanf(argv[1], "bluetooth:%4hx:%4hx:%4hx", &vendor, &product,
								&version);
	if (result == 3) {
		source = 0x0001;
		goto done;
	}

	result = sscanf(argv[1], "usb:%4hx:%4hx:%4hx", &vendor, &product,
								&version);
	if (result == 3) {
		source = 0x0002;
		goto done;
	}

	did_usage();
	exit(EXIT_FAILURE);

done:
	if (index == MGMT_INDEX_NONE)
		index = 0;

	cp.source = htobs(source);
	cp.vendor = htobs(vendor);
	cp.product = htobs(product);
	cp.version = htobs(version);

	if (mgmt_send(mgmt, MGMT_OP_SET_DEVICE_ID, index, sizeof(cp), &cp,
						did_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send set_device_id cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void static_addr_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Set static address failed "
						"with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	else
		printf("Static address successfully set\n");

	mainloop_quit();
}

static void static_addr_usage(void)
{
	printf("Usage: btmgmt static-addr <address>\n");
}

static void cmd_static_addr(struct mgmt *mgmt, uint16_t index,
							int argc, char **argv)
{
	struct mgmt_cp_set_static_address cp;

	if (argc < 2) {
		static_addr_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	str2ba(argv[1], &cp.bdaddr);

	if (mgmt_send(mgmt, MGMT_OP_SET_STATIC_ADDRESS, index, sizeof(cp), &cp,
					static_addr_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send set_static_address cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void options_rsp(uint16_t op, uint16_t id, uint8_t status,
					uint16_t len, const void *param)
{
	const uint32_t *rp = param;

	if (status != 0) {
		fprintf(stderr,
			"%s for hci%u failed with status 0x%02x (%s)\n",
			mgmt_opstr(op), id, status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Too small %s response (%u bytes)\n",
							mgmt_opstr(op), len);
		goto done;
	}

	printf("hci%u %s complete, options: ", id, mgmt_opstr(op));
	print_options(get_le32(rp));
	printf("\n");

done:
	mainloop_quit();
}

static void cmd_public_addr(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_set_public_address cp;

	if (argc < 2) {
		printf("Usage: btmgmt public-addr <address>\n");
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	str2ba(argv[1], &cp.bdaddr);

	if (send_cmd(mgmt, MGMT_OP_SET_PUBLIC_ADDRESS, index, sizeof(cp), &cp,
							options_rsp) == 0) {
		fprintf(stderr, "Unable to send Set Public Address cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void cmd_ext_config(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_set_external_config cp;

	if (argc < 2) {
		printf("Specify \"on\" or \"off\"\n");
		exit(EXIT_FAILURE);
	}

	if (strcasecmp(argv[1], "on") == 0 || strcasecmp(argv[1], "yes") == 0)
		cp.config = 0x01;
	else if (strcasecmp(argv[1], "off") == 0)
		cp.config = 0x00;
	else
		cp.config = atoi(argv[1]);

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (send_cmd(mgmt, MGMT_OP_SET_EXTERNAL_CONFIG, index, sizeof(cp), &cp,
							options_rsp) == 0) {
		fprintf(stderr, "Unable to send Set External Config cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void cmd_debug_keys(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	cmd_setting(mgmt, index, MGMT_OP_SET_DEBUG_KEYS, argc, argv);
}

static void conn_info_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_get_conn_info *rp = param;	char addr[18];

	if (len == 0 && status != 0) {
		fprintf(stderr, "Get Conn Info failed, status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Unexpected Get Conn Info len %u\n", len);
		goto done;
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status != 0) {
		fprintf(stderr, "Get Conn Info for %s (%s) failed. status 0x%02x (%s)\n",
						addr, typestr(rp->addr.type),
						status, mgmt_errstr(status));
		goto done;
	}

	printf("Connection Information for %s (%s)\n",
						addr, typestr(rp->addr.type));
	printf("\tRSSI %d\n\tTX power %d\n\tmaximum TX power %d\n",
				rp->rssi, rp->tx_power, rp->max_tx_power);

done:
	mainloop_quit();
}

static void conn_info_usage(void)
{
	printf("Usage: btmgmt conn-info [-t type] <remote address>\n");
}

static struct option conn_info_options[] = {
	{ "help",	0, 0, 'h' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_conn_info(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_get_conn_info cp;
	uint8_t type = BDADDR_BREDR;
	int opt;

	while ((opt = getopt_long(argc, argv, "+t:h", conn_info_options,
								NULL)) != -1) {
		switch (opt) {
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			conn_info_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		conn_info_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	if (mgmt_send(mgmt, MGMT_OP_GET_CONN_INFO, index, sizeof(cp), &cp,
					conn_info_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send get_conn_info cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void io_cap_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Could not set IO Capability with "
						"status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	else
		printf("IO Capabilities successfully set\n");

	mainloop_quit();
}

static void io_cap_usage(void)
{
	printf("Usage: btmgmt io-cap <cap>\n");
}

static void cmd_io_cap(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_set_io_capability cp;
	uint8_t cap;

	if (argc < 2) {
		io_cap_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	cap = strtol(argv[1], NULL, 0);
	memset(&cp, 0, sizeof(cp));
	cp.io_capability = cap;

	if (mgmt_send(mgmt, MGMT_OP_SET_IO_CAPABILITY, index, sizeof(cp), &cp,
					io_cap_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send set-io-cap cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void scan_params_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Set scan parameters failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	else
		printf("Scan parameters successfully set\n");

	mainloop_quit();
}

static void scan_params_usage(void)
{
	printf("Usage: btmgmt scan-params <interval> <window>\n");
}

static void cmd_scan_params(struct mgmt *mgmt, uint16_t index,
							int argc, char **argv)
{
	struct mgmt_cp_set_scan_params cp;

	if (argc < 3) {
		scan_params_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	cp.interval = strtol(argv[1], NULL, 0);
	cp.window = strtol(argv[2], NULL, 0);

	if (mgmt_send(mgmt, MGMT_OP_SET_SCAN_PARAMS, index, sizeof(cp), &cp,
					scan_params_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send set_scan_params cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void clock_info_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_get_clock_info *rp = param;

	if (len < sizeof(*rp)) {
		fprintf(stderr, "Unexpected Get Clock Info len %u\n", len);
		exit(EXIT_FAILURE);
	}

	if (status) {
		fprintf(stderr, "Get Clock Info failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
		exit(EXIT_FAILURE);
	}

	printf("Local Clock:   %u\n", le32_to_cpu(rp->local_clock));
	printf("Piconet Clock: %u\n", le32_to_cpu(rp->piconet_clock));
	printf("Accurary:      %u\n", le16_to_cpu(rp->accuracy));

	mainloop_quit();
}

static void cmd_clock_info(struct mgmt *mgmt, uint16_t index,
							int argc, char **argv)
{
	struct mgmt_cp_get_clock_info cp;

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));

	if (argc > 1)
		str2ba(argv[1], &cp.addr.bdaddr);

	if (mgmt_send(mgmt, MGMT_OP_GET_CLOCK_INFO, index, sizeof(cp), &cp,
					clock_info_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send get_clock_info cmd\n");
		exit(EXIT_FAILURE);
	}
}

static void add_device_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Add device failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	mainloop_quit();
}

static void add_device_usage(void)
{
	printf("Usage: btmgmt add-device [-a action] [-t type] <address>\n");
}

static struct option add_device_options[] = {
	{ "help",	0, 0, 'h' },
	{ "action",	1, 0, 'a' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_add_device(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_add_device cp;
	uint8_t action = 0x00;
	uint8_t type = BDADDR_BREDR;
	char addr[18];
	int opt;

	while ((opt = getopt_long(argc, argv, "+a:t:h", add_device_options,
								NULL)) != -1) {
		switch (opt) {
		case 'a':
			action = strtol(optarg, NULL, 0);
			break;
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			add_device_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		add_device_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;
	cp.action = action;

	ba2str(&cp.addr.bdaddr, addr);
	printf("Adding device with %s (%s)\n", addr, typestr(cp.addr.type));

	if (mgmt_send(mgmt, MGMT_OP_ADD_DEVICE, index, sizeof(cp), &cp,
					add_device_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send add device command\n");
		exit(EXIT_FAILURE);
	}
}

static void remove_device_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		fprintf(stderr, "Remove device failed with status 0x%02x (%s)\n",
						status, mgmt_errstr(status));
	mainloop_quit();
}

static void del_device_usage(void)
{
	printf("Usage: btmgmt del-device [-t type] <address>\n");
}

static struct option del_device_options[] = {
	{ "help",	0, 0, 'h' },
	{ "type",	1, 0, 't' },
	{ 0, 0, 0, 0 }
};

static void cmd_del_device(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_remove_device cp;
	uint8_t type = BDADDR_BREDR;
	char addr[18];
	int opt;

	while ((opt = getopt_long(argc, argv, "+t:h", del_device_options,
								NULL)) != -1) {
		switch (opt) {
		case 't':
			type = strtol(optarg, NULL, 0);
			break;
		case 'h':
		default:
			del_device_usage();
			exit(EXIT_SUCCESS);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		del_device_usage();
		exit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	ba2str(&cp.addr.bdaddr, addr);
	printf("Removing device with %s (%s)\n", addr, typestr(cp.addr.type));

	if (mgmt_send(mgmt, MGMT_OP_REMOVE_DEVICE, index, sizeof(cp), &cp,
					remove_device_rsp, NULL, NULL) == 0) {
		fprintf(stderr, "Unable to send remove device command\n");
		exit(EXIT_FAILURE);
	}
}

static void cmd_clr_devices(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	char *bdaddr_any = "00:00:00:00:00:00";
	char *rm_argv[] = { "del-device", bdaddr_any, NULL };

	cmd_del_device(mgmt, index, 2, rm_argv);
}

static struct {
	char *cmd;
	void (*func)(struct mgmt *mgmt, uint16_t index, int argc, char **argv);
	char *doc;
} command[] = {
	{ "monitor",	cmd_monitor,	"Monitor events"		},
	{ "version",	cmd_version,	"Get the MGMT Version"		},
	{ "commands",	cmd_commands,	"List supported commands"	},
	{ "config",	cmd_config,	"Show configuration info"	},
	{ "info",	cmd_info,	"Show controller info"		},
	{ "power",	cmd_power,	"Toggle powered state"		},
	{ "discov",	cmd_discov,	"Toggle discoverable state"	},
	{ "connectable",cmd_connectable,"Toggle connectable state"	},
	{ "fast-conn",	cmd_fast_conn,	"Toggle fast connectable state"	},
	{ "bondable",	cmd_bondable,	"Toggle bondable state"		},
	{ "pairable",	cmd_bondable,	"Toggle bondable state"		},
	{ "linksec",	cmd_linksec,	"Toggle link level security"	},
	{ "ssp",	cmd_ssp,	"Toggle SSP mode"		},
	{ "sc",		cmd_sc,		"Toogle SC support"		},
	{ "hs",		cmd_hs,		"Toggle HS support"		},
	{ "le",		cmd_le,		"Toggle LE support"		},
	{ "advertising",cmd_advertising,"Toggle LE advertising",	},
	{ "bredr",	cmd_bredr,	"Toggle BR/EDR support",	},
	{ "privacy",	cmd_privacy,	"Toggle privacy support"	},
	{ "class",	cmd_class,	"Set device major/minor class"	},
	{ "disconnect", cmd_disconnect, "Disconnect device"		},
	{ "con",	cmd_con,	"List connections"		},
	{ "find",	cmd_find,	"Discover nearby devices"	},
	{ "find-service", cmd_find_service, "Discover nearby service"	},
	{ "name",	cmd_name,	"Set local name"		},
	{ "pair",	cmd_pair,	"Pair with a remote device"	},
	{ "cancelpair",	cmd_cancel_pair,"Cancel pairing"		},
	{ "unpair",	cmd_unpair,	"Unpair device"			},
	{ "keys",	cmd_keys,	"Load Link Keys"		},
	{ "ltks",	cmd_ltks,	"Load Long Term Keys"		},
	{ "irks",	cmd_irks,	"Load Identity Resolving Keys"	},
	{ "block",	cmd_block,	"Block Device"			},
	{ "unblock",	cmd_unblock,	"Unblock Device"		},
	{ "add-uuid",	cmd_add_uuid,	"Add UUID"			},
	{ "rm-uuid",	cmd_remove_uuid,"Remove UUID"			},
	{ "clr-uuids",	cmd_clr_uuids,	"Clear UUIDs"			},
	{ "local-oob",	cmd_local_oob,	"Local OOB data"		},
	{ "remote-oob",	cmd_remote_oob,	"Remote OOB data"		},
	{ "did",	cmd_did,	"Set Device ID"			},
	{ "static-addr",cmd_static_addr,"Set static address"		},
	{ "public-addr",cmd_public_addr,"Set public address"		},
	{ "ext-config",	cmd_ext_config,	"External configuration"	},
	{ "debug-keys",	cmd_debug_keys,	"Toogle debug keys"		},
	{ "conn-info",	cmd_conn_info,	"Get connection information"	},
	{ "io-cap",	cmd_io_cap,	"Set IO Capability"		},
	{ "scan-params",cmd_scan_params,"Set Scan Parameters"		},
	{ "get-clock",	cmd_clock_info,	"Get Clock Information"		},
	{ "add-device", cmd_add_device, "Add Device"			},
	{ "del-device", cmd_del_device, "Remove Device"			},
	{ "clr-devices",cmd_clr_devices,"Clear Devices"			},
	{ }
};

static void gap_ready(bool status, void *user_data)
{
}

static void usage(void)
{
	int i;

	printf("btmgmt ver %s\n", VERSION);
	printf("Usage:\n"
		"\tbtmgmt [options] <command> [command parameters]\n");

	printf("Options:\n"
		"\t--index <id>\tSpecify adapter index\n"
		"\t--verbose\tEnable extra logging\n"
		"\t--help\tDisplay help\n");

	printf("Commands:\n");
	for (i = 0; command[i].cmd; i++)
		printf("\t%-15s\t%s\n", command[i].cmd, command[i].doc);

	printf("\n"
		"For more information on the usage of each command use:\n"
		"\tbtmgmt <command> --help\n" );
}

static struct option main_options[] = {
	{ "index",	1, 0, 'i' },
	{ "verbose",	0, 0, 'v' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct bt_gap *gap;
	int opt, i;
	uint16_t index = MGMT_INDEX_NONE;
	struct mgmt *mgmt;
	int exit_status;

	while ((opt = getopt_long(argc, argv, "+hvi:",
						main_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (strlen(optarg) > 3 &&
					strncasecmp(optarg, "hci", 3) == 0)
				index = atoi(optarg + 3);
			else
				index = atoi(optarg);
			break;
		case 'v':
			monitor = true;
			break;
		case 'h':
		default:
			usage();
			return 0;
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		usage();
		return 0;
	}

	mainloop_init();

	if (index == MGMT_INDEX_NONE)
		gap = bt_gap_new_default();
	else
		gap = bt_gap_new_index(index);

	bt_gap_set_ready_handler(gap, gap_ready, NULL, NULL);

	mgmt = mgmt_new_default();
	if (!mgmt) {
		fprintf(stderr, "Unable to open mgmt_socket\n");
		return EXIT_FAILURE;
	}

	for (i = 0; command[i].cmd; i++) {
		if (strcmp(command[i].cmd, argv[0]) != 0)
			continue;

		command[i].func(mgmt, index, argc, argv);
		break;
	}

	if (command[i].cmd == NULL) {
		fprintf(stderr, "Unknown command: %s\n", argv[0]);
		mgmt_unref(mgmt);
		return EXIT_FAILURE;
	}

	mgmt_register(mgmt, MGMT_EV_CONTROLLER_ERROR, index, controller_error,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_INDEX_ADDED, index, index_added,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_INDEX_REMOVED, index, index_removed,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_NEW_SETTINGS, index, new_settings,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_DISCOVERING, index, discovering,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_NEW_LINK_KEY, index, new_link_key,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_DEVICE_CONNECTED, index, connected,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_DEVICE_DISCONNECTED, index, disconnected,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_CONNECT_FAILED, index, conn_failed,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_AUTH_FAILED, index, auth_failed,
								NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_LOCAL_NAME_CHANGED, index,
					local_name_changed, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_DEVICE_FOUND, index, device_found,
								mgmt, NULL);
	mgmt_register(mgmt, MGMT_EV_PIN_CODE_REQUEST, index, request_pin,
								mgmt, NULL);
	mgmt_register(mgmt, MGMT_EV_USER_CONFIRM_REQUEST, index, user_confirm,
								mgmt, NULL);
	mgmt_register(mgmt, MGMT_EV_USER_PASSKEY_REQUEST, index,
						request_passkey, mgmt, NULL);
	mgmt_register(mgmt, MGMT_EV_PASSKEY_NOTIFY, index,
						passkey_notify, mgmt, NULL);
	mgmt_register(mgmt, MGMT_EV_UNCONF_INDEX_ADDED, index,
					unconf_index_added, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_UNCONF_INDEX_REMOVED, index,
					unconf_index_removed, NULL, NULL);
	mgmt_register(mgmt, MGMT_EV_NEW_CONFIG_OPTIONS, index,
					new_config_options, NULL, NULL);

	exit_status = mainloop_run();

	mgmt_cancel_all(mgmt);
	mgmt_unregister_all(mgmt);
	mgmt_unref(mgmt);

	bt_gap_unref(gap);

	return exit_status;
}

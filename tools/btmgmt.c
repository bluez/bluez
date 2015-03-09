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
#include <stdarg.h>
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
#include <wordexp.h>
#include <ctype.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"

#include "src/uuid-helper.h"
#include "lib/mgmt.h"

#include "client/display.h"
#include "src/shared/mainloop.h"
#include "src/shared/io.h"
#include "src/shared/util.h"
#include "src/shared/mgmt.h"

static struct mgmt *mgmt = NULL;
static uint16_t mgmt_index = MGMT_INDEX_NONE;

static bool discovery = false;
static bool resolve_names = true;
static bool interactive = false;

static char *saved_prompt = NULL;
static int saved_point = 0;

static struct {
	uint16_t index;
	uint16_t req;
	struct mgmt_addr_info addr;
} prompt = {
	.index = MGMT_INDEX_NONE,
};

static int pending_index = 0;

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define PROMPT_ON	COLOR_BLUE "[mgmt]" COLOR_OFF "# "

static void update_prompt(uint16_t index)
{
	char str[32];

	if (index == MGMT_INDEX_NONE)
		snprintf(str, sizeof(str), "%s# ",
					COLOR_BLUE "[mgmt]" COLOR_OFF);
	else
		snprintf(str, sizeof(str),
				COLOR_BLUE "[hci%u]" COLOR_OFF "# ", index);

	if (saved_prompt) {
		free(saved_prompt);
		saved_prompt = strdup(str);
		return;
	}

	rl_set_prompt(str);
}

static void noninteractive_quit(int status)
{
	if (interactive)
		return;

	if (status == EXIT_SUCCESS)
		mainloop_exit_success();
	else
		mainloop_exit_failure();
}

#define print(fmt, arg...) do { \
	if (interactive) \
		rl_printf(fmt "\n", ## arg); \
	else \
		printf(fmt "\n", ## arg); \
} while (0)

#define error(fmt, arg...) do { \
	if (interactive) \
		rl_printf(COLOR_RED fmt "\n" COLOR_OFF, ## arg); \
	else \
		fprintf(stderr, fmt "\n", ## arg); \
} while (0)

static size_t hex2bin(const char *hexstr, uint8_t *buf, size_t buflen)
{
	size_t i, len;

	len = MIN((strlen(hexstr) / 2), buflen);
	memset(buf, 0, len);

	for (i = 0; i < len; i++)
		sscanf(hexstr + (i * 2), "%02hhX", &buf[i]);

	return len;
}

static size_t bin2hex(const uint8_t *buf, size_t buflen, char *str,
								size_t strlen)
{
	size_t i;

	for (i = 0; i < buflen && i < (strlen / 2); i++)
		sprintf(str + (i * 2), "%02x", buf[i]);

	return i;
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
		error("Failed to open identity file: %s", strerror(errno));
		return false;
	}

	n = fscanf(fp, "%m[0-9a-f:] (type %u) %m[0-9a-f]", &addr, &type, &key);

	fclose(fp);

	if (n != 3)
		return false;

	str2ba(addr, &irk->addr.bdaddr);
	hex2bin(key, irk->val, sizeof(irk->val));

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
		error("Invalid address type %u", type);
		return false;
	}

	return true;
}

static void controller_error(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	const struct mgmt_ev_controller_error *ev = param;

	if (len < sizeof(*ev)) {
		error("Too short (%u bytes) controller error event", len);
		return;
	}

	print("hci%u error 0x%02x", index, ev->error_code);
}

static void index_added(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	print("hci%u added", index);
}

static void index_removed(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	print("hci%u removed", index);
}

static void unconf_index_added(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	print("hci%u added (unconfigured)", index);
}

static void unconf_index_removed(uint16_t index, uint16_t len,
				const void *param, void *user_data)
{
	print("hci%u removed (unconfigured)", index);
}

static const char *options_str[] = {
				"external",
				"public-address",
};

static const char *options2str(uint32_t options)
{
	static char str[256];
	unsigned i;
	int off;

	off = 0;
	str[0] = '\0';

	for (i = 0; i < NELEM(options_str); i++) {
		if ((options & (1 << i)) != 0)
			off += snprintf(str + off, sizeof(str) - off, "%s ",
							options_str[i]);
	}

	return str;
}

static void new_config_options(uint16_t index, uint16_t len,
					const void *param, void *user_data)
{
	const uint32_t *ev = param;

	if (len < sizeof(*ev)) {
		error("Too short new_config_options event (%u)", len);
		return;
	}

	print("hci%u new_config_options: %s", index, options2str(get_le32(ev)));
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
				"static-addr",
};

static const char *settings2str(uint32_t settings)
{
	static char str[256];
	unsigned i;
	int off;

	off = 0;
	str[0] = '\0';

	for (i = 0; i < NELEM(settings_str); i++) {
		if ((settings & (1 << i)) != 0)
			off += snprintf(str + off, sizeof(str) - off, "%s ",
							settings_str[i]);
	}

	return str;
}

static void new_settings(uint16_t index, uint16_t len,
					const void *param, void *user_data)
{
	const uint32_t *ev = param;

	if (len < sizeof(*ev)) {
		error("Too short new_settings event (%u)", len);
		return;
	}

	print("hci%u new_settings: %s", index, settings2str(get_le32(ev)));
}

static void discovering(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_discovering *ev = param;

	if (len < sizeof(*ev)) {
		error("Too short (%u bytes) discovering event", len);
		return;
	}

	print("hci%u type %u discovering %s", index, ev->type,
					ev->discovering ? "on" : "off");

	if (ev->discovering == 0 && discovery)
		return noninteractive_quit(EXIT_SUCCESS);
}

static void new_link_key(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_new_link_key *ev = param;
	char addr[18];

	if (len != sizeof(*ev)) {
		error("Invalid new_link_key length (%u bytes)", len);
		return;
	}

	ba2str(&ev->key.addr.bdaddr, addr);
	print("hci%u new_link_key %s type 0x%02x pin_len %d store_hint %u",
		index, addr, ev->key.type, ev->key.pin_len, ev->store_hint);
}

static const char *typestr(uint8_t type)
{
	static const char *str[] = { "BR/EDR", "LE Public", "LE Random" };

	if (type <= BDADDR_LE_RANDOM)
		return str[type];

	return "(unknown)";
}

static void connected(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_device_connected *ev = param;
	uint16_t eir_len;
	char addr[18];

	if (len < sizeof(*ev)) {
		error("Invalid connected event length (%u bytes)", len);
		return;
	}

	eir_len = get_le16(&ev->eir_len);
	if (len != sizeof(*ev) + eir_len) {
		error("Invalid connected event length (%u != eir_len %u)",
								len, eir_len);
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	print("hci%u %s type %s connected eir_len %u", index, addr,
					typestr(ev->addr.type), eir_len);
}

static void release_prompt(void)
{
	if (!interactive)
		return;

	memset(&prompt, 0, sizeof(prompt));
	prompt.index = MGMT_INDEX_NONE;

	if (!saved_prompt)
		return;

	/* This will cause rl_expand_prompt to re-run over the last prompt,
	 * but our prompt doesn't expand anyway.
	 */
	rl_set_prompt(saved_prompt);
	rl_replace_line("", 0);
	rl_point = saved_point;
	rl_redisplay();

	free(saved_prompt);
	saved_prompt = NULL;
}

static void disconnected(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_device_disconnected *ev = param;
	char addr[18];
	uint8_t reason;

	if (len < sizeof(struct mgmt_addr_info)) {
		error("Invalid disconnected event length (%u bytes)", len);
		return;
	}

	if (!memcmp(&ev->addr, &prompt.addr, sizeof(ev->addr)))
		release_prompt();

	if (len < sizeof(*ev))
		reason = MGMT_DEV_DISCONN_UNKNOWN;
	else
		reason = ev->reason;

	ba2str(&ev->addr.bdaddr, addr);
	print("hci%u %s type %s disconnected with reason %u",
			index, addr, typestr(ev->addr.type), reason);
}

static void conn_failed(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_connect_failed *ev = param;
	char addr[18];

	if (len != sizeof(*ev)) {
		error("Invalid connect_failed event length (%u bytes)", len);
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	print("hci%u %s type %s connect failed (status 0x%02x, %s)",
			index, addr, typestr(ev->addr.type), ev->status,
			mgmt_errstr(ev->status));
}

static void auth_failed(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_auth_failed *ev = param;
	char addr[18];

	if (len != sizeof(*ev)) {
		error("Invalid auth_failed event length (%u bytes)", len);
		return;
	}

	if (!memcmp(&ev->addr, &prompt.addr, sizeof(ev->addr)))
		release_prompt();

	ba2str(&ev->addr.bdaddr, addr);
	print("hci%u %s auth failed with status 0x%02x (%s)",
			index, addr, ev->status, mgmt_errstr(ev->status));
}

static void local_name_changed(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_local_name_changed *ev = param;

	if (len != sizeof(*ev)) {
		error("Invalid local_name_changed length (%u bytes)", len);
		return;
	}

	print("hci%u name changed: %s", index, ev->name);
}

static void confirm_name_rsp(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_confirm_name *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		error("confirm_name failed with status 0x%02x (%s)", status,
							mgmt_errstr(status));
		return;
	}

	if (len != sizeof(*rp)) {
		error("confirm_name rsp length %u instead of %zu",
							len, sizeof(*rp));
		return;
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status != 0)
		error("confirm_name for %s failed: 0x%02x (%s)",
			addr, status, mgmt_errstr(status));
	else
		print("confirm_name succeeded for %s", addr);
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
		error("Too short device_found length (%u bytes)", len);
		return;
	}

	flags = btohl(ev->flags);

	eir_len = get_le16(&ev->eir_len);
	if (len != sizeof(*ev) + eir_len) {
		error("dev_found: expected %zu bytes, got %u bytes",
						sizeof(*ev) + eir_len, len);
		return;
	}

	if (discovery) {
		char addr[18], *name;

		ba2str(&ev->addr.bdaddr, addr);
		print("hci%u dev_found: %s type %s rssi %d "
			"flags 0x%04x ", index, addr,
			typestr(ev->addr.type), ev->rssi, flags);

		if (ev->addr.type != BDADDR_BREDR)
			print("AD flags 0x%02x ",
					eir_get_flags(ev->eir, eir_len));

		name = eir_get_name(ev->eir, eir_len);
		if (name)
			print("name %s", name);
		else
			print("eir_len %u", eir_len);

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
		error("PIN Code reply failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("PIN Reply successful");
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
		error("PIN Neg reply failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("PIN Negative Reply successful");
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

static void confirm_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		error("User Confirm reply failed. status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("User Confirm Reply successful");
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
		error("Confirm Neg reply failed. status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("User Confirm Negative Reply successful");
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

static void passkey_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		error("User Passkey reply failed. status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("User Passkey Reply successful");
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
		error("Passkey Neg reply failed. status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("User Passkey Negative Reply successful");
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

static bool prompt_input(const char *input)
{
	size_t len;

	if (!prompt.req)
		return false;

	len = strlen(input);

	switch (prompt.req) {
	case MGMT_EV_PIN_CODE_REQUEST:
		if (len)
			mgmt_pin_reply(mgmt, prompt.index, &prompt.addr,
								input, len);
		else
			mgmt_pin_neg_reply(mgmt, prompt.index, &prompt.addr);
		break;
	case MGMT_EV_USER_PASSKEY_REQUEST:
		if (strlen(input) > 0)
			mgmt_passkey_reply(mgmt, prompt.index, &prompt.addr,
								atoi(input));
		else
			mgmt_passkey_neg_reply(mgmt, prompt.index,
								&prompt.addr);
		break;
	case MGMT_EV_USER_CONFIRM_REQUEST:
		if (input[0] == 'y' || input[0] == 'Y')
			mgmt_confirm_reply(mgmt, prompt.index, &prompt.addr);
		else
			mgmt_confirm_neg_reply(mgmt, prompt.index,
								&prompt.addr);
		break;
	}

	release_prompt();

	return true;
}

static void interactive_prompt(const char *msg)
{
	if (saved_prompt)
		return;

	saved_prompt = strdup(rl_prompt);
	if (!saved_prompt)
		return;

	saved_point = rl_point;

	rl_set_prompt("");
	rl_redisplay();

	rl_set_prompt(msg);

	rl_replace_line("", 0);
	rl_redisplay();
}

static size_t get_input(char *buf, size_t buf_len)
{
	size_t len;

	if (!fgets(buf, buf_len, stdin))
		return 0;

	len = strlen(buf);

	/* Remove trailing white-space */
	while (len && isspace(buf[len - 1]))
		buf[--len] = '\0';

	return len;
}

static void ask(uint16_t index, uint16_t req, const struct mgmt_addr_info *addr,
						const char *fmt, ...)
{
	char msg[256], buf[18];
	va_list ap;
	int off;

	prompt.index = index;
	prompt.req = req;
	memcpy(&prompt.addr, addr, sizeof(*addr));

	va_start(ap, fmt);
	off = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	snprintf(msg + off, sizeof(msg) - off, " %s ",
					COLOR_BOLDGRAY ">>" COLOR_OFF);

	if (interactive) {
		interactive_prompt(msg);
		va_end(ap);
		return;
	}

	printf("%s", msg);
	fflush(stdout);

	memset(buf, 0, sizeof(buf));
	get_input(buf, sizeof(buf));
	prompt_input(buf);
}

static void request_pin(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_pin_code_request *ev = param;
	char addr[18];

	if (len != sizeof(*ev)) {
		error("Invalid pin_code request length (%u bytes)", len);
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	print("hci%u %s request PIN", index, addr);

	ask(index, MGMT_EV_PIN_CODE_REQUEST, &ev->addr,
				"PIN Request (press enter to reject)");
}

static void user_confirm(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_user_confirm_request *ev = param;
	uint32_t val;
	char addr[18];

	if (len != sizeof(*ev)) {
		error("Invalid user_confirm request length (%u)", len);
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	val = get_le32(&ev->value);

	print("hci%u %s User Confirm %06u hint %u", index, addr,
							val, ev->confirm_hint);

	if (ev->confirm_hint)
		ask(index, MGMT_EV_USER_CONFIRM_REQUEST, &ev->addr,
				"Accept pairing with %s (yes/no)", addr);
	else
		ask(index, MGMT_EV_USER_CONFIRM_REQUEST, &ev->addr,
			"Confirm value %06u for %s (yes/no)", val, addr);
}

static void request_passkey(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_user_passkey_request *ev = param;
	char addr[18];

	if (len != sizeof(*ev)) {
		error("Invalid passkey request length (%u bytes)", len);
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	print("hci%u %s request passkey", index, addr);

	ask(index, MGMT_EV_USER_PASSKEY_REQUEST, &ev->addr,
			"Passkey Request (press enter to reject)");
}

static void passkey_notify(uint16_t index, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_ev_passkey_notify *ev = param;
	char addr[18];

	if (len != sizeof(*ev)) {
		error("Invalid passkey request length (%u bytes)", len);
		return;
	}

	ba2str(&ev->addr.bdaddr, addr);
	print("hci%u %s request passkey", index, addr);

	print("Passkey Notify: %06u (entered %u)", get_le32(&ev->passkey),
								ev->entered);
}

static void version_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_version *rp = param;

	if (status != 0) {
		error("Reading mgmt version failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		error("Too small version reply (%u bytes)", len);
		goto done;
	}

	print("MGMT Version %u, revision %u", rp->version,
						get_le16(&rp->revision));

done:
	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_version(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	if (mgmt_send(mgmt, MGMT_OP_READ_VERSION, MGMT_INDEX_NONE,
				0, NULL, version_rsp, NULL, NULL) == 0) {
		error("Unable to send read_version cmd");
		return noninteractive_quit(EXIT_FAILURE);
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
		error("Read Supported Commands failed: status 0x%02x (%s)",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		error("Too small commands reply (%u bytes)", len);
		goto done;
	}

	num_commands = get_le16(&rp->num_commands);
	num_events = get_le16(&rp->num_events);

	expected_len = sizeof(*rp) + num_commands * sizeof(uint16_t) +
						num_events * sizeof(uint16_t);

	if (len < expected_len) {
		error("Too small commands reply (%u != %zu)",
							len, expected_len);
		goto done;
	}

	opcode = rp->opcodes;

	print("%u commands:", num_commands);
	for (i = 0; i < num_commands; i++) {
		uint16_t op = get_le16(opcode++);
		print("\t%s (0x%04x)", mgmt_opstr(op), op);
	}

	print("%u events:", num_events);
	for (i = 0; i < num_events; i++) {
		uint16_t ev = get_le16(opcode++);
		print("\t%s (0x%04x)", mgmt_evstr(ev), ev);
	}

done:
	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_commands(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	if (mgmt_send(mgmt, MGMT_OP_READ_COMMANDS, MGMT_INDEX_NONE,
				0, NULL, commands_rsp, NULL, NULL) == 0) {
		error("Unable to send read_commands cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void unconf_index_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_unconf_index_list *rp = param;
	uint16_t count;
	unsigned int i;

	if (status != 0) {
		error("Reading index list failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		error("Too small index list reply (%u bytes)", len);
		goto done;
	}

	count = get_le16(&rp->num_controllers);

	if (len < sizeof(*rp) + count * sizeof(uint16_t)) {
		error("Index count (%u) doesn't match reply length (%u)",
								count, len);
		goto done;
	}

	print("Unconfigured index list with %u item%s",
						count, count != 1 ? "s" : "");

	for (i = 0; i < count; i++) {
		uint16_t index;

		index = get_le16(&rp->index[i]);

		print("\thci%u", index);

	}

done:
	noninteractive_quit(EXIT_SUCCESS);
}

static void config_info_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_config_info *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);

	if (status != 0) {
		error("Reading hci%u config failed with status 0x%02x (%s)",
					index, status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		error("Too small info reply (%u bytes)", len);
		goto done;
	}

	print("hci%u:\tmanufacturer %u", index, get_le16(&rp->manufacturer));

	print("\tsupported options: %s",
			options2str(get_le32(&rp->supported_options)));
	print("\tmissing options: %s",
			options2str(get_le32(&rp->missing_options)));

done:
	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_config(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	void *data;

	if (index == MGMT_INDEX_NONE) {
		if (mgmt_send(mgmt, MGMT_OP_READ_UNCONF_INDEX_LIST,
					MGMT_INDEX_NONE, 0, NULL,
					unconf_index_rsp, mgmt, NULL) == 0) {
			error("Unable to send unconf_index_list cmd");
			return noninteractive_quit(EXIT_FAILURE);
		}

		return;
	}

	data = UINT_TO_PTR(index);

	if (mgmt_send(mgmt, MGMT_OP_READ_CONFIG_INFO, index, 0, NULL,
					config_info_rsp, data, NULL) == 0) {
		error("Unable to send read_config_info cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void info_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_info *rp = param;
	uint16_t index = PTR_TO_UINT(user_data);
	char addr[18];

	pending_index--;

	if (status != 0) {
		error("Reading hci%u info failed with status 0x%02x (%s)",
					index, status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		error("Too small info reply (%u bytes)", len);
		goto done;
	}

	ba2str(&rp->bdaddr, addr);
	print("hci%u:\taddr %s version %u manufacturer %u"
			" class 0x%02x%02x%02x", index,
			addr, rp->version, get_le16(&rp->manufacturer),
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);

	print("\tsupported settings: %s",
			settings2str(get_le32(&rp->supported_settings)));

	print("\tcurrent settings: %s",
			settings2str(get_le32(&rp->current_settings)));

	print("\tname %s", rp->name);
	print("\tshort name %s", rp->short_name);

	if (pending_index > 0)
		return;

done:
	noninteractive_quit(EXIT_SUCCESS);
}

static void index_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	struct mgmt *mgmt = user_data;
	uint16_t count;
	unsigned int i;

	if (status != 0) {
		error("Reading index list failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len < sizeof(*rp)) {
		error("Too small index list reply (%u bytes)", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	count = get_le16(&rp->num_controllers);

	if (len < sizeof(*rp) + count * sizeof(uint16_t)) {
		error("Index count (%u) doesn't match reply length (%u)",
								count, len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("Index list with %u item%s", count, count != 1 ? "s" : "");

	for (i = 0; i < count; i++) {
		uint16_t index;
		void *data;

		index = get_le16(&rp->index[i]);

		data = UINT_TO_PTR(index);

		if (mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL,
						info_rsp, data, NULL) == 0) {
			error("Unable to send read_info cmd");
			return noninteractive_quit(EXIT_FAILURE);
		}

		pending_index++;
	}

	if (!count)
		noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_info(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	void *data;

	if (index == MGMT_INDEX_NONE) {
		if (mgmt_send(mgmt, MGMT_OP_READ_INDEX_LIST,
					MGMT_INDEX_NONE, 0, NULL,
					index_rsp, mgmt, NULL) == 0) {
			error("Unable to send index_list cmd");
			return noninteractive_quit(EXIT_FAILURE);
		}

		return;
	}

	data = UINT_TO_PTR(index);

	if (mgmt_send(mgmt, MGMT_OP_READ_INFO, index, 0, NULL, info_rsp,
							data, NULL) == 0) {
		error("Unable to send read_info cmd");
		return noninteractive_quit(EXIT_FAILURE);
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
		error("%s for hci%u failed with status 0x%02x (%s)",
			mgmt_opstr(op), id, status, mgmt_errstr(status));
		goto done;
	}

	if (len < sizeof(*rp)) {
		error("Too small %s response (%u bytes)",
							mgmt_opstr(op), len);
		goto done;
	}

	print("hci%u %s complete, settings: %s", id, mgmt_opstr(op),
						settings2str(get_le32(rp)));

done:
	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_setting(struct mgmt *mgmt, uint16_t index, uint16_t op,
							int argc, char **argv)
{
	uint8_t val;

	if (argc < 2) {
		print("Specify \"on\" or \"off\"");
		return noninteractive_quit(EXIT_FAILURE);
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
		error("Unable to send %s cmd", mgmt_opstr(op));
		return noninteractive_quit(EXIT_FAILURE);
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
		print("Usage: %s <yes/no/limited> [timeout]", argv[0]);
		return noninteractive_quit(EXIT_FAILURE);
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
		error("Unable to send set_discoverable cmd");
		return noninteractive_quit(EXIT_FAILURE);
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
		print("Specify \"on\" or \"off\" or \"only\"");
		return noninteractive_quit(EXIT_FAILURE);
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
		error("Unable to send set_secure_conn cmd");
		return noninteractive_quit(EXIT_FAILURE);
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
		print("Specify \"on\" or \"off\"");
		return noninteractive_quit(EXIT_FAILURE);
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
		if (hex2bin(argv[2], cp.irk,
					sizeof(cp.irk)) != sizeof(cp.irk)) {
			error("Invalid key format");
			return noninteractive_quit(EXIT_FAILURE);
		}
	} else {
		int fd;

		fd = open("/dev/urandom", O_RDONLY);
		if (fd < 0) {
			error("open(/dev/urandom): %s", strerror(errno));
			return noninteractive_quit(EXIT_FAILURE);
		}

		if (read(fd, cp.irk, sizeof(cp.irk)) != sizeof(cp.irk)) {
			error("Reading from urandom failed");
			close(fd);
			return noninteractive_quit(EXIT_FAILURE);
		}

		close(fd);
	}

	if (send_cmd(mgmt, MGMT_OP_SET_PRIVACY, index, sizeof(cp), &cp,
							setting_rsp) == 0) {
		error("Unable to send Set Privacy command");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void class_rsp(uint16_t op, uint16_t id, uint8_t status, uint16_t len,
							const void *param)
{
	const struct mgmt_ev_class_of_dev_changed *rp = param;

	if (len == 0 && status != 0) {
		error("%s failed, status 0x%02x (%s)",
				mgmt_opstr(op), status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len != sizeof(*rp)) {
		error("Unexpected %s len %u", mgmt_opstr(op), len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("%s succeeded. Class 0x%02x%02x%02x", mgmt_opstr(op),
		rp->class_of_dev[2], rp->class_of_dev[1], rp->class_of_dev[0]);

	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_class(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	uint8_t class[2];

	if (argc < 3) {
		print("Usage: %s <major> <minor>", argv[0]);
		return noninteractive_quit(EXIT_FAILURE);
	}

	class[0] = atoi(argv[1]);
	class[1] = atoi(argv[2]);

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (send_cmd(mgmt, MGMT_OP_SET_DEV_CLASS, index, sizeof(class), class,
							class_rsp) == 0) {
		error("Unable to send set_dev_class cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void disconnect_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_disconnect *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		error("Disconnect failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len != sizeof(*rp)) {
		error("Invalid disconnect response length (%u)", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status == 0)
		print("%s disconnected", addr);
	else
		error("Disconnecting %s failed with status 0x%02x (%s)",
				addr, status, mgmt_errstr(status));

	noninteractive_quit(EXIT_SUCCESS);
}

static void disconnect_usage(void)
{
	print("Usage: disconnect [-t type] <remote address>");
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
			disconnect_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			disconnect_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		disconnect_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	if (mgmt_send(mgmt, MGMT_OP_DISCONNECT, index, sizeof(cp), &cp,
					disconnect_rsp, NULL, NULL) == 0) {
		error("Unable to send disconnect cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void con_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_get_connections *rp = param;
	uint16_t count, i;

	if (len < sizeof(*rp)) {
		error("Too small (%u bytes) get_connections rsp", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	count = get_le16(&rp->conn_count);
	if (len != sizeof(*rp) + count * sizeof(struct mgmt_addr_info)) {
		error("Invalid get_connections length (count=%u, len=%u)",
								count, len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	for (i = 0; i < count; i++) {
		char addr[18];

		ba2str(&rp->addr[i].bdaddr, addr);

		print("%s type %s", addr, typestr(rp->addr[i].type));
	}

	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_con(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (mgmt_send(mgmt, MGMT_OP_GET_CONNECTIONS, index, 0, NULL,
						con_rsp, NULL, NULL) == 0) {
		error("Unable to send get_connections cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void find_service_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		error("Start Service Discovery failed: status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("Service discovery started");
	discovery = true;
}

static void find_service_usage(void)
{
	print("Usage: find-service [-u UUID] [-r RSSI_Threshold] [-l|-b]");
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
		return noninteractive_quit(EXIT_FAILURE);
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
				print("Max %u UUIDs supported", MAX_UUIDS);
				return noninteractive_quit(EXIT_FAILURE);
			}

			if (bt_string2uuid(&uuid, optarg) < 0) {
				print("Invalid UUID: %s", optarg);
				return noninteractive_quit(EXIT_FAILURE);
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
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			find_service_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc > 0) {
		find_service_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	cp = (void *) buf;
	cp->type = type;
	cp->rssi = rssi;
	cp->uuid_count = cpu_to_le16(count);

	if (mgmt_send(mgmt, MGMT_OP_START_SERVICE_DISCOVERY, index,
				sizeof(*cp) + count * 16, cp,
				find_service_rsp, NULL, NULL) == 0) {
		error("Unable to send start_service_discovery cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void find_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0) {
		error("Unable to start discovery. status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("Discovery started");
	discovery = true;
}

static void find_usage(void)
{
	print("Usage: find [-l|-b]>");
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
			find_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			find_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	memset(&cp, 0, sizeof(cp));
	cp.type = type;

	if (mgmt_send(mgmt, MGMT_OP_START_DISCOVERY, index, sizeof(cp), &cp,
						find_rsp, NULL, NULL) == 0) {
		error("Unable to send start_discovery cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void name_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Unable to set local name with status 0x%02x (%s)",
						status, mgmt_errstr(status));

	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_name(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_set_local_name cp;

	if (argc < 2) {
		print("Usage: %s <name> [shortname]", argv[0]);
		return noninteractive_quit(EXIT_FAILURE);
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
		error("Unable to send set_name cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void pair_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_pair_device *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		error("Pairing failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len != sizeof(*rp)) {
		error("Unexpected pair_rsp len %u", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (!memcmp(&rp->addr, &prompt.addr, sizeof(rp->addr)))
		release_prompt();

	ba2str(&rp->addr.bdaddr, addr);

	if (status)
		error("Pairing with %s (%s) failed. status 0x%02x (%s)",
			addr, typestr(rp->addr.type), status,
			mgmt_errstr(status));
	else
		print("Paired with %s (%s)", addr, typestr(rp->addr.type));

	noninteractive_quit(EXIT_SUCCESS);
}

static void pair_usage(void)
{
	print("Usage: pair [-c cap] [-t type] <remote address>");
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
			pair_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			pair_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		pair_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;
	cp.io_cap = cap;

	ba2str(&cp.addr.bdaddr, addr);
	print("Pairing with %s (%s)", addr, typestr(cp.addr.type));

	if (mgmt_send(mgmt, MGMT_OP_PAIR_DEVICE, index, sizeof(cp), &cp,
						pair_rsp, NULL, NULL) == 0) {
		error("Unable to send pair_device cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void cancel_pair_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_addr_info *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		error("Cancel Pairing failed with 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len != sizeof(*rp)) {
		error("Unexpected cancel_pair_rsp len %u", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	ba2str(&rp->bdaddr, addr);

	if (status)
		error("Cancel Pairing with %s (%s) failed. 0x%02x (%s)",
			addr, typestr(rp->type), status,
			mgmt_errstr(status));
	else
		print("Pairing Cancelled with %s", addr);

	noninteractive_quit(EXIT_SUCCESS);
}

static void cancel_pair_usage(void)
{
	print("Usage: cancelpair [-t type] <remote address>");
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
			cancel_pair_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			cancel_pair_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		cancel_pair_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.bdaddr);
	cp.type = type;

	if (mgmt_send(mgmt, MGMT_OP_CANCEL_PAIR_DEVICE, index, sizeof(cp), &cp,
					cancel_pair_rsp, NULL, NULL) == 0) {
		error("Unable to send cancel_pair_device cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void unpair_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_unpair_device *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		error("Unpair device failed. status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len != sizeof(*rp)) {
		error("Unexpected unpair_device_rsp len %u", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status)
		error("Unpairing %s failed. status 0x%02x (%s)",
				addr, status, mgmt_errstr(status));
	else
		print("%s unpaired", addr);

	noninteractive_quit(EXIT_SUCCESS);
}

static void unpair_usage(void)
{
	print("Usage: unpair [-t type] <remote address>");
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
			unpair_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			unpair_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		unpair_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;
	cp.disconnect = 1;

	if (mgmt_send(mgmt, MGMT_OP_UNPAIR_DEVICE, index, sizeof(cp), &cp,
						unpair_rsp, NULL, NULL) == 0) {
		error("Unable to send unpair_device cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void keys_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Load keys failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	else
		print("Keys successfully loaded");

	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_keys(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_load_link_keys cp;

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));

	if (mgmt_send(mgmt, MGMT_OP_LOAD_LINK_KEYS, index, sizeof(cp), &cp,
						keys_rsp, NULL, NULL) == 0) {
		error("Unable to send load_keys cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void ltks_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Load keys failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	else
		print("Long term keys successfully loaded");

	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_ltks(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_load_long_term_keys cp;

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));

	if (mgmt_send(mgmt, MGMT_OP_LOAD_LONG_TERM_KEYS, index, sizeof(cp), &cp,
						ltks_rsp, NULL, NULL) == 0) {
		error("Unable to send load_ltks cmd");
		return noninteractive_quit(EXIT_SUCCESS);
	}
}

static void irks_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Load IRKs failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	else
		print("Identity Resolving Keys successfully loaded");

	noninteractive_quit(EXIT_SUCCESS);
}

static void irks_usage(void)
{
	print("Usage: irks [--local]");
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
				error("Number of IRKs exceeded");
				return noninteractive_quit(EXIT_FAILURE);
			}
			if (strlen(optarg) > 3 &&
					strncasecmp(optarg, "hci", 3) == 0)
				local_index = atoi(optarg + 3);
			else
				local_index = atoi(optarg);
			if (!load_identity(local_index, &cp->irks[count])) {
				error("Unable to load identity");
				return noninteractive_quit(EXIT_FAILURE);
			}
			count++;
			break;
		case 'h':
			irks_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			irks_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc > 0) {
		irks_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	cp->irk_count = cpu_to_le16(count);

	if (mgmt_send(mgmt, MGMT_OP_LOAD_IRKS, index,
					sizeof(*cp) + count * 23, cp,
					irks_rsp, NULL, NULL) == 0) {
		error("Unable to send load_irks cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void block_rsp(uint16_t op, uint16_t id, uint8_t status, uint16_t len,
							const void *param)
{
	const struct mgmt_addr_info *rp = param;
	char addr[18];

	if (len == 0 && status != 0) {
		error("%s failed, status 0x%02x (%s)",
				mgmt_opstr(op), status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len != sizeof(*rp)) {
		error("Unexpected %s len %u", mgmt_opstr(op), len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	ba2str(&rp->bdaddr, addr);

	if (status)
		error("%s %s (%s) failed. status 0x%02x (%s)",
				mgmt_opstr(op), addr, typestr(rp->type),
				status, mgmt_errstr(status));
	else
		print("%s %s succeeded", mgmt_opstr(op), addr);

	noninteractive_quit(EXIT_SUCCESS);
}

static void block_usage(void)
{
	print("Usage: block [-t type] <remote address>");
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
			block_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			block_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		block_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	if (send_cmd(mgmt, MGMT_OP_BLOCK_DEVICE, index, sizeof(cp), &cp,
							block_rsp) == 0) {
		error("Unable to send block_device cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void unblock_usage(void)
{
	print("Usage: unblock [-t type] <remote address>");
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
			unblock_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			unblock_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		unblock_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	if (send_cmd(mgmt, MGMT_OP_UNBLOCK_DEVICE, index, sizeof(cp), &cp,
							block_rsp) == 0) {
		error("Unable to send unblock_device cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void cmd_add_uuid(struct mgmt *mgmt, uint16_t index, int argc,
							char **argv)
{
	struct mgmt_cp_add_uuid cp;
	uint128_t uint128;
	uuid_t uuid, uuid128;

	if (argc < 3) {
		print("UUID and service hint needed");
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (bt_string2uuid(&uuid, argv[1]) < 0) {
		print("Invalid UUID: %s", argv[1]);
		return noninteractive_quit(EXIT_FAILURE);
	}

	memset(&cp, 0, sizeof(cp));

	uuid_to_uuid128(&uuid128, &uuid);
	ntoh128((uint128_t *) uuid128.value.uuid128.data, &uint128);
	htob128(&uint128, (uint128_t *) cp.uuid);

	cp.svc_hint = atoi(argv[2]);

	if (send_cmd(mgmt, MGMT_OP_ADD_UUID, index, sizeof(cp), &cp,
							class_rsp) == 0) {
		error("Unable to send add_uuid cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void cmd_remove_uuid(struct mgmt *mgmt, uint16_t index, int argc,
								char **argv)
{
	struct mgmt_cp_remove_uuid cp;
	uint128_t uint128;
	uuid_t uuid, uuid128;

	if (argc < 2) {
		print("UUID needed");
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (bt_string2uuid(&uuid, argv[1]) < 0) {
		print("Invalid UUID: %s", argv[1]);
		return noninteractive_quit(EXIT_FAILURE);
	}

	memset(&cp, 0, sizeof(cp));

	uuid_to_uuid128(&uuid128, &uuid);
	ntoh128((uint128_t *) uuid128.value.uuid128.data, &uint128);
	htob128(&uint128, (uint128_t *) cp.uuid);

	if (send_cmd(mgmt, MGMT_OP_REMOVE_UUID, index, sizeof(cp), &cp,
							class_rsp) == 0) {
		error("Unable to send remove_uuid cmd");
		return noninteractive_quit(EXIT_FAILURE);
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
	char str[33];

	if (status != 0) {
		error("Read Local OOB Data failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len < sizeof(*rp)) {
		error("Too small (%u bytes) read_local_oob rsp", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	bin2hex(rp->hash, 16, str, sizeof(str));
	print("Hash C from P-192: %s", str);

	bin2hex(rp->randomizer, 16, str, sizeof(str));
	print("Randomizer R with P-192: %s", str);

	if (len < sizeof(*rp_ext))
		return noninteractive_quit(EXIT_SUCCESS);

	bin2hex(rp_ext->hash256, 16, str, sizeof(str));
	print("Hash C from P-256: %s", str);

	bin2hex(rp_ext->randomizer256, 16, str, sizeof(str));
	print("Randomizer R with P-256: %s", str);

	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_local_oob(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	if (index == MGMT_INDEX_NONE)
		index = 0;

	if (mgmt_send(mgmt, MGMT_OP_READ_LOCAL_OOB_DATA, index, 0, NULL,
					local_oob_rsp, NULL, NULL) == 0) {
		error("Unable to send read_local_oob cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void remote_oob_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_addr_info *rp = param;
	char addr[18];

	if (status != 0) {
		error("Add Remote OOB Data failed: 0x%02x (%s)",
						status, mgmt_errstr(status));
		return;
	}

	if (len < sizeof(*rp)) {
		error("Too small (%u bytes) add_remote_oob rsp", len);
		return;
	}

	ba2str(&rp->bdaddr, addr);
	print("Remote OOB data added for %s (%u)", addr, rp->type);
}

static void remote_oob_usage(void)
{
	print("Usage: remote-oob [-t <addr_type>] "
		"[-r <rand192>] [-h <hash192>] [-R <rand256>] [-H <hash256>] "
		"<addr>");
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
			hex2bin(optarg, cp.rand192, 16);
			break;
		case 'h':
			hex2bin(optarg, cp.hash192, 16);
			break;
		case 'R':
			hex2bin(optarg, cp.rand256, 16);
			break;
		case 'H':
			hex2bin(optarg, cp.hash256, 16);
			break;
		default:
			remote_oob_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		remote_oob_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	str2ba(argv[0], &cp.addr.bdaddr);

	print("Adding OOB data for %s (%s)", argv[0], typestr(cp.addr.type));

	if (mgmt_send(mgmt, MGMT_OP_ADD_REMOTE_OOB_DATA, index,
				sizeof(cp), &cp, remote_oob_rsp,
				NULL, NULL) == 0) {
		error("Unable to send add_remote_oob cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void did_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Set Device ID failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	else
		print("Device ID successfully set");

	noninteractive_quit(EXIT_SUCCESS);
}

static void did_usage(void)
{
	print("Usage: did <source>:<vendor>:<product>:<version>");
	print("       possible source values: bluetooth, usb");
}

static void cmd_did(struct mgmt *mgmt, uint16_t index, int argc, char **argv)
{
	struct mgmt_cp_set_device_id cp;
	uint16_t vendor, product, version , source;
	int result;

	if (argc < 2) {
		did_usage();
		return noninteractive_quit(EXIT_FAILURE);
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
	return noninteractive_quit(EXIT_FAILURE);

done:
	if (index == MGMT_INDEX_NONE)
		index = 0;

	cp.source = htobs(source);
	cp.vendor = htobs(vendor);
	cp.product = htobs(product);
	cp.version = htobs(version);

	if (mgmt_send(mgmt, MGMT_OP_SET_DEVICE_ID, index, sizeof(cp), &cp,
						did_rsp, NULL, NULL) == 0) {
		error("Unable to send set_device_id cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void static_addr_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Set static address failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	else
		print("Static address successfully set");

	noninteractive_quit(EXIT_SUCCESS);
}

static void static_addr_usage(void)
{
	print("Usage: static-addr <address>");
}

static void cmd_static_addr(struct mgmt *mgmt, uint16_t index,
							int argc, char **argv)
{
	struct mgmt_cp_set_static_address cp;

	if (argc < 2) {
		static_addr_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	str2ba(argv[1], &cp.bdaddr);

	if (mgmt_send(mgmt, MGMT_OP_SET_STATIC_ADDRESS, index, sizeof(cp), &cp,
					static_addr_rsp, NULL, NULL) == 0) {
		error("Unable to send set_static_address cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void options_rsp(uint16_t op, uint16_t id, uint8_t status,
					uint16_t len, const void *param)
{
	const uint32_t *rp = param;

	if (status != 0) {
		error("%s for hci%u failed with status 0x%02x (%s)",
			mgmt_opstr(op), id, status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len < sizeof(*rp)) {
		error("Too small %s response (%u bytes)",
							mgmt_opstr(op), len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("hci%u %s complete, options: %s", id, mgmt_opstr(op),
						options2str(get_le32(rp)));

	noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_public_addr(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_set_public_address cp;

	if (argc < 2) {
		print("Usage: public-addr <address>");
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	str2ba(argv[1], &cp.bdaddr);

	if (send_cmd(mgmt, MGMT_OP_SET_PUBLIC_ADDRESS, index, sizeof(cp), &cp,
							options_rsp) == 0) {
		error("Unable to send Set Public Address cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void cmd_ext_config(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_set_external_config cp;

	if (argc < 2) {
		print("Specify \"on\" or \"off\"");
		return noninteractive_quit(EXIT_FAILURE);
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
		error("Unable to send Set External Config cmd");
		return noninteractive_quit(EXIT_FAILURE);
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
		error("Get Conn Info failed, status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (len < sizeof(*rp)) {
		error("Unexpected Get Conn Info len %u", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	ba2str(&rp->addr.bdaddr, addr);

	if (status) {
		error("Get Conn Info for %s (%s) failed. status 0x%02x (%s)",
						addr, typestr(rp->addr.type),
						status, mgmt_errstr(status));
	} else {
		print("Connection Information for %s (%s)",
						addr, typestr(rp->addr.type));
		print("\tRSSI %d\tTX power %d\tmaximum TX power %d",
				rp->rssi, rp->tx_power, rp->max_tx_power);
	}

	noninteractive_quit(EXIT_SUCCESS);
}

static void conn_info_usage(void)
{
	print("Usage: conn-info [-t type] <remote address>");
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
			conn_info_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			conn_info_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		conn_info_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	if (mgmt_send(mgmt, MGMT_OP_GET_CONN_INFO, index, sizeof(cp), &cp,
					conn_info_rsp, NULL, NULL) == 0) {
		error("Unable to send get_conn_info cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void io_cap_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Could not set IO Capability with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	else
		print("IO Capabilities successfully set");

	noninteractive_quit(EXIT_SUCCESS);
}

static void io_cap_usage(void)
{
	print("Usage: io-cap <cap>");
}

static void cmd_io_cap(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	struct mgmt_cp_set_io_capability cp;
	uint8_t cap;

	if (argc < 2) {
		io_cap_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	cap = strtol(argv[1], NULL, 0);
	memset(&cp, 0, sizeof(cp));
	cp.io_capability = cap;

	if (mgmt_send(mgmt, MGMT_OP_SET_IO_CAPABILITY, index, sizeof(cp), &cp,
					io_cap_rsp, NULL, NULL) == 0) {
		error("Unable to send set-io-cap cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void scan_params_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Set scan parameters failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	else
		print("Scan parameters successfully set");

	noninteractive_quit(EXIT_SUCCESS);
}

static void scan_params_usage(void)
{
	print("Usage: scan-params <interval> <window>");
}

static void cmd_scan_params(struct mgmt *mgmt, uint16_t index,
							int argc, char **argv)
{
	struct mgmt_cp_set_scan_params cp;

	if (argc < 3) {
		scan_params_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	cp.interval = strtol(argv[1], NULL, 0);
	cp.window = strtol(argv[2], NULL, 0);

	if (mgmt_send(mgmt, MGMT_OP_SET_SCAN_PARAMS, index, sizeof(cp), &cp,
					scan_params_rsp, NULL, NULL) == 0) {
		error("Unable to send set_scan_params cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void clock_info_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	const struct mgmt_rp_get_clock_info *rp = param;

	if (len < sizeof(*rp)) {
		error("Unexpected Get Clock Info len %u", len);
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (status) {
		error("Get Clock Info failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
		return noninteractive_quit(EXIT_FAILURE);
	}

	print("Local Clock:   %u", le32_to_cpu(rp->local_clock));
	print("Piconet Clock: %u", le32_to_cpu(rp->piconet_clock));
	print("Accurary:      %u", le16_to_cpu(rp->accuracy));

	noninteractive_quit(EXIT_SUCCESS);
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
		error("Unable to send get_clock_info cmd");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void add_device_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Add device failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	noninteractive_quit(EXIT_SUCCESS);
}

static void add_device_usage(void)
{
	print("Usage: add-device [-a action] [-t type] <address>");
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
			add_device_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			add_device_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		add_device_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;
	cp.action = action;

	ba2str(&cp.addr.bdaddr, addr);
	print("Adding device with %s (%s)", addr, typestr(cp.addr.type));

	if (mgmt_send(mgmt, MGMT_OP_ADD_DEVICE, index, sizeof(cp), &cp,
					add_device_rsp, NULL, NULL) == 0) {
		error("Unable to send add device command");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void remove_device_rsp(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	if (status != 0)
		error("Remove device failed with status 0x%02x (%s)",
						status, mgmt_errstr(status));
	noninteractive_quit(EXIT_SUCCESS);
}

static void del_device_usage(void)
{
	print("Usage: del-device [-t type] <address>");
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
			del_device_usage();
			return noninteractive_quit(EXIT_SUCCESS);
		default:
			del_device_usage();
			return noninteractive_quit(EXIT_FAILURE);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		del_device_usage();
		return noninteractive_quit(EXIT_FAILURE);
	}

	if (index == MGMT_INDEX_NONE)
		index = 0;

	memset(&cp, 0, sizeof(cp));
	str2ba(argv[0], &cp.addr.bdaddr);
	cp.addr.type = type;

	ba2str(&cp.addr.bdaddr, addr);
	print("Removing device with %s (%s)", addr, typestr(cp.addr.type));

	if (mgmt_send(mgmt, MGMT_OP_REMOVE_DEVICE, index, sizeof(cp), &cp,
					remove_device_rsp, NULL, NULL) == 0) {
		error("Unable to send remove device command");
		return noninteractive_quit(EXIT_FAILURE);
	}
}

static void cmd_clr_devices(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	char *bdaddr_any = "00:00:00:00:00:00";
	char *rm_argv[] = { "del-device", bdaddr_any, NULL };

	cmd_del_device(mgmt, index, 2, rm_argv);
}

struct cmd_info {
	char *cmd;
	void (*func)(struct mgmt *mgmt, uint16_t index, int argc, char **argv);
	char *doc;
	char * (*gen) (const char *text, int state);
	void (*disp) (char **matches, int num_matches, int max_length);
};

static struct cmd_info all_cmd[] = {
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
};

static void cmd_quit(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	mainloop_exit_success();
}

static void register_mgmt_callbacks(struct mgmt *mgmt, uint16_t index)
{
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

}

static void cmd_select(struct mgmt *mgmt, uint16_t index,
						int argc, char **argv)
{
	if (argc != 2) {
		error("Usage: select <index>");
		return;
	}

	mgmt_cancel_all(mgmt);
	mgmt_unregister_all(mgmt);

	if (!strcmp(argv[1], "none") || !strcmp(argv[1], "any") ||
						!strcmp(argv[1], "all"))
		mgmt_index = MGMT_INDEX_NONE;
	else if (!strncmp(argv[1], "hci", 3))
		mgmt_index = atoi(&argv[1][3]);
	else
		mgmt_index = atoi(argv[1]);

	register_mgmt_callbacks(mgmt, mgmt_index);

	print("Selected index %u", mgmt_index);

	update_prompt(mgmt_index);
}

static struct cmd_info interactive_cmd[] = {
	{ "select",	cmd_select,	"Select a different index"	},
	{ "quit",	cmd_quit,	"Exit program"			},
	{ "exit",	cmd_quit,	"Exit program"			},
	{ "help",	NULL,		"List supported commands"	},
};

static char *cmd_generator(const char *text, int state)
{
	static size_t i, j, len;
	const char *cmd;

	if (!state) {
		i = 0;
		j = 0;
		len = strlen(text);
	}

	while (i < NELEM(all_cmd)) {
		cmd = all_cmd[i++].cmd;

		if (!strncmp(cmd, text, len))
			return strdup(cmd);
	}

	while (j < NELEM(interactive_cmd)) {
		cmd = interactive_cmd[j++].cmd;

		if (!strncmp(cmd, text, len))
			return strdup(cmd);
	}

	return NULL;
}

static char **cmd_completion(const char *text, int start, int end)
{
	char **matches = NULL;

	if (start > 0) {
		unsigned int i;

		for (i = 0; i < NELEM(all_cmd); i++) {
			struct cmd_info *c = &all_cmd[i];

			if (strncmp(c->cmd, rl_line_buffer, start - 1))
				continue;

			if (!c->gen)
				continue;

			rl_completion_display_matches_hook = c->disp;
			matches = rl_completion_matches(text, c->gen);
			break;
		}
	} else {
		rl_completion_display_matches_hook = NULL;
		matches = rl_completion_matches(text, cmd_generator);
	}

	if (!matches)
		rl_attempted_completion_over = 1;

	return matches;
}

static struct cmd_info *find_cmd(const char *cmd, struct cmd_info table[],
							size_t cmd_count)
{
	size_t i;

	for (i = 0; i < cmd_count; i++) {
		if (!strcmp(table[i].cmd, cmd))
			return &table[i];
	}

	return NULL;
}

static void rl_handler(char *input)
{
	struct cmd_info *c;
	wordexp_t w;
	char *cmd, **argv;
	size_t argc, i;

	if (!input) {
		rl_insert_text("quit");
		rl_redisplay();
		rl_crlf();
		mainloop_quit();
		return;
	}

	if (!strlen(input))
		goto done;

	if (prompt_input(input))
		goto done;

	add_history(input);

	if (wordexp(input, &w, WRDE_NOCMD))
		goto done;

	if (w.we_wordc == 0)
		goto free_we;

	cmd = w.we_wordv[0];
	argv = w.we_wordv;
	argc = w.we_wordc;

	c = find_cmd(cmd, all_cmd, NELEM(all_cmd));
	if (!c && interactive)
		c = find_cmd(cmd, interactive_cmd, NELEM(interactive_cmd));

	if (c && c->func) {
		c->func(mgmt, mgmt_index, argc, argv);
		goto free_we;
	}

	if (strcmp(cmd, "help")) {
		print("Invalid command");
		goto free_we;
	}

	print("Available commands:");

	for (i = 0; i < NELEM(all_cmd); i++) {
		c = &all_cmd[i];
		if (c->doc)
			print("  %s %-*s %s", c->cmd,
				(int)(25 - strlen(c->cmd)), "", c->doc ? : "");
	}

	if (!interactive)
		goto free_we;

	for (i = 0; i < NELEM(interactive_cmd); i++) {
		c = &interactive_cmd[i];
		if (c->doc)
			print("  %s %-*s %s", c->cmd,
				(int)(25 - strlen(c->cmd)), "", c->doc ? : "");
	}

free_we:
	wordfree(&w);
done:
	free(input);
}

static void usage(void)
{
	unsigned int i;

	printf("btmgmt ver %s\n", VERSION);
	printf("Usage:\n"
		"\tbtmgmt [options] <command> [command parameters]\n");

	printf("Options:\n"
		"\t--index <id>\tSpecify adapter index\n"
		"\t--verbose\tEnable extra logging\n"
		"\t--help\tDisplay help\n");

	printf("Commands:\n");
	for (i = 0; i < NELEM(all_cmd); i++)
		printf("\t%-15s\t%s\n", all_cmd[i].cmd, all_cmd[i].doc);

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

static bool prompt_read(struct io *io, void *user_data)
{
	rl_callback_read_char();
	return true;
}

static struct io *setup_stdin(void)
{
	struct io *io;

	io = io_new(STDIN_FILENO);
	if (!io)
		return io;

	io_set_read_handler(io, prompt_read, NULL, NULL);

	return io;
}

int main(int argc, char *argv[])
{
	struct io *input;
	uint16_t index = MGMT_INDEX_NONE;
	int status, opt;

	while ((opt = getopt_long(argc, argv, "+hi:",
						main_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (strlen(optarg) > 3 &&
					strncasecmp(optarg, "hci", 3) == 0)
				index = atoi(optarg + 3);
			else
				index = atoi(optarg);
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

	mainloop_init();

	mgmt = mgmt_new_default();
	if (!mgmt) {
		fprintf(stderr, "Unable to open mgmt_socket\n");
		return EXIT_FAILURE;
	}

	if (argc > 0) {
		struct cmd_info *c;

		c = find_cmd(argv[0], all_cmd, NELEM(all_cmd));
		if (!c) {
			fprintf(stderr, "Unknown command: %s\n", argv[0]);
			mgmt_unref(mgmt);
			return EXIT_FAILURE;
		}

		c->func(mgmt, index, argc, argv);
	}

	register_mgmt_callbacks(mgmt, index);

	/* Interactive mode */
	if (!argc)
		input = setup_stdin();
	else
		input = NULL;

	if (input) {
		interactive = true;

		rl_attempted_completion_function = cmd_completion;

		rl_erase_empty_line = 1;
		rl_callback_handler_install(NULL, rl_handler);

		update_prompt(index);
		rl_redisplay();
	}

	mgmt_index = index;

	status = mainloop_run();

	if (input) {
		io_destroy(input);

		rl_message("");
		rl_callback_handler_remove();
	}

	mgmt_cancel_all(mgmt);
	mgmt_unregister_all(mgmt);
	mgmt_unref(mgmt);

	return status;
}

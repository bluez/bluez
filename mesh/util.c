/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <readline/readline.h>
#include <glib.h>

#include "client/display.h"
#include "src/shared/util.h"
#include "mesh/mesh-net.h"
#include "mesh/node.h"
#include "mesh/util.h"

struct cmd_menu {
	const char *name;
	const struct menu_entry *table;
};

static struct menu_entry *main_cmd_table;
static struct menu_entry *current_cmd_table;
static GList *menu_list;

static char *main_menu_prompt;
static int main_menu_point;

static int match_menu_name(const void *a, const void *b)
{
	const struct cmd_menu *menu = a;
	const char *name = b;

	return strcasecmp(menu->name, name);
}

bool cmd_menu_init(const struct menu_entry *cmd_table)
{
	struct cmd_menu *menu;

	if (main_cmd_table) {
		rl_printf("Main menu already registered\n");
		return false;
	}

	menu = g_malloc(sizeof(struct cmd_menu));
	if (!menu)
		return false;

	menu->name = "meshctl";
	menu->table = cmd_table;
	menu_list = g_list_append(menu_list, menu);
	main_cmd_table = (struct menu_entry *) cmd_table;
	current_cmd_table = (struct menu_entry *) main_cmd_table;

	return true;
}

void cmd_menu_main(bool forced)
{
	current_cmd_table = main_cmd_table;

	if (!forced) {
		rl_set_prompt(main_menu_prompt);
		rl_replace_line("", 0);
		rl_point = main_menu_point;
		rl_redisplay();
	}

	g_free(main_menu_prompt);
	main_menu_prompt = NULL;
}

bool add_cmd_menu(const char *name, const struct menu_entry *cmd_table)
{
	struct cmd_menu *menu;
	GList *l;

	l = g_list_find_custom(menu_list, name, match_menu_name);
	if (l) {
		menu = l->data;
		rl_printf("menu \"%s\" already registered\n", menu->name);
		return false;
	}

	menu = g_malloc(sizeof(struct cmd_menu));
	if (!menu)
		return false;

	menu->name = name;
	menu->table = cmd_table;
	menu_list = g_list_append(menu_list, menu);

	return true;
}

void set_menu_prompt(const char *name, const char *id)
{
	char *prompt;

	prompt = g_strdup_printf(COLOR_BLUE "[%s%s%s]" COLOR_OFF "# ", name,
					id ? ": Target = " : "", id ? id : "");
	rl_set_prompt(prompt);
	g_free(prompt);
	rl_on_new_line();
}

bool switch_cmd_menu(const char *name)
{
	GList *l;
	struct cmd_menu *menu;

	l = g_list_find_custom(menu_list, name, match_menu_name);
	if(!l)
		return false;

	menu = l->data;
	current_cmd_table = (struct menu_entry *) menu->table;

	main_menu_point = rl_point;
	main_menu_prompt = g_strdup(rl_prompt);

	return true;
}

void process_menu_cmd(const char *cmd, const char *arg)
{
	int i;
	int len;
	struct menu_entry *cmd_table = current_cmd_table;

	if (!current_cmd_table)
		return;

	len = strlen(cmd);

	for (i = 0; cmd_table[i].cmd; i++) {
		if (strncmp(cmd, cmd_table[i].cmd, len))
			continue;

		if (cmd_table[i].func) {
			cmd_table[i].func(arg);
			return;
		}
	}

	if (strncmp(cmd, "help", len)) {
		rl_printf("Invalid command\n");
		return;
	}

	print_cmd_menu(cmd_table);
}

void print_cmd_menu(const struct menu_entry *cmd_table)
{
	int i;

	rl_printf("Available commands:\n");

	for (i = 0; cmd_table[i].cmd; i++) {
		if (cmd_table[i].desc)
			rl_printf("  %s %-*s %s\n", cmd_table[i].cmd,
					(int)(40 - strlen(cmd_table[i].cmd)),
					cmd_table[i].arg ? : "",
					cmd_table[i].desc ? : "");
	}

}

void cmd_menu_cleanup(void)
{
	main_cmd_table = NULL;
	current_cmd_table = NULL;

	g_list_free_full(menu_list, g_free);
}

void print_byte_array(const char *prefix, const void *ptr, int len)
{
	const uint8_t *data = ptr;
	char *line, *bytes;
	int i;

	line = g_malloc(strlen(prefix) + (16 * 3) + 2);
	sprintf(line, "%s ", prefix);
	bytes = line + strlen(prefix) + 1;

	for (i = 0; i < len; ++i) {
		sprintf(bytes, "%2.2x ", data[i]);
		if ((i + 1) % 16) {
			bytes += 3;
		} else {
			rl_printf("\r%s\n", line);
			bytes = line + strlen(prefix) + 1;
		}
	}

	if (i % 16)
		rl_printf("\r%s\n", line);

	g_free(line);
}

bool str2hex(const char *str, uint16_t in_len, uint8_t *out,
		uint16_t out_len)
{
	uint16_t i;

	if (in_len < out_len * 2)
		return false;

	for (i = 0; i < out_len; i++) {
		if (sscanf(&str[i * 2], "%02hhx", &out[i]) != 1)
			return false;
	}

	return true;
}

size_t hex2str(uint8_t *in, size_t in_len, char *out,
		size_t out_len)
{
	static const char hexdigits[] = "0123456789abcdef";
	size_t i;

	if(in_len * 2 > out_len - 1)
		return 0;

	for (i = 0; i < in_len; i++) {
		out[i * 2] = hexdigits[in[i] >> 4];
		out[i * 2 + 1] = hexdigits[in[i] & 0xf];
	}

	out[in_len * 2] = '\0';
	return i;
}

uint16_t mesh_opcode_set(uint32_t opcode, uint8_t *buf)
{
	if (opcode <= 0x7e) {
		buf[0] = opcode;
		return 1;
	} else if (opcode >= 0x8000 && opcode <= 0xbfff) {
		put_be16(opcode, buf);
		return 2;
	} else if (opcode >= 0xc00000 && opcode <= 0xffffff) {
		buf[0] = (opcode >> 16) & 0xff;
		put_be16(opcode, buf + 1);
		return 3;
	} else {
		rl_printf("Illegal Opcode %x", opcode);
		return 0;
	}
}

bool mesh_opcode_get(const uint8_t *buf, uint16_t sz, uint32_t *opcode, int *n)
{
	if (!n || !opcode || sz < 1) return false;

	switch (buf[0] & 0xc0) {
	case 0x00:
	case 0x40:
		/* RFU */
		if (buf[0] == 0x7f)
			return false;

		*n = 1;
		*opcode = buf[0];
		break;

	case 0x80:
		if (sz < 2)
			return false;

		*n = 2;
		*opcode = get_be16(buf);
		break;

	case 0xc0:
		if (sz < 3)
			return false;

		*n = 3;
		*opcode = get_be16(buf + 1);
		*opcode |= buf[0] << 16;
		break;

	default:
		rl_printf("Bad Packet:\n");
		print_byte_array("\t", (void *) buf, sz);
		return false;
	}

	return true;
}

const char *mesh_status_str(uint8_t status)
{
	switch (status) {
	case MESH_STATUS_SUCCESS: return "Success";
	case MESH_STATUS_INVALID_ADDRESS: return "Invalid Address";
	case MESH_STATUS_INVALID_MODEL: return "Invalid Model";
	case MESH_STATUS_INVALID_APPKEY: return "Invalid AppKey";
	case MESH_STATUS_INVALID_NETKEY: return "Invalid NetKey";
	case MESH_STATUS_INSUFF_RESOURCES: return "Insufficient Resources";
	case MESH_STATUS_IDX_ALREADY_STORED: return "Key Idx Already Stored";
	case MESH_STATUS_INVALID_PUB_PARAM: return "Invalid Publish Parameters";
	case MESH_STATUS_NOT_SUB_MOD: return "Not a Subscribe Model";
	case MESH_STATUS_STORAGE_FAIL: return "Storage Failure";
	case MESH_STATUS_FEAT_NOT_SUP: return "Feature Not Supported";
	case MESH_STATUS_CANNOT_UPDATE: return "Cannot Update";
	case MESH_STATUS_CANNOT_REMOVE: return "Cannot Remove";
	case MESH_STATUS_CANNOT_BIND: return "Cannot bind";
	case MESH_STATUS_UNABLE_CHANGE_STATE: return "Unable to change state";
	case MESH_STATUS_CANNOT_SET: return "Cannot set";
	case MESH_STATUS_UNSPECIFIED_ERROR: return "Unspecified error";
	case MESH_STATUS_INVALID_BINDING: return "Invalid Binding";

	default: return "Unknown";
	}
}

void print_model_pub(uint16_t ele_addr, uint32_t mod_id,
						struct mesh_publication *pub)
{
	rl_printf("\tElement: %4.4x\n", ele_addr);
	rl_printf("\tPub Addr: %4.4x", pub->u.addr16);
	if (mod_id > 0xffff0000)
		rl_printf("\tModel: %8.8x \n", mod_id);
	else
		rl_printf("\tModel: %4.4x \n", (uint16_t) (mod_id & 0xffff));
	rl_printf("\tApp Key Idx: %4.4x", pub->app_idx);
	rl_printf("\tTTL: %2.2x", pub->ttl);
}

void swap_u256_bytes(uint8_t *u256)
{
	int i;

	/* End-to-End byte reflection of 32 octet buffer */
	for (i = 0; i < 16; i++) {
		u256[i] ^= u256[31 - i];
		u256[31 - i] ^= u256[i];
		u256[i] ^= u256[31 - i];
	}
}

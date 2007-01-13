/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2005-2006  Johan Hedberg <johan.hedberg@nokia.com>
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"
#include "dbus-error.h"
#include "dbus-hci.h"
#include "dbus-manager.h"
#include "dbus-adapter.h"
#include "dbus-service.h"
#include "dbus-security.h"
#include "dbus-test.h"
#include "dbus-rfcomm.h"
#include "dbus-sdp.h"
#include "dbus-common.h"

#define BLUEZ_NAME "org.bluez"

#define MAX_CONN_NUMBER		10
#define RECONNECT_RETRY_TIMEOUT	5000

static DBusConnection *conn = NULL;

static sdp_session_t *sess = NULL;

static int experimental = 0;

service_handler_func_t find_service_handler(struct service_data *handlers, DBusMessage *msg)
{
	struct service_data *current;
	const char *name;

	name = dbus_message_get_member(msg);

	for (current = handlers; current->name != NULL; current++) {
		if (!strcmp(current->name, name))
			return current->handler_func;
	}

	return NULL;
}

int str2uuid(uuid_t *uuid, const char *string)
{
	uint16_t svclass, data1, data2, data3, data5;
	uint32_t data0, data4;

	svclass = sdp_str2svclass(string);
	if (svclass) {
		sdp_uuid16_create(uuid, svclass);
		return 0;
	}

	if (strlen(string) == 36 &&
			string[8] == '-' &&
			string[13] == '-' &&
			string[18] == '-' &&
			string[23] == '-' &&
			sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
				&data0, &data1, &data2, &data3, &data4, &data5) == 6) {
		uint8_t val[16];

		data0 = htonl(data0);
		data1 = htons(data1);
		data2 = htons(data2);
		data3 = htons(data3);
		data4 = htonl(data4);
		data5 = htons(data5);

		memcpy(&val[0], &data0, 4);
		memcpy(&val[4], &data1, 2);
		memcpy(&val[6], &data2, 2);
		memcpy(&val[8], &data3, 2);
		memcpy(&val[10], &data4, 4);
		memcpy(&val[14], &data5, 2);

		sdp_uuid128_create(uuid, val);
		return 0;
	}

	return -1;
}

int l2raw_connect(const char *local, const bdaddr_t *remote)
{
	struct sockaddr_l2 addr;
	long arg;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (sk < 0) {
		error("Can't create socket: %s (%d)", strerror(errno), errno);
		return sk;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(local, &addr.l2_bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("Can't bind socket: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	arg = fcntl(sk, F_GETFL);
	if (arg < 0) {
		error("Can't get file flags: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	arg |= O_NONBLOCK;
	if (fcntl(sk, F_SETFL, arg) < 0) {
		error("Can't set file flags: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, remote);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (errno == EAGAIN || errno == EINPROGRESS)
			return sk;
		error("Can't connect socket: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	return sk;

failed:
	close(sk);
	return -1;
}

int check_address(const char *addr)
{
	char tmp[18];
	char *ptr = tmp;

	if (!addr)
		return -1;

	if (strlen(addr) != 17)
		return -1;

	memcpy(tmp, addr, 18);

	while (*ptr) {

		*ptr = toupper(*ptr);
		if (*ptr < '0'|| (*ptr > '9' && *ptr < 'A') || *ptr > 'F')
			return -1;

		ptr++;
		*ptr = toupper(*ptr);
		if (*ptr < '0'|| (*ptr > '9' && *ptr < 'A') || *ptr > 'F')
			return -1;

		ptr++;
		*ptr = toupper(*ptr);
		if (*ptr == 0)
			break;

		if (*ptr != ':')
			return -1;

		ptr++;
	}

	return 0;
}

DBusHandlerResult handle_method_call(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const char *iface, *name;
	
	iface = dbus_message_get_interface(msg);
	name = dbus_message_get_member(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, iface) &&
					!strcmp("Introspect", name))
		return simple_introspect(conn, msg, data);
	else if (!strcmp(ADAPTER_INTERFACE, iface))
		return handle_adapter_method(conn, msg, data);
	else if (!strcmp(SECURITY_INTERFACE, iface))
		return handle_security_method(conn, msg, data);
	else if (!strcmp(TEST_INTERFACE, iface))
		return handle_test_method(conn, msg, data);
	else if (!strcmp(RFCOMM_INTERFACE, iface))
		return handle_rfcomm_method(conn, msg, data);
	else
		return error_unknown_method(conn, msg);
}

void hcid_dbus_set_experimental(void)
{
	experimental = 1;
}

int hcid_dbus_use_experimental(void)
{
	return experimental;
}

static gboolean system_bus_reconnect(void *data)
{
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr;
	int sk, i;
	gboolean ret_val = TRUE;

	if (dbus_connection_get_is_connected(conn))
		return FALSE;

	if (hcid_dbus_init() < 0)
		return TRUE;

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		error("Can't open HCI socket: %s (%d)",
				strerror(errno), errno);
		return TRUE;
	}

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		error("Can't allocate memory");
		goto failed;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, (void *) dl) < 0) {
		info("Can't get device list: %s (%d)",
			strerror(errno), errno);
		goto failed;
	}

	/* reset the default device */
	set_default_adapter(-1);

	for (i = 0; i < dl->dev_num; i++, dr++)
		hcid_dbus_register_device(dr->dev_id);

	ret_val = FALSE;

failed:
	if (sk >= 0)
		close(sk);

	if (dl)
		free(dl);

	return ret_val;
}

static void disconnect_callback(void *user_data)
{
	set_dbus_connection(NULL);
	g_timeout_add(RECONNECT_RETRY_TIMEOUT, system_bus_reconnect,
			NULL);
}

static const DBusObjectPathVTable manager_vtable = {
	.message_function	= &handle_manager_method,
	.unregister_function	= NULL
};

void hcid_dbus_exit(void)
{
	char **children;
	DBusConnection *conn = get_dbus_connection();
	int i;

	if (!conn || !dbus_connection_get_is_connected(conn))
		return;

	release_default_agent();
	release_default_auth_agent();
	release_service_agents(conn);

	/* Unregister all paths in Adapter path hierarchy */
	if (!dbus_connection_list_registered(conn, BASE_PATH, &children))
		goto done;

	for (i = 0; children[i]; i++) {
		char dev_path[MAX_PATH_LENGTH];

		snprintf(dev_path, sizeof(dev_path), "%s/%s", BASE_PATH,
				children[i]);

		unregister_adapter_path(dev_path);
	}

	dbus_free_string_array(children);

done:
	unregister_adapter_path(BASE_PATH);

	dbus_connection_unref(conn);
	set_dbus_connection(NULL);
}

int hcid_dbus_init(void)
{
	DBusConnection *conn;

	conn = init_dbus(BLUEZ_NAME, disconnect_callback, NULL);
	if (!conn)
		return -1;

	if (!dbus_connection_register_fallback(conn, BASE_PATH,
						&manager_vtable, NULL)) {
		error("D-Bus failed to register %s fallback", BASE_PATH);
		return -1;
	}

	set_dbus_connection(conn);

	dbus_connection_unref(conn);

	return 0;
}

int register_sdp_record(uint8_t *data, uint32_t size, uint32_t *handle)
{
	if (!sess) {
		sess = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
		if (!sess) {
			error("Can't connect to SDP daemon:(%s, %d)",
						strerror(errno), errno);
			return -1;
		}
	}

	return sdp_device_record_register_binary(sess, BDADDR_ANY,
						data, size, 0, handle);
}

int unregister_sdp_record(uint32_t handle)
{
	if (!sess)
		return -ENOENT;

	return sdp_device_record_unregister_binary(sess, BDADDR_ANY, handle);
}

void cleanup_sdp_session(void)
{
	if (sess)
		sdp_close(sess);

	sess = NULL;
}

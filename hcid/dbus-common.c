/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2005-2007  Johan Hedberg <johan.hedberg@nokia.com>
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

#include <glib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"
#include "dbus-helper.h"
#include "dbus-error.h"
#include "manager.h"
#include "adapter.h"
#include "device.h"
#include "dbus-hci.h"
#include "dbus-service.h"
#include "dbus-database.h"
#include "dbus-security.h"
#include "dbus-test.h"
#include "dbus-sdp.h"
#include "dbus-common.h"

#define BLUEZ_NAME "org.bluez"

#define MAX_CONN_NUMBER		10
#define RECONNECT_RETRY_TIMEOUT	5000

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
	uint8_t val[16];

	svclass = sdp_str2svclass(string);
	if (svclass) {
		sdp_uuid16_create(uuid, svclass);
		return 0;
	}

	if (strlen(string) != 36)
		return -1;

	if (string[8] != '-' || string[13] != '-' ||
				string[18] != '-' || string[23] != '-')
		return -1;

	if (sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
			&data0, &data1, &data2, &data3, &data4, &data5) != 6)
		return -1;

	/* Base UUID is 00001203-0000-1000-8000-00805F9B34FB */
	if (data1 == 0x0000 && data2 == 0x1000 && data3 == 0x8000 &&
				data4 == 0x00805F9B && data5 == 0x34FB) {
		if ((data0 & 0xffff0000) > 0)
			sdp_uuid32_create(uuid, data0);
		else
			sdp_uuid16_create(uuid, data0);
		return 0;
	}

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

int find_conn(int s, int dev_id, long arg)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int i;

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	cl->dev_id = dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(s, HCIGETCONNLIST, cl)) {
		error("Can't get connection list");
		goto failed;
	}

	for (i = 0; i < cl->conn_num; i++, ci++) {
		if (bacmp((bdaddr_t *) arg, &ci->bdaddr))
			continue;
		g_free(cl);
		return 1;
	}

failed:
	g_free(cl);
	return 0;
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
	DBusConnection *conn = get_dbus_connection();
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr;
	int sk, i;
	gboolean ret_val = TRUE;

	if (conn) {
		if (dbus_connection_get_is_connected(conn))
			return FALSE;
	}

	if (hcid_dbus_init() < 0)
		return TRUE;

	init_services(CONFIGDIR);

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		error("Can't open HCI socket: %s (%d)",
				strerror(errno), errno);
		return TRUE;
	}

	dl = g_malloc0(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));

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

	g_free(dl);

	return ret_val;
}

static void disconnect_callback(void *user_data)
{
	set_dbus_connection(NULL);

	release_services(NULL);

	g_timeout_add(RECONNECT_RETRY_TIMEOUT,
				system_bus_reconnect, NULL);
}

void hcid_dbus_exit(void)
{
	char **children;
	DBusConnection *conn = get_dbus_connection();
	int i;

	if (!conn || !dbus_connection_get_is_connected(conn))
		return;

	release_default_agent();
	release_default_auth_agent();
	release_services(conn);

	device_cleanup();

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

	set_dbus_connection(NULL);

	dbus_connection_unref(conn);
}

int hcid_dbus_init(void)
{
	DBusConnection *conn;

	conn = init_dbus(BLUEZ_NAME, disconnect_callback, NULL);
	if (!conn)
		return -1;

	if (!dbus_connection_create_object_path(conn, BASE_PATH, NULL, NULL))
		return -1;

	if (!manager_init(conn, BASE_PATH))
		return -1;

	if (!database_init(conn, BASE_PATH))
		return -1;

	if (!security_init(conn, BASE_PATH))
		return -1;

	if (device_init(conn) == FALSE)
		return -1;

	set_dbus_connection(conn);

	return 0;
}

static inline sdp_session_t *get_sdp_session(void)
{
	if (!sess) {
		sess = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
		if (!sess) {
			error("Can't connect to SDP daemon:(%s, %d)",
						strerror(errno), errno);
		}
	}

	return sess;
}

void cleanup_sdp_session(void)
{
	if (sess)
		sdp_close(sess);

	sess = NULL;
}

int register_sdp_binary(uint8_t *data, uint32_t size, uint32_t *handle)
{
	int err;

	if (!get_sdp_session())
		return -1;

	err = sdp_device_record_register_binary(sess, BDADDR_ANY,
						data, size, 0, handle);
	if (err < 0)
		cleanup_sdp_session();

	return err;
}

int register_sdp_record(sdp_record_t *rec)
{
	int err;

	if (!get_sdp_session())
		return -1;

	err = sdp_device_record_register(sess, BDADDR_ANY, rec, 0);
	if (err < 0)
		cleanup_sdp_session();

	return err;
}

int update_sdp_record(uint32_t handle, sdp_record_t *rec)
{
	if (!get_sdp_session())
		return -1;

	/* Update on the server */
	rec->handle = handle;
	if (sdp_device_record_update(sess, BDADDR_ANY, rec)) {
		cleanup_sdp_session();
		error("Service Record update failed: %s(%d).\n",
						strerror(errno), errno);
		return -1;
	}

	return 0;
}

int unregister_sdp_record(uint32_t handle)
{
	int err;

	if (!sess)
		return -ENOENT;

	err = sdp_device_record_unregister_binary(sess, BDADDR_ANY, handle);
	if (err < 0)
		cleanup_sdp_session();

	return err;
}

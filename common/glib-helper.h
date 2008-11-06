/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

int set_nonblocking(int fd);

typedef void (*bt_io_callback_t) (GIOChannel *io, int err, const bdaddr_t *src,
		const bdaddr_t *dst, gpointer user_data);
typedef void (*bt_callback_t) (sdp_list_t *recs, int err, gpointer user_data);
typedef void (*bt_destroy_t) (gpointer user_data);
typedef void (*bt_hci_result_t) (uint8_t status, gpointer user_data);

int bt_discover_services(const bdaddr_t *src, const bdaddr_t *dst,
		bt_callback_t cb, void *user_data, bt_destroy_t destroy);

int bt_search_service(const bdaddr_t *src, const bdaddr_t *dst,
			uuid_t *uuid, bt_callback_t cb, void *user_data,
			bt_destroy_t destroy);
int bt_cancel_discovery(const bdaddr_t *src, const bdaddr_t *dst);

gchar *bt_uuid2string(uuid_t *uuid);
uint16_t bt_name2class(const char *string);
char *bt_name2string(const char *string);
int bt_string2uuid(uuid_t *uuid, const char *string);
gchar *bt_list2string(GSList *list);
GSList *bt_string2list(const gchar *str);

GIOChannel *bt_rfcomm_listen(const bdaddr_t *src, uint8_t channel,
			uint32_t flags, bt_io_callback_t cb, void *user_data);
GIOChannel *bt_rfcomm_listen_allocate(const bdaddr_t *src, uint8_t *channel,
			uint32_t flags, bt_io_callback_t cb, void *user_data);
int bt_rfcomm_connect(const bdaddr_t *src, const bdaddr_t *dst,
			uint8_t channel, bt_io_callback_t cb, void *user_data);

GIOChannel *bt_l2cap_listen(const bdaddr_t *src, uint16_t psm, uint16_t mtu,
			uint32_t flags, bt_io_callback_t cb, void *user_data);
int bt_l2cap_connect(const bdaddr_t *src, const bdaddr_t *dst,
			uint16_t psm, uint16_t mtu, bt_io_callback_t cb,
			void *user_data);
int bt_sco_connect(const bdaddr_t *src, const bdaddr_t *dst,
			bt_io_callback_t cb, void *user_data);
GIOChannel *bt_sco_listen(const bdaddr_t *src, uint16_t mtu,
				bt_io_callback_t cb, void *user_data);

int bt_acl_encrypt(const bdaddr_t *src, const bdaddr_t *dst,
			bt_hci_result_t cb, gpointer user_data);

/* Experiemental bt_io API */

typedef struct bt_io BtIO;

typedef enum {
	BT_IO_AUTO,
	BT_IO_L2CAP,
	BT_IO_RFCOMM,
	BT_IO_SCO,
} BtIOTransport;

typedef enum {
	BT_IO_SUCCESS,
	BT_IO_FAILED,
} BtIOError;

typedef void (*BtIOFunc) (BtIO *io, BtIOError err, GIOChannel *chan,
				gpointer user_data);

BtIO *bt_io_create(BtIOTransport type, gpointer user_data, GDestroyNotify notify);
BtIO *bt_io_ref(BtIO *io);
void bt_io_unref(BtIO *io);
gboolean bt_io_set_source(BtIO *io, const char *address);
const char *bt_io_get_source(BtIO *io);
gboolean bt_io_set_destination(BtIO *io, const char *address);
const char *bt_io_get_destination(BtIO *io);
gboolean bt_io_set_flags(BtIO *io, guint32 flags);
guint32 bt_io_get_flags(BtIO *io);
gboolean bt_io_set_channel(BtIO *io, guint8 channel);
guint8 bt_io_get_channel(BtIO *io);
gboolean bt_io_set_psm(BtIO *io, guint16 psm);
guint16 bt_io_get_psm(BtIO *io);
gboolean bt_io_set_mtu(BtIO *io, guint16 mtu);
guint16 bt_io_get_mtu(BtIO *io);
BtIOError bt_io_connect(BtIO *io, const char *uuid, BtIOFunc func);
BtIOError bt_io_listen(BtIO *io, const char *uuid, BtIOFunc func);
BtIOError bt_io_shutdown(BtIO *io);

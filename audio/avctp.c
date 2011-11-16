/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011  Texas Instruments, Inc.
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

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include <glib.h>

#include "adapter.h"
#include "../src/device.h"

#include "log.h"
#include "error.h"
#include "uinput.h"
#include "btio.h"
#include "manager.h"
#include "device.h"
#include "avctp.h"

#define QUIRK_NO_RELEASE 1 << 0

/* Message types */
#define AVCTP_COMMAND		0
#define AVCTP_RESPONSE		1

/* Packet types */
#define AVCTP_PACKET_SINGLE	0
#define AVCTP_PACKET_START	1
#define AVCTP_PACKET_CONTINUE	2
#define AVCTP_PACKET_END	3

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avctp_header {
	uint8_t ipid:1;
	uint8_t cr:1;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

struct avc_header {
	uint8_t code:4;
	uint8_t _hdr0:4;
	uint8_t subunit_id:3;
	uint8_t subunit_type:5;
	uint8_t opcode;
} __attribute__ ((packed));

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avctp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t cr:1;
	uint8_t ipid:1;
	uint16_t pid;
} __attribute__ ((packed));
#define AVCTP_HEADER_LENGTH 3

struct avc_header {
	uint8_t _hdr0:4;
	uint8_t code:4;
	uint8_t subunit_type:5;
	uint8_t subunit_id:3;
	uint8_t opcode;
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif

struct avctp_state_callback {
	avctp_state_cb cb;
	void *user_data;
	unsigned int id;
};

struct avctp_server {
	bdaddr_t src;
	GIOChannel *io;
	GSList *sessions;
};

struct avctp {
	struct avctp_server *server;
	bdaddr_t dst;

	avctp_state_t state;

	int uinput;

	GIOChannel *io;
	guint io_id;

	uint16_t mtu;

	uint8_t key_quirks[256];
};

struct avctp_pdu_handler {
	uint8_t opcode;
	avctp_pdu_cb cb;
	void *user_data;
	unsigned int id;
};

static struct {
	const char *name;
	uint8_t avc;
	uint16_t uinput;
} key_map[] = {
	{ "PLAY",		PLAY_OP,		KEY_PLAYCD },
	{ "STOP",		STAVC_OP_OP,		KEY_STOPCD },
	{ "PAUSE",		PAUSE_OP,		KEY_PAUSECD },
	{ "FORWARD",		FORWARD_OP,		KEY_NEXTSONG },
	{ "BACKWARD",		BACKWARD_OP,		KEY_PREVIOUSSONG },
	{ "REWIND",		REWIND_OP,		KEY_REWIND },
	{ "FAST FORWARD",	FAST_FORWARD_OP,	KEY_FASTFORWARD },
	{ NULL }
};

static GSList *callbacks = NULL;
static GSList *servers = NULL;
static GSList *handlers = NULL;

static void auth_cb(DBusError *derr, void *user_data);

static int send_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct uinput_event event;

	memset(&event, 0, sizeof(event));
	event.type	= type;
	event.code	= code;
	event.value	= value;

	return write(fd, &event, sizeof(event));
}

static void send_key(int fd, uint16_t key, int pressed)
{
	if (fd < 0)
		return;

	send_event(fd, EV_KEY, key, pressed);
	send_event(fd, EV_SYN, SYN_REPORT, 0);
}

static size_t handle_panel_passthrough(struct avctp *session,
					uint8_t transaction, uint8_t *code,
					uint8_t *subunit, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	const char *status;
	int pressed, i;

	if (*code != AVC_CTYPE_CONTROL || *subunit != AVC_SUBUNIT_PANEL) {
		*code = AVC_CTYPE_REJECTED;
		return 0;
	}

	if (operand_count == 0)
		goto done;

	if (operands[0] & 0x80) {
		status = "released";
		pressed = 0;
	} else {
		status = "pressed";
		pressed = 1;
	}

	for (i = 0; key_map[i].name != NULL; i++) {
		uint8_t key_quirks;

		if ((operands[0] & 0x7F) != key_map[i].avc)
			continue;

		DBG("AV/C: %s %s", key_map[i].name, status);

		key_quirks = session->key_quirks[key_map[i].avc];

		if (key_quirks & QUIRK_NO_RELEASE) {
			if (!pressed) {
				DBG("AV/C: Ignoring release");
				break;
			}

			DBG("AV/C: treating key press as press + release");
			send_key(session->uinput, key_map[i].uinput, 1);
			send_key(session->uinput, key_map[i].uinput, 0);
			break;
		}

		send_key(session->uinput, key_map[i].uinput, pressed);
		break;
	}

	if (key_map[i].name == NULL)
		DBG("AV/C: unknown button 0x%02X %s",
						operands[0] & 0x7F, status);

done:
	*code = AVC_CTYPE_ACCEPTED;
	return operand_count;
}

static size_t handle_unit_info(struct avctp *session,
					uint8_t transaction, uint8_t *code,
					uint8_t *subunit, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	if (*code != AVC_CTYPE_STATUS) {
		*code = AVC_CTYPE_REJECTED;
		return 0;
	}

	*code = AVC_CTYPE_STABLE;

	/* The first operand should be 0x07 for the UNITINFO response.
	 * Neither AVRCP (section 22.1, page 117) nor AVC Digital
	 * Interface Command Set (section 9.2.1, page 45) specs
	 * explain this value but both use it */
	if (operand_count >= 1)
		operands[0] = 0x07;
	if (operand_count >= 2)
		operands[1] = AVC_SUBUNIT_PANEL << 3;

	DBG("reply to AVC_OP_UNITINFO");

	return 0;
}

static size_t handle_subunit_info(struct avctp *session,
					uint8_t transaction, uint8_t *code,
					uint8_t *subunit, uint8_t *operands,
					size_t operand_count, void *user_data)
{
	if (*code != AVC_CTYPE_STATUS) {
		*code = AVC_CTYPE_REJECTED;
		return 0;
	}

	*code = AVC_CTYPE_STABLE;

	/* The first operand should be 0x07 for the UNITINFO response.
	 * Neither AVRCP (section 22.1, page 117) nor AVC Digital
	 * Interface Command Set (section 9.2.1, page 45) specs
	 * explain this value but both use it */
	if (operand_count >= 2)
		operands[1] = AVC_SUBUNIT_PANEL << 3;

	DBG("reply to AVC_OP_SUBUNITINFO");

	return 0;
}

static struct avctp_pdu_handler *find_handler(GSList *list, uint8_t opcode)
{
	for (; list; list = list->next) {
		struct avctp_pdu_handler *handler = list->data;

		if (handler->opcode == opcode)
			return handler;
	}

	return NULL;
}

static void avctp_disconnected(struct avctp *session)
{
	struct avctp_server *server = session->server;

	if (!session)
		return;

	if (session->io) {
		g_io_channel_shutdown(session->io, TRUE, NULL);
		g_io_channel_unref(session->io);
		session->io = NULL;
	}

	if (session->io_id) {
		g_source_remove(session->io_id);
		session->io_id = 0;

		if (session->state == AVCTP_STATE_CONNECTING) {
			struct audio_device *dev;

			dev = manager_get_device(&session->server->src,
							&session->dst, FALSE);
			audio_device_cancel_authorization(dev, auth_cb,
								session);
		}
	}

	if (session->uinput >= 0) {
		char address[18];

		ba2str(&session->dst, address);
		DBG("AVCTP: closing uinput for %s", address);

		ioctl(session->uinput, UI_DEV_DESTROY);
		close(session->uinput);
		session->uinput = -1;
	}

	server->sessions = g_slist_remove(server->sessions, session);
	g_free(session);
}

static void avctp_set_state(struct avctp *session, avctp_state_t new_state)
{
	GSList *l;
	struct audio_device *dev;
	avctp_state_t old_state = session->state;

	dev = manager_get_device(&session->server->src, &session->dst, FALSE);
	if (dev == NULL) {
		error("avdtp_set_state(): no matching audio device");
		return;
	}

	session->state = new_state;

	for (l = callbacks; l != NULL; l = l->next) {
		struct avctp_state_callback *cb = l->data;
		cb->cb(dev, old_state, new_state, cb->user_data);
	}

	switch (new_state) {
	case AVCTP_STATE_DISCONNECTED:
		DBG("AVCTP Disconnected");

		avctp_disconnected(session);

		if (old_state != AVCTP_STATE_CONNECTED)
			break;

		if (!audio_device_is_active(dev, NULL))
			audio_device_set_authorized(dev, FALSE);

		break;
	case AVCTP_STATE_CONNECTING:
		DBG("AVCTP Connecting");
		break;
	case AVCTP_STATE_CONNECTED:
		DBG("AVCTP Connected");
		break;
	default:
		error("Invalid AVCTP state %d", new_state);
		return;
	}
}

static gboolean session_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct avctp *session = data;
	uint8_t buf[1024], *operands, code, subunit;
	struct avctp_header *avctp;
	struct avc_header *avc;
	int ret, packet_size, operand_count, sock;
	struct avctp_pdu_handler *handler;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		goto failed;

	sock = g_io_channel_unix_get_fd(session->io);

	ret = read(sock, buf, sizeof(buf));
	if (ret <= 0)
		goto failed;

	DBG("Got %d bytes of data for AVCTP session %p", ret, session);

	if ((unsigned int) ret < sizeof(struct avctp_header)) {
		error("Too small AVCTP packet");
		goto failed;
	}

	avctp = (struct avctp_header *) buf;

	DBG("AVCTP transaction %u, packet type %u, C/R %u, IPID %u, "
			"PID 0x%04X",
			avctp->transaction, avctp->packet_type,
			avctp->cr, avctp->ipid, ntohs(avctp->pid));

	ret -= sizeof(struct avctp_header);
	if ((unsigned int) ret < sizeof(struct avc_header)) {
		error("Too small AVCTP packet");
		goto failed;
	}

	avc = (struct avc_header *) (buf + sizeof(struct avctp_header));

	ret -= sizeof(struct avc_header);

	operands = buf + sizeof(struct avctp_header) + sizeof(struct avc_header);
	operand_count = ret;

	DBG("AV/C %s 0x%01X, subunit_type 0x%02X, subunit_id 0x%01X, "
			"opcode 0x%02X, %d operands",
			avctp->cr ? "response" : "command",
			avc->code, avc->subunit_type, avc->subunit_id,
			avc->opcode, operand_count);

	if (avctp->cr == AVCTP_RESPONSE)
		return TRUE;

	packet_size = AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH;
	avctp->cr = AVCTP_RESPONSE;

	if (avctp->packet_type != AVCTP_PACKET_SINGLE) {
		avc->code = AVC_CTYPE_NOT_IMPLEMENTED;
		goto done;
	}

	if (avctp->pid != htons(AV_REMOTE_SVCLASS_ID)) {
		avctp->ipid = 1;
		avc->code = AVC_CTYPE_REJECTED;
		goto done;
	}

	handler = find_handler(handlers, avc->opcode);
	if (!handler) {
		DBG("handler not found for 0x%02x", avc->opcode);
		avc->code = AVC_CTYPE_REJECTED;
		goto done;
	}

	code = avc->code;
	subunit = avc->subunit_type;

	packet_size += handler->cb(session, avctp->transaction, &code,
					&subunit, operands, operand_count,
					handler->user_data);

	avc->code = code;
	avc->subunit_type = subunit;

done:
	ret = write(sock, buf, packet_size);
	if (ret != packet_size)
		goto failed;

	return TRUE;

failed:
	DBG("AVCTP session %p got disconnected", session);
	avctp_set_state(session, AVCTP_STATE_DISCONNECTED);
	return FALSE;
}

static int uinput_create(char *name)
{
	struct uinput_dev dev;
	int fd, err, i;

	fd = open("/dev/uinput", O_RDWR);
	if (fd < 0) {
		fd = open("/dev/input/uinput", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/misc/uinput", O_RDWR);
			if (fd < 0) {
				err = -errno;
				error("Can't open input device: %s (%d)",
							strerror(-err), -err);
				return err;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));
	if (name)
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE - 1);

	dev.id.bustype = BUS_BLUETOOTH;
	dev.id.vendor  = 0x0000;
	dev.id.product = 0x0000;
	dev.id.version = 0x0000;

	if (write(fd, &dev, sizeof(dev)) < 0) {
		err = -errno;
		error("Can't write device information: %s (%d)",
						strerror(-err), -err);
		close(fd);
		return err;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_REL);
	ioctl(fd, UI_SET_EVBIT, EV_REP);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);

	for (i = 0; key_map[i].name != NULL; i++)
		ioctl(fd, UI_SET_KEYBIT, key_map[i].uinput);

	if (ioctl(fd, UI_DEV_CREATE, NULL) < 0) {
		err = -errno;
		error("Can't create uinput device: %s (%d)",
						strerror(-err), -err);
		close(fd);
		return err;
	}

	return fd;
}

static void init_uinput(struct avctp *session)
{
	struct audio_device *dev;
	char address[18], name[248 + 1];

	dev = manager_get_device(&session->server->src, &session->dst, FALSE);

	device_get_name(dev->btd_dev, name, sizeof(name));
	if (g_str_equal(name, "Nokia CK-20W")) {
		session->key_quirks[FORWARD_OP] |= QUIRK_NO_RELEASE;
		session->key_quirks[BACKWARD_OP] |= QUIRK_NO_RELEASE;
		session->key_quirks[PLAY_OP] |= QUIRK_NO_RELEASE;
		session->key_quirks[PAUSE_OP] |= QUIRK_NO_RELEASE;
	}

	ba2str(&session->dst, address);

	session->uinput = uinput_create(address);
	if (session->uinput < 0)
		error("AVRCP: failed to init uinput for %s", address);
	else
		DBG("AVRCP: uinput initialized for %s", address);
}

static void avctp_connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	struct avctp *session = data;
	char address[18];
	uint16_t imtu;
	GError *gerr = NULL;

	if (err) {
		avctp_set_state(session, AVCTP_STATE_DISCONNECTED);
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, BT_IO_L2CAP, &gerr,
			BT_IO_OPT_DEST, &address,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_INVALID);
	if (gerr) {
		avctp_set_state(session, AVCTP_STATE_DISCONNECTED);
		error("%s", gerr->message);
		g_error_free(gerr);
		return;
	}

	DBG("AVCTP: connected to %s", address);

	if (!session->io)
		session->io = g_io_channel_ref(chan);

	init_uinput(session);

	avctp_set_state(session, AVCTP_STATE_CONNECTED);
	session->mtu = imtu;
	session->io_id = g_io_add_watch(chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) session_cb, session);
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct avctp *session = user_data;
	GError *err = NULL;

	if (session->io_id) {
		g_source_remove(session->io_id);
		session->io_id = 0;
	}

	if (derr && dbus_error_is_set(derr)) {
		error("Access denied: %s", derr->message);
		avctp_set_state(session, AVCTP_STATE_DISCONNECTED);
		return;
	}

	if (!bt_io_accept(session->io, avctp_connect_cb, session,
								NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		avctp_set_state(session, AVCTP_STATE_DISCONNECTED);
	}
}

static struct avctp_server *find_server(GSList *list, const bdaddr_t *src)
{
	for (; list; list = list->next) {
		struct avctp_server *server = list->data;

		if (bacmp(&server->src, src) == 0)
			return server;
	}

	return NULL;
}

static struct avctp *find_session(GSList *list, const bdaddr_t *dst)
{
	for (; list != NULL; list = g_slist_next(list)) {
		struct avctp *s = list->data;

		if (bacmp(dst, &s->dst))
			continue;

		return s;
	}

	return NULL;
}

static struct avctp *avctp_get_internal(const bdaddr_t *src,
							const bdaddr_t *dst)
{
	struct avctp_server *server;
	struct avctp *session;

	assert(src != NULL);
	assert(dst != NULL);

	server = find_server(servers, src);
	if (server == NULL)
		return NULL;

	session = find_session(server->sessions, dst);
	if (session)
		return session;

	session = g_new0(struct avctp, 1);

	session->server = server;
	bacpy(&session->dst, dst);
	session->state = AVCTP_STATE_DISCONNECTED;

	server->sessions = g_slist_append(server->sessions, session);

	return session;
}

static void avctp_confirm_cb(GIOChannel *chan, gpointer data)
{
	struct avctp *session;
	struct audio_device *dev;
	char address[18];
	bdaddr_t src, dst;
	GError *err = NULL;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	DBG("AVCTP: incoming connect from %s", address);

	session = avctp_get_internal(&src, &dst);
	if (!session)
		goto drop;

	dev = manager_get_device(&src, &dst, FALSE);
	if (!dev) {
		dev = manager_get_device(&src, &dst, TRUE);
		if (!dev) {
			error("Unable to get audio device object for %s",
					address);
			goto drop;
		}
	}

	if (dev->control == NULL) {
		btd_device_add_uuid(dev->btd_dev, AVRCP_REMOTE_UUID);
		if (dev->control == NULL)
			goto drop;
	}

	if (session->io) {
		error("Refusing unexpected connect from %s", address);
		goto drop;
	}

	avctp_set_state(session, AVCTP_STATE_CONNECTING);
	session->io = g_io_channel_ref(chan);

	if (audio_device_request_authorization(dev, AVRCP_TARGET_UUID,
						auth_cb, session) < 0)
		goto drop;

	session->io_id = g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
							session_cb, session);
	return;

drop:
	if (!session || !session->io)
		g_io_channel_shutdown(chan, TRUE, NULL);
	if (session)
		avctp_set_state(session, AVCTP_STATE_DISCONNECTED);
}

static GIOChannel *avctp_server_socket(const bdaddr_t *src, gboolean master)
{
	GError *err = NULL;
	GIOChannel *io;

	io = bt_io_listen(BT_IO_L2CAP, NULL, avctp_confirm_cb, NULL,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_PSM, AVCTP_PSM,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_MASTER, master,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
	}

	return io;
}

static unsigned int passthrough_id = 0;
static unsigned int unit_id = 0;
static unsigned int subunit_id = 0;

int avctp_register(const bdaddr_t *src, gboolean master)
{
	struct avctp_server *server;

	server = g_new0(struct avctp_server, 1);
	if (!server)
		return -ENOMEM;

	server->io = avctp_server_socket(src, master);
	if (!server->io) {
		g_free(server);
		return -1;
	}

	bacpy(&server->src, src);

	servers = g_slist_append(servers, server);

	if (!passthrough_id)
		passthrough_id = avctp_register_pdu_handler(AVC_OP_PASSTHROUGH,
					handle_panel_passthrough, NULL);

	if (!unit_id)
		unit_id = avctp_register_pdu_handler(AVC_OP_UNITINFO, handle_unit_info,
									NULL);

	if (!subunit_id)
		subunit_id = avctp_register_pdu_handler(AVC_OP_SUBUNITINFO,
						handle_subunit_info, NULL);

	return 0;
}

void avctp_unregister(const bdaddr_t *src)
{
	struct avctp_server *server;

	server = find_server(servers, src);
	if (!server)
		return;

	while (server->sessions)
		avctp_disconnected(server->sessions->data);

	servers = g_slist_remove(servers, server);

	g_io_channel_shutdown(server->io, TRUE, NULL);
	g_io_channel_unref(server->io);
	g_free(server);

	if (servers)
		return;

	if (passthrough_id) {
		avctp_unregister_pdu_handler(passthrough_id);
		passthrough_id = 0;
	}

	if (unit_id) {
		avctp_unregister_pdu_handler(unit_id);
		passthrough_id = 0;
	}

	if (subunit_id) {
		avctp_unregister_pdu_handler(subunit_id);
		subunit_id = 0;
	}
}

int avctp_send_passthrough(struct avctp *session, uint8_t op)
{
	unsigned char buf[AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH + 2];
	struct avctp_header *avctp = (void *) buf;
	struct avc_header *avc = (void *) &buf[AVCTP_HEADER_LENGTH];
	uint8_t *operands = &buf[AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH];
	int sk;
	static uint8_t transaction = 0;

	if (session->state != AVCTP_STATE_CONNECTED)
		return -ENOTCONN;

	memset(buf, 0, sizeof(buf));

	avctp->transaction = transaction++;
	avctp->packet_type = AVCTP_PACKET_SINGLE;
	avctp->cr = AVCTP_COMMAND;
	avctp->pid = htons(AV_REMOTE_SVCLASS_ID);

	avc->code = AVC_CTYPE_CONTROL;
	avc->subunit_type = AVC_SUBUNIT_PANEL;
	avc->opcode = AVC_OP_PASSTHROUGH;

	operands[0] = op & 0x7f;
	operands[1] = 0;

	sk = g_io_channel_unix_get_fd(session->io);

	if (write(sk, buf, sizeof(buf)) < 0)
		return -errno;

	/* Button release */
	avctp->transaction = transaction++;
	operands[0] |= 0x80;

	if (write(sk, buf, sizeof(buf)) < 0)
		return -errno;

	return 0;
}

int avctp_send_vendordep(struct avctp *session, uint8_t transaction,
				uint8_t code, uint8_t subunit,
				uint8_t *operands, size_t operand_count)
{
	uint8_t *buf;
	struct avctp_header *avctp;
	struct avc_header *avc;
	uint8_t *pdu;
	int sk, err = 0;
	uint16_t size;

	if (session->state != AVCTP_STATE_CONNECTED)
		return -ENOTCONN;

	sk = g_io_channel_unix_get_fd(session->io);
	size = AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH + operand_count;
	buf = g_malloc0(size);

	avctp = (void *) buf;
	avc = (void *) &buf[AVCTP_HEADER_LENGTH];
	pdu = (void *) &buf[AVCTP_HEADER_LENGTH + AVC_HEADER_LENGTH];

	avctp->transaction = transaction;
	avctp->packet_type = AVCTP_PACKET_SINGLE;
	avctp->cr = AVCTP_RESPONSE;
	avctp->pid = htons(AV_REMOTE_SVCLASS_ID);

	avc->code = code;
	avc->subunit_type = subunit;
	avc->opcode = AVC_OP_VENDORDEP;

	memcpy(pdu, operands, operand_count);

	if (write(sk, buf, size) < 0)
		err = -errno;

	g_free(buf);
	return err;
}

unsigned int avctp_add_state_cb(avctp_state_cb cb, void *user_data)
{
	struct avctp_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct avctp_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	callbacks = g_slist_append(callbacks, state_cb);

	return state_cb->id;
}

gboolean avctp_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = callbacks; l != NULL; l = l->next) {
		struct avctp_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			callbacks = g_slist_remove(callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}

unsigned int avctp_register_pdu_handler(uint8_t opcode, avctp_pdu_cb cb,
							void *user_data)
{
	struct avctp_pdu_handler *handler;
	static unsigned int id = 0;

	handler = find_handler(handlers, opcode);
	if (handler)
		return 0;

	handler = g_new(struct avctp_pdu_handler, 1);
	handler->opcode = opcode;
	handler->cb = cb;
	handler->user_data = user_data;
	handler->id = ++id;

	handlers = g_slist_append(handlers, handler);

	return handler->id;
}

gboolean avctp_unregister_pdu_handler(unsigned int id)
{
	GSList *l;

	for (l = handlers; l != NULL; l = l->next) {
		struct avctp_pdu_handler *handler = l->data;

		if (handler->id == id) {
			handlers = g_slist_remove(handlers, handler);
			g_free(handler);
			return TRUE;
		}
	}

	return FALSE;
}

struct avctp *avctp_connect(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct avctp *session;
	GError *err = NULL;
	GIOChannel *io;

	session = avctp_get_internal(src, dst);
	if (!session)
		return NULL;

	if (session->state > AVCTP_STATE_DISCONNECTED)
		return session;

	avctp_set_state(session, AVCTP_STATE_CONNECTING);

	io = bt_io_connect(BT_IO_L2CAP, avctp_connect_cb, session, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &session->server->src,
				BT_IO_OPT_DEST_BDADDR, &session->dst,
				BT_IO_OPT_PSM, AVCTP_PSM,
				BT_IO_OPT_INVALID);
	if (err) {
		avctp_set_state(session, AVCTP_STATE_DISCONNECTED);
		error("%s", err->message);
		g_error_free(err);
		return NULL;
	}

	session->io = io;

	return session;
}

void avctp_disconnect(struct avctp *session)
{
	if (!session->io)
		return;

	avctp_set_state(session, AVCTP_STATE_DISCONNECTED);
}

struct avctp *avctp_get(const bdaddr_t *src, const bdaddr_t *dst)
{
	return avctp_get_internal(src, dst);
}

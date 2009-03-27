/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <bluetooth/sdp_lib.h>
#include <bluetooth/l2cap.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "uinput.h"
#include "adapter.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "control.h"
#include "sdpd.h"
#include "glib-helper.h"
#include "btio.h"
#include "dbus-common.h"

#define AVCTP_PSM 23

/* Message types */
#define AVCTP_COMMAND		0
#define AVCTP_RESPONSE		1

/* Packet types */
#define AVCTP_PACKET_SINGLE	0
#define AVCTP_PACKET_START	1
#define AVCTP_PACKET_CONTINUE	2
#define AVCTP_PACKET_END	3

/* ctype entries */
#define CTYPE_CONTROL		0x0
#define CTYPE_STATUS		0x1
#define CTYPE_NOT_IMPLEMENTED	0x8
#define CTYPE_ACCEPTED		0x9
#define CTYPE_REJECTED		0xA
#define CTYPE_STABLE		0xC

/* opcodes */
#define OP_UNITINFO		0x30
#define OP_SUBUNITINFO		0x31
#define OP_PASSTHROUGH		0x7c

/* subunits of interest */
#define SUBUNIT_PANEL		0x09

/* operands in passthrough commands */
#define VOLUP_OP		0x41
#define VOLDOWN_OP		0x42
#define MUTE_OP			0x43

#define PLAY_OP			0x44
#define STOP_OP			0x45
#define PAUSE_OP		0x46
#define REWIND_OP		0x48
#define FAST_FORWARD_OP		0x49
#define NEXT_OP			0x4b
#define PREV_OP			0x4c

static DBusConnection *connection = NULL;

static GSList *servers = NULL;
static GSList *sessions = NULL;

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avctp_header {
	uint8_t ipid:1;
	uint8_t cr:1;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint16_t pid;
} __attribute__ ((packed));

struct avrcp_header {
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

struct avrcp_header {
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
	uint32_t tg_record_id;
	uint32_t ct_record_id;
};

struct avctp {
	struct audio_device *dev;

	avctp_state_t state;

	bdaddr_t src;
	bdaddr_t dst;

	int uinput;

	GIOChannel *io;
	guint io_id;

	uint16_t mtu;
};

struct control {
	struct avctp *session;
};

static GSList *avctp_callbacks = NULL;

static sdp_record_t *avrcp_ct_record()
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrct;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM, ver = 0x0100, feat = 0x000f;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrct, AV_REMOTE_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrct);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP CT", 0, 0);

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static sdp_record_t *avrcp_tg_record()
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrtg;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM, ver = 0x0100, feat = 0x000f;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrtg, AV_REMOTE_TARGET_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &avrtg);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto[1] = sdp_list_append(0, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP TG", 0, 0);

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static struct avctp *find_session(const bdaddr_t *src, const bdaddr_t *dst)
{
	GSList *l;

	for (l = sessions; l != NULL; l = g_slist_next(l)) {
		struct avctp *s = l->data;

		if (bacmp(src, &s->src) || bacmp(dst, &s->dst))
			continue;

		return s;
	}

	return NULL;
}

static struct avctp *avctp_get(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct avctp *session;

	assert(src != NULL);
	assert(dst != NULL);

	session = find_session(src, dst);
	if (session)
		return session;

	session = g_new0(struct avctp, 1);

	session->state = AVCTP_STATE_DISCONNECTED;
	session->uinput = -1;
	bacpy(&session->src, src);
	bacpy(&session->dst, dst);

	sessions = g_slist_append(sessions, session);

	return session;
}

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

static void handle_panel_passthrough(struct avctp *session,
					const unsigned char *operands,
					int operand_count)
{
	const char *status;
	int pressed;

	if (operand_count == 0)
		return;

	if (operands[0] & 0x80) {
		status = "released";
		pressed = 0;
	} else {
		status = "pressed";
		pressed = 1;
	}

	switch (operands[0] & 0x7F) {
	case PLAY_OP:
		debug("AVRCP: PLAY %s", status);
		send_key(session->uinput, KEY_PLAYPAUSE, pressed);
		break;
	case STOP_OP:
		debug("AVRCP: STOP %s", status);
		send_key(session->uinput, KEY_STOP, pressed);
		break;
	case PAUSE_OP:
		debug("AVRCP: PAUSE %s", status);
		send_key(session->uinput, KEY_PLAYPAUSE, pressed);
		break;
	case NEXT_OP:
		debug("AVRCP: NEXT %s", status);
		send_key(session->uinput, KEY_NEXTSONG, pressed);
		break;
	case PREV_OP:
		debug("AVRCP: PREV %s", status);
		send_key(session->uinput, KEY_PREVIOUSSONG, pressed);
		break;
	case REWIND_OP:
		debug("AVRCP: REWIND %s", status);
		send_key(session->uinput, KEY_REWIND, pressed);
		break;
	case FAST_FORWARD_OP:
		debug("AVRCP: FAST FORWARD %s", status);
		send_key(session->uinput, KEY_FORWARD, pressed);
		break;
	default:
		debug("AVRCP: unknown button 0x%02X %s", operands[0] & 0x7F, status);
		break;
	}
}

static void avctp_unref(struct avctp *session)
{
	sessions = g_slist_remove(sessions, session);

	if (session->state == AVCTP_STATE_CONNECTED) {
		gboolean value = FALSE;
		g_dbus_emit_signal(session->dev->conn, session->dev->path,
					AUDIO_CONTROL_INTERFACE,
					"Disconnected", DBUS_TYPE_INVALID);
		emit_property_changed(session->dev->conn, session->dev->path,
					AUDIO_CONTROL_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &value);
	}

	if (session->io) {
		g_io_channel_shutdown(session->io, TRUE, NULL);
		g_io_channel_unref(session->io);
	}

	if (session->io_id)
		g_source_remove(session->io_id);

	if (session->dev && session->dev->control)
		session->dev->control->session = NULL;

	if (session->uinput >= 0) {
		ioctl(session->uinput, UI_DEV_DESTROY);
		close(session->uinput);
	}

	g_free(session);
}

static gboolean session_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct avctp *session = data;
	unsigned char buf[1024], *operands;
	struct avctp_header *avctp;
	struct avrcp_header *avrcp;
	int ret, packet_size, operand_count, sock;

	if (!(cond | G_IO_IN))
		goto failed;

	sock = g_io_channel_unix_get_fd(session->io);

	ret = read(sock, buf, sizeof(buf));
	if (ret <= 0)
		goto failed;

	debug("Got %d bytes of data for AVCTP session %p", ret, session);

	if ((unsigned int) ret < sizeof(struct avctp_header)) {
		error("Too small AVCTP packet");
		goto failed;
	}

	packet_size = ret;

	avctp = (struct avctp_header *) buf;

	debug("AVCTP transaction %u, packet type %u, C/R %u, IPID %u, "
			"PID 0x%04X",
			avctp->transaction, avctp->packet_type,
			avctp->cr, avctp->ipid, ntohs(avctp->pid));

	ret -= sizeof(struct avctp_header);
	if ((unsigned int) ret < sizeof(struct avrcp_header)) {
		error("Too small AVRCP packet");
		goto failed;
	}

	avrcp = (struct avrcp_header *) (buf + sizeof(struct avctp_header));

	ret -= sizeof(struct avrcp_header);

	operands = buf + sizeof(struct avctp_header) + sizeof(struct avrcp_header);
	operand_count = ret;

	debug("AVRCP %s 0x%01X, subunit_type 0x%02X, subunit_id 0x%01X, "
			"opcode 0x%02X, %d operands",
			avctp->cr ? "response" : "command",
			avrcp->code, avrcp->subunit_type, avrcp->subunit_id,
			avrcp->opcode, operand_count);

	if (avctp->packet_type != AVCTP_PACKET_SINGLE) {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_NOT_IMPLEMENTED;
	} else if (avctp->pid != htons(AV_REMOTE_SVCLASS_ID)) {
		avctp->ipid = 1;
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_REJECTED;
	} else if (avctp->cr == AVCTP_COMMAND &&
			avrcp->code == CTYPE_CONTROL &&
			avrcp->subunit_type == SUBUNIT_PANEL &&
			avrcp->opcode == OP_PASSTHROUGH) {
		handle_panel_passthrough(session, operands, operand_count);
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_ACCEPTED;
	} else if (avctp->cr == AVCTP_COMMAND &&
			avrcp->code == CTYPE_STATUS &&
			(avrcp->opcode == OP_UNITINFO
			|| avrcp->opcode == OP_SUBUNITINFO)) {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_STABLE;
		debug("reply to %s", avrcp->opcode == OP_UNITINFO ?
				"OP_UNITINFO" : "OP_SUBUNITINFO");
	} else {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_REJECTED;
	}
	ret = write(sock, buf, packet_size);

	return TRUE;

failed:
	debug("AVCTP session %p got disconnected", session);
	avctp_unref(session);
	return FALSE;
}

static int uinput_create(char *name)
{
	struct uinput_dev dev;
	int fd, err;

	fd = open("/dev/uinput", O_RDWR);
	if (fd < 0) {
		fd = open("/dev/input/uinput", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/misc/uinput", O_RDWR);
			if (fd < 0) {
				err = errno;
				error("Can't open input device: %s (%d)",
							strerror(err), err);
				return -err;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));
	if (name)
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE);

	dev.id.bustype = BUS_BLUETOOTH;
	dev.id.vendor  = 0x0000;
	dev.id.product = 0x0000;
	dev.id.version = 0x0000;

	if (write(fd, &dev, sizeof(dev)) < 0) {
		err = errno;
		error("Can't write device information: %s (%d)",
						strerror(err), err);
		close(fd);
		errno = err;
		return -err;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_REL);
	ioctl(fd, UI_SET_EVBIT, EV_REP);
	ioctl(fd, UI_SET_EVBIT, EV_SYN);

	ioctl(fd, UI_SET_KEYBIT, KEY_PLAYPAUSE);
	ioctl(fd, UI_SET_KEYBIT, KEY_STOP);
	ioctl(fd, UI_SET_KEYBIT, KEY_NEXTSONG);
	ioctl(fd, UI_SET_KEYBIT, KEY_PREVIOUSSONG);
	ioctl(fd, UI_SET_KEYBIT, KEY_REWIND);
	ioctl(fd, UI_SET_KEYBIT, KEY_FORWARD);

	if (ioctl(fd, UI_DEV_CREATE, NULL) < 0) {
		err = errno;
		error("Can't create uinput device: %s (%d)",
						strerror(err), err);
		close(fd);
		errno = err;
		return -err;
	}

	return fd;
}

static void init_uinput(struct avctp *session)
{
	char address[18];

	ba2str(&session->dst, address);

	session->uinput = uinput_create(address);
	if (session->uinput < 0)
		error("AVRCP: failed to init uinput for %s", address);
	else
		debug("AVRCP: uinput initialized for %s", address);
}

static void avctp_set_state(struct avctp *session, avctp_state_t new_state)
{
	GSList *l;
	avdtp_session_state_t old_state = session->state;

	session->state = new_state;

	for (l = avctp_callbacks; l != NULL; l = l->next) {
		struct avctp_state_callback *cb = l->data;
		cb->cb(session->dev, old_state, new_state, cb->user_data);
	}
}

static void avctp_connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	struct control *control = data;
	struct avctp *session = control->session;
	char address[18];
	uint16_t imtu;
	GError *gerr = NULL;
	gboolean value;

	if (!session) {
		debug("avctp_connect_cb: session removed while connecting");
		if (!err)
			g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	if (err) {
		avctp_unref(session);
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, BT_IO_L2CAP, &gerr,
			BT_IO_OPT_DEST, &address,
			BT_IO_OPT_IMTU, &imtu,
			BT_IO_OPT_INVALID);
	if (gerr) {
		avctp_unref(session);
		error("%s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	debug("AVCTP: connected to %s", address);

	if (!session->io)
		session->io = g_io_channel_ref(chan);

	init_uinput(session);

	value = TRUE;
	g_dbus_emit_signal(session->dev->conn, session->dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_INVALID);
	emit_property_changed(session->dev->conn, session->dev->path,
				AUDIO_CONTROL_INTERFACE, "Connected",
				DBUS_TYPE_BOOLEAN, &value);

	avctp_set_state(session, AVCTP_STATE_CONNECTED);
	session->mtu = imtu;
	session->io_id = g_io_add_watch(chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) session_cb, session);
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct control *control = user_data;
	struct avctp *session = control->session;
	GError *err = NULL;

	if (derr && dbus_error_is_set(derr)) {
		error("Access denied: %s", derr->message);
		avctp_unref(session);
		return;
	}

	if (!bt_io_accept(session->io, avctp_connect_cb, control,
								NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		avctp_unref(session);
	}
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

	session = avctp_get(&src, &dst);

	if (!session) {
		error("Unable to create new AVCTP session");
		goto drop;
	}

	if (session->io) {
		error("Refusing unexpected connect from %s", address);
		goto drop;
	}

	dev = manager_get_device(&src, &dst);
	if (!dev) {
		error("Unable to get audio device object for %s", address);
		goto drop;
	}

	if (!dev->control)
		dev->control = control_init(dev);

	if (!dev->control->session)
		dev->control->session = session;

	if (!session->dev)
		session->dev = dev;

	avctp_set_state(session, AVCTP_STATE_CONNECTING);
	session->io = g_io_channel_ref(chan);

	if (avdtp_is_connected(&src, &dst)) {
		if (!bt_io_accept(chan, avctp_connect_cb, dev->control,
								NULL, NULL))
			goto drop;
	} else if (btd_request_authorization(&src, &dst,
				AVRCP_TARGET_UUID, auth_cb, dev->control) < 0)
		goto drop;

	return;

drop:
	if (!session->io)
		g_io_channel_shutdown(chan, TRUE, NULL);
	avctp_unref(session);
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

gboolean avrcp_connect(struct audio_device *dev)
{
	struct control *control = dev->control;
	struct avctp *session;
	GError *err = NULL;
	GIOChannel *io;

	if (control->session)
		return TRUE;

	session = avctp_get(&dev->src, &dev->dst);
	if (!session) {
		error("Unable to create new AVCTP session");
		return FALSE;
	}

	session->dev = dev;
	avctp_set_state(session, AVCTP_STATE_CONNECTING);

	io = bt_io_connect(BT_IO_L2CAP, avctp_connect_cb, control, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_PSM, AVCTP_PSM,
				BT_IO_OPT_INVALID);
	if (err) {
		avctp_unref(session);
		error("%s", err->message);
		g_error_free(err);
		return FALSE;
	}

	g_io_channel_unref(io);

	control->session = session;

	return TRUE;
}

void avrcp_disconnect(struct audio_device *dev)
{
	struct control *control = dev->control;
	struct avctp *session = control->session;

	if (!session)
		return;

	avctp_unref(session);
	control->session = NULL;
}

int avrcp_register(DBusConnection *conn, const bdaddr_t *src, GKeyFile *config)
{
	sdp_record_t *record;
	gboolean tmp, master = TRUE;
	GError *err = NULL;
	struct avctp_server *server;

	if (config) {
		tmp = g_key_file_get_boolean(config, "General",
							"Master", &err);
		if (err) {
			debug("audio.conf: %s", err->message);
			g_error_free(err);
		} else
			master = tmp;
	}

	server = g_new0(struct avctp_server, 1);
	if (!server)
		return -ENOMEM;

	if (!connection)
		connection = dbus_connection_ref(conn);

	record = avrcp_tg_record();
	if (!record) {
		error("Unable to allocate new service record");
		return -1;
	}

	if (add_record_to_server(src, record) < 0) {
		error("Unable to register AVRCP target service record");
		sdp_record_free(record);
		return -1;
	}
	server->tg_record_id = record->handle;

	record = avrcp_ct_record();
	if (!record) {
		error("Unable to allocate new service record");
		return -1;
	}

	if (add_record_to_server(src, record) < 0) {
		error("Unable to register AVRCP controller service record");
		sdp_record_free(record);
		return -1;
	}
	server->ct_record_id = record->handle;

	server->io = avctp_server_socket(src, master);
	if (!server->io) {
		remove_record_from_server(server->ct_record_id);
		remove_record_from_server(server->tg_record_id);
		g_free(server);
		return -1;
	}

	bacpy(&server->src, src);

	servers = g_slist_append(servers, server);

	return 0;
}

static struct avctp_server *find_server(GSList *list, const bdaddr_t *src)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct avctp_server *server = l->data;

		if (bacmp(&server->src, src) == 0)
			return server;
	}

	return NULL;
}

void avrcp_unregister(const bdaddr_t *src)
{
	struct avctp_server *server;

	server = find_server(servers, src);
	if (!server)
		return;

	servers = g_slist_remove(servers, server);

	remove_record_from_server(server->ct_record_id);
	remove_record_from_server(server->tg_record_id);

	g_io_channel_shutdown(server->io, TRUE, NULL);
	g_io_channel_unref(server->io);
	g_free(server);

	if (servers)
		return;

	dbus_connection_unref(connection);
	connection = NULL;
}

static DBusMessage *control_is_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct audio_device *device = data;
	struct control *control = device->control;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	connected = (control->session != NULL);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *control_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	gboolean value;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Connected */
	value = (device->control->session != NULL);
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &value);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable control_methods[] = {
	{ "IsConnected",	"",	"b",	control_is_connected,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "GetProperties",	"",	"a{sv}",control_get_properties },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable control_signals[] = {
	{ "Connected",			"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "Disconnected",		"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "PropertyChanged",		"sv"	},
	{ NULL, NULL }
};

static void control_free(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control->session)
		avctp_unref(control->session);

	g_free(control);
	dev->control = NULL;
}

static void path_unregister(void *data)
{
	struct audio_device *dev = data;

	debug("Unregistered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, dev->path);

	control_free(dev);
}

void control_unregister(struct audio_device *dev)
{
	g_dbus_unregister_interface(dev->conn, dev->path,
		AUDIO_CONTROL_INTERFACE);
}

struct control *control_init(struct audio_device *dev)
{
	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					control_methods, control_signals, NULL,
					dev, path_unregister))
		return NULL;

	debug("Registered interface %s on path %s",
		AUDIO_CONTROL_INTERFACE, dev->path);

	return g_new0(struct control, 1);
}

gboolean control_is_active(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control->session &&
			control->session->state != AVCTP_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

unsigned int avctp_add_state_cb(avctp_state_cb cb, void *user_data)
{
	struct avctp_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct avctp_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	avctp_callbacks = g_slist_append(avctp_callbacks, state_cb);

	return state_cb->id;
}

gboolean avctp_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = avctp_callbacks; l != NULL; l = l->next) {
		struct avctp_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			avctp_callbacks = g_slist_remove(avctp_callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}

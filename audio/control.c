/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#include "dbus-service.h"
#include "logging.h"
#include "uinput.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "control.h"
#include "sdpd.h"
#include "glib-helper.h"

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
#define CTYPE_ACCEPTED		0x9
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

static uint32_t tg_record_id = 0;
static uint32_t ct_record_id = 0;

static GIOChannel *avctp_server = NULL;

static GSList *sessions = NULL;

typedef enum {
	AVCTP_STATE_DISCONNECTED = 0,
	AVCTP_STATE_CONNECTING,
	AVCTP_STATE_CONNECTED
} avctp_state_t;

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

struct avctp {
	struct audio_device *dev;

	avctp_state_t state;

	bdaddr_t src;
	bdaddr_t dst;

	int uinput;

	int sock;

	guint io;

	uint16_t mtu;
};

struct control {
	struct avctp *session;
};

static sdp_record_t *avrcp_ct_record()
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrct;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVCTP_PSM, ver = 0x0103, feat = 0x000f;

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
	uint16_t lp = AVCTP_PSM, ver = 0x0103, feat = 0x000f;

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

	session->uinput = -1;
	session->sock = -1;
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

	if (session->state == AVCTP_STATE_CONNECTED)
		g_dbus_emit_signal(session->dev->conn,
						session->dev->path,
						AUDIO_CONTROL_INTERFACE,
						"Disconnected",
						DBUS_TYPE_INVALID);
	if (session->sock >= 0)
		close(session->sock);
	if (session->io)
		g_source_remove(session->io);

	if (session->dev)
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
	int ret, packet_size, operand_count;

	if (!(cond | G_IO_IN))
		goto failed;

	ret = read(session->sock, buf, sizeof(buf));
	if (ret <= 0)
		goto failed;

	debug("Got %d bytes of data for AVCTP session %p", ret, session);

	if (ret < sizeof(struct avctp_header)) {
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
	if (ret < sizeof(struct avrcp_header)) {
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

	if (avctp->packet_type == AVCTP_PACKET_SINGLE &&
			avctp->cr == AVCTP_COMMAND &&
			avctp->pid == htons(AV_REMOTE_SVCLASS_ID) &&
			avrcp->code == CTYPE_CONTROL &&
			avrcp->subunit_type == SUBUNIT_PANEL &&
			avrcp->opcode == OP_PASSTHROUGH) {
		handle_panel_passthrough(session, operands, operand_count);
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_ACCEPTED;
		ret = write(session->sock, buf, packet_size);
	}

	if (avctp->packet_type == AVCTP_PACKET_SINGLE &&
			avctp->cr == AVCTP_COMMAND &&
			avctp->pid == htons(AV_REMOTE_SVCLASS_ID) &&
			avrcp->code == CTYPE_STATUS &&
			(avrcp->opcode == OP_UNITINFO
			|| avrcp->opcode == OP_SUBUNITINFO)) {
		avctp->cr = AVCTP_RESPONSE;
		avrcp->code = CTYPE_STABLE;
		debug("reply to %s", avrcp->opcode == OP_UNITINFO ?
				"OP_UNITINFO" : "OP_SUBUNITINFO");
		ret = write(session->sock, buf, packet_size);
	}

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
	char address[18], *name;

	ba2str(&session->dst, address);

	name = session->dev->name ? session->dev->name : address;

	session->uinput = uinput_create(name);
	if (session->uinput < 0)
		error("AVRCP: failed to init uinput for %s", name);
	else
		debug("AVRCP: uinput initialized for %s", name);
}

static void avctp_connect_session(struct avctp *session)
{
	GIOChannel *io;

	session->state = AVCTP_STATE_CONNECTED;
	session->dev = manager_device_connected(&session->dst,
						AVRCP_TARGET_UUID);
	session->dev->control->session = session;

	init_uinput(session);

	g_dbus_emit_signal(session->dev->conn, session->dev->path,
					AUDIO_CONTROL_INTERFACE, "Connected",
					DBUS_TYPE_INVALID);

	if (session->io)
		g_source_remove(session->io);

	io = g_io_channel_unix_new(session->sock);
	session->io = g_io_add_watch(io,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) session_cb, session);
	g_io_channel_unref(io);
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct avctp *session = user_data;

	if (derr && dbus_error_is_set(derr)) {
		error("Access denied: %s", derr->message);
		if (dbus_error_has_name(derr, DBUS_ERROR_NO_REPLY)) {
			debug("Canceling authorization request");
			service_cancel_auth(&session->src, &session->dst);
		}

		avctp_unref(session);
		return;
	}

	avctp_connect_session(session);
}

static void avctp_server_cb(GIOChannel *chan, int err, const bdaddr_t *src,
				const bdaddr_t *dst, gpointer data)
{
	socklen_t size;
	struct l2cap_options l2o;
	struct avctp *session;
	GIOCondition flags = G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	char address[18];

	if (err < 0) {
		error("AVCTP server socket: %s (%d)", strerror(-err), -err);
		return;
	}

	session = avctp_get(src, dst);

	if (!session) {
		error("Unable to create new AVCTP session");
		goto drop;
	}

	if (session->sock >= 0) {
		error("Refusing unexpected connect from %s", address);
		goto drop;
	}

	session->state = AVCTP_STATE_CONNECTING;
	session->sock = g_io_channel_unix_get_fd(chan);

	memset(&l2o, 0, sizeof(l2o));
	size = sizeof(l2o);
	if (getsockopt(session->sock, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &size) < 0) {
		err = errno;
		error("getsockopt(L2CAP_OPTIONS): %s (%d)", strerror(err),
				err);
		avctp_unref(session);
		goto drop;
	}

	session->mtu = l2o.imtu;

	session->io = g_io_add_watch(chan, flags, (GIOFunc) session_cb,
				session);
	g_io_channel_unref(chan);

	if (avdtp_is_connected(src, dst))
		goto proceed;

	if (service_req_auth(src, dst, AVRCP_TARGET_UUID, auth_cb, session) < 0)
		goto drop;

	return;

proceed:
	avctp_connect_session(session);

	return;

drop:
	close(session->sock);
}

static GIOChannel *avctp_server_socket(gboolean master)
{
	int lm;
	GIOChannel *io;

	lm = L2CAP_LM_SECURE;

	if (master)
		lm |= L2CAP_LM_MASTER;

	io = bt_l2cap_listen(BDADDR_ANY, AVCTP_PSM, 0, lm, avctp_server_cb,
				NULL);
	if (!io) {
		error("Unable to allocate new io channel");
		return NULL;
	}

	return io;
}

static void avctp_connect_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer data)
{
	struct avctp *session = data;
	struct l2cap_options l2o;
	socklen_t len;
	int sk;
	char address[18];

	if (err < 0) {
		avctp_unref(session);
		error("AVCTP connect(%s): %s (%d)", address, strerror(-err),
				-err);
		return;
	}

	ba2str(&session->dst, address);
	debug("AVCTP: connected to %s", address);

	g_io_channel_set_close_on_unref(chan, FALSE);
	sk = g_io_channel_unix_get_fd(chan);
	session->sock = sk;

	memset(&l2o, 0, sizeof(l2o));
	len = sizeof(l2o);
	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &len) < 0) {
		err = errno;
		avctp_unref(session);
		error("getsockopt(L2CAP_OPTIONS): %s (%d)", strerror(err),
				err);
		return;
	}

	init_uinput(session);

	g_dbus_emit_signal(session->dev->conn, session->dev->path,
					AUDIO_CONTROL_INTERFACE, "Connected",
					DBUS_TYPE_INVALID);

	session->state = AVCTP_STATE_CONNECTED;
	session->mtu = l2o.imtu;
	session->io = g_io_add_watch(chan,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) session_cb, session);
}

gboolean avrcp_connect(struct audio_device *dev)
{
	struct control *control = dev->control;
	struct avctp *session;
	int err;

	if (control->session)
		return TRUE;

	session = avctp_get(&dev->src, &dev->dst);
	if (!session) {
		error("Unable to create new AVCTP session");
		return FALSE;
	}

	session->dev = dev;
	session->state = AVCTP_STATE_CONNECTING;

	err = bt_l2cap_connect(&dev->src, &dev->dst, AVCTP_PSM, 0,
				avctp_connect_cb, session);
	if (err < 0) {
		avctp_unref(session);
		error("Connect failed. %s(%d)", strerror(-err), -err);
		return FALSE;
	}

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

int avrcp_init(DBusConnection *conn, GKeyFile *config)
{
	sdp_record_t *record;
	gboolean tmp, master = TRUE;
	GError *err = NULL;

	if (avctp_server)
		return 0;

	if (config) {
		tmp = g_key_file_get_boolean(config, "General",
							"Master", &err);
		if (err) {
			debug("audio.conf: %s", err->message);
			g_error_free(err);
		} else
			master = tmp;
	}

	connection = dbus_connection_ref(conn);

	record = avrcp_tg_record();
	if (!record) {
		error("Unable to allocate new service record");
		return -1;
	}

	if (add_record_to_server(BDADDR_ANY, record) < 0) {
		error("Unable to register AVRCP target service record");
		sdp_record_free(record);
		return -1;
	}
	tg_record_id = record->handle;

	record = avrcp_ct_record();
	if (!record) {
		error("Unable to allocate new service record");
		return -1;
	}

	if (add_record_to_server(BDADDR_ANY, record) < 0) {
		error("Unable to register AVRCP controller service record");
		sdp_record_free(record);
		return -1;
	}
	ct_record_id = record->handle;

	avctp_server = avctp_server_socket(master);
	if (!avctp_server)
		return -1;

	return 0;
}

void avrcp_exit(void)
{
	if (!avctp_server)
		return;

	g_io_channel_close(avctp_server);
	g_io_channel_unref(avctp_server);
	avctp_server = NULL;

	remove_record_from_server(ct_record_id);
	ct_record_id = 0;

	remove_record_from_server(tg_record_id);
	tg_record_id = 0;

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

static GDBusMethodTable control_methods[] = {
	{ "IsConnected",	"",	"b",	control_is_connected },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable control_signals[] = {
	{ "Connected",			""	},
	{ "Disconnected",		""	},
	{ NULL, NULL }
};

struct control *control_init(struct audio_device *dev)
{
	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_CONTROL_INTERFACE,
					control_methods, control_signals, NULL,
					dev, NULL))
		return NULL;

	return g_new0(struct control, 1);
}

void control_free(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control->session)
		avctp_unref(control->session);

	g_free(control);
	dev->control = NULL;
}

gboolean control_is_active(struct audio_device *dev)
{
	struct control *control = dev->control;

	if (control->session &&
			control->session->state != AVCTP_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

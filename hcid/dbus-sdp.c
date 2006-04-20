/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "hcid.h"
#include "textfile.h"

struct dbus_sdp_record {
	char *owner;		/* null for remote services or unique name if local */
	bdaddr_t provider;	/* remote Bluetooth address or local address */
	char *name;		/* service name */
	uint32_t identifier;
	uint16_t uuid;
	uint8_t channel;
};

/* list of remote and local service records */
static struct slist *sdp_records = NULL;

struct search_request_info *search_request_info_new(bdaddr_t *dba, DBusMessage *msg)
{
	struct search_request_info *search = malloc(sizeof(struct search_request_info));
	if (!search)
		return NULL;

	memset(search, 0, sizeof(*search));

	bacpy(&search->bdaddr, dba);
	search->rq = dbus_message_ref(msg);

	return search;
}
void search_request_info_free(struct search_request_info *search)
{
	if (search->rq)
		dbus_message_unref(search->rq);
	if (search->session)
		free(search->session);
	if (search->io)
		free(search->io);

	free(search);
}

void dbus_sdp_record_free(struct dbus_sdp_record *rec)
{
	if (rec->owner)
		free(rec->owner);
	if (rec->name)
		free(rec->name);

	free(rec);
}

static void id2str(uint32_t id, char *dst)
{
	snprintf(dst, 9, "%2.2X%2.2X%2.2X%2.2X", (id >> 24) & 0xFF,
			(id >> 16) & 0xFF, (id >> 8) & 0xFF, id & 0xFF);
	debug ("%s, identifier:%s", __PRETTY_FUNCTION__, dst);
}

static uint32_t str2id(const char *id)
{
	return atoi(id);
}


static uint32_t generate_new_id(const bdaddr_t *provider, uint8_t channel)
{
	/* FIXME: generate the pseudo random id */
	return 1;
}

struct dbus_sdp_record *dbus_sdp_record_new(const char *owner, bdaddr_t *provider,
						const char *name, uint32_t uuid, uint8_t channel)
{
	struct dbus_sdp_record *rec;

	/* FIXME: validate the arguments */

	rec = malloc(sizeof(struct dbus_sdp_record));
	if (!rec)
		return NULL;

	memset(rec, 0, sizeof(*rec));
	if (owner) {
		rec->owner = strdup(owner);
		if (!rec->owner)
			goto mem_fail;
	}

	bacpy(&rec->provider, provider);

	rec->name = strdup(name);
	if(!rec->name)
		goto mem_fail;
	
	rec->uuid = uuid;
	rec->channel = channel;
	rec->identifier = generate_new_id(provider, channel);

	return rec;

mem_fail:
	dbus_sdp_record_free(rec);
	return NULL;
}

static void owner_exited(const char *owner, struct hci_dbus_data *dbus_data)
{
	struct slist *cur, *next;

	debug("SDP provider owner %s exited", owner);

	for (cur = sdp_records; cur != NULL; cur = next) {
		struct dbus_sdp_record *rec = cur->data;

		next = cur->next;

		if(!rec->owner)
			continue;

		if (strcmp(rec->owner, owner))
			continue;

		sdp_records = slist_remove(sdp_records, rec);
		dbus_sdp_record_free(rec);
	}
}

static int record_cmp(const struct dbus_sdp_record *a, const struct dbus_sdp_record *b)
{
	int ret;
	
	if (b->owner) {
		if (!a->owner)
			return -1;
		ret = strcmp(a->owner, b->owner);
		if (ret)
			return ret;
	}

	if (bacmp(&b->provider, BDADDR_ANY)) {
		if (!bacmp(&a->provider, BDADDR_ANY))
			return -1;
		ret = bacmp(&a->provider, &b->provider);
		if (ret)
			return ret;
	}

	if (b->uuid) {
		ret = (a->uuid - b->uuid);
		if (ret)
			return ret;
	}

	if (b->channel) {
		ret = (a->channel - b->channel);
		if (ret)
			return ret;
	}

	return 0;
}

static gboolean sdp_client_connection_cb(GIOChannel *chan, GIOCondition cond, struct hci_dbus_data *dbus_data)
{
	debug("%s, line:%d condition:%d", __PRETTY_FUNCTION__, __LINE__, cond);
	/* FIXME: send the request */
	return FALSE;
}

int dbus_sdp_connect(struct hci_dbus_data *dbus_data, const bdaddr_t *sba,
			const bdaddr_t *dba, uint32_t flags, int *err)
{
	struct sockaddr_l2 sa;
	sdp_session_t *session = malloc(sizeof(sdp_session_t));
	if (!session) {
		if (err)
			*err = ENOMEM;
		return -1;
	}

	memset(session, 0, sizeof(*session));
	session->flags = flags;

	// create L2CAP connection
	session->sock = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	session->local = 0;
	if (session->sock >= 0) {
		sa.l2_family = AF_BLUETOOTH;
		sa.l2_psm = 0;
		if (bacmp(sba, BDADDR_ANY) != 0) {
			sa.l2_bdaddr = *sba;
			if (bind(session->sock, (struct sockaddr *) &sa, sizeof(sa)) < 0)
				goto fail;
		}
		if (flags & SDP_WAIT_ON_CLOSE) {
			struct linger l = { .l_onoff = 1, .l_linger = 1 };
			setsockopt(session->sock, SOL_SOCKET, SO_LINGER, &l, sizeof(l));
		}
		sa.l2_psm = htobs(SDP_PSM);
		sa.l2_bdaddr = *dba;

		debug("%s, line:%d connecting ...", __PRETTY_FUNCTION__, __LINE__);

		dbus_data->search->io = g_io_channel_unix_new(session->sock);

		fcntl(session->sock, F_SETFL, fcntl(session->sock, F_GETFL, 0)|O_NONBLOCK);
		if (connect(session->sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
			if ( !(errno == EAGAIN || errno == EINPROGRESS)) {
				error("connect() failed:%s (%d)", strerror(errno), errno);
				goto fail;
			}
			g_io_add_watch(dbus_data->search->io, G_IO_OUT,
					(GIOFunc)sdp_client_connection_cb, dbus_data);
		} else {
			debug("Connect completed in the first attempt");
			sdp_client_connection_cb(dbus_data->search->io, G_IO_OUT, dbus_data);
		}

		dbus_data->search->session = session;
		return 0;
	}
fail:
	if (err)
		*err = errno;

	if (session->sock >= 0)
		close(session->sock);
	free(session);
	errno = *err;

	return -1;
}

static DBusHandlerResult get_identifiers(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1];
	struct hci_dbus_data *dbus_data = data;
	struct dbus_sdp_record *rec;
	struct slist *l;
	const char *peer;
	char *str;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	DBusError err;
	bdaddr_t sba, dba;
	uint32_t flags = 0;
	int conn_err, found = 0;

	dbus_error_init(&err);

	dbus_message_get_args(msg, &err,
			DBUS_TYPE_STRING, &peer,
			DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	str2ba(peer, &dba);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	/* check the cache */
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (l = sdp_records; l; l = l->next) {
		char id_str[9];
		char *id_ptr = id_str;

		rec = l->data;
		if (bacmp(&rec->provider, &dba))
			continue;
		id2str(rec->identifier, id_ptr);
		dbus_message_iter_append_basic(&array_iter,
					DBUS_TYPE_STRING, &id_ptr);
		found = 1;
	}

	dbus_message_iter_close_container(&iter, &array_iter);
	
	if (found)
		return send_reply_and_unref(conn, reply);

	dbus_message_unref(reply);

	if (dbus_data->search)
		return error_service_search_in_progress(conn, msg);

	/* check if it is a unknown address */
	snprintf(filename, PATH_MAX, "%s/%s/lastseen", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, peer);
	if (!str)
		return error_unknown_address(conn, msg);

	free(str);

	/* FIXME: if found, when it is invalid/expired? */
	
	/* FIXME: check if there is an active connection */
	
	/* Check if there is an inquiry/bonding in progress */

	/* Background search */
	dbus_data->search = search_request_info_new(&dba, msg);
	if (!dbus_data->search)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	hci_devba(dbus_data->dev_id, &sba);

	if (dbus_sdp_connect(dbus_data, &sba, &dba, flags, &conn_err) < 0) {
		search_request_info_free(dbus_data->search);
		dbus_data->search = NULL;
		return error_failed(conn, msg, conn_err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult get_identifiers_by_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_uuid(DBusConnection *conn,
					 DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_name(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


static DBusHandlerResult register_rfcomm(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct dbus_sdp_record *rec, ref;
	DBusMessage *reply;
	DBusError err;
	const char *owner, *name;
	bdaddr_t provider;
	char id_str[9];
	char *id_ptr = id_str;
	uint8_t channel;

	owner = dbus_message_get_sender(msg);

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_BYTE, &channel,
			DBUS_TYPE_INVALID);
	
	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	hci_devba(dbus_data->dev_id, &provider);
	
	rec = dbus_sdp_record_new(owner, &provider, name, RFCOMM_UUID, channel);
	if (!rec)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	
	if (slist_find(sdp_records, &rec, (cmp_func_t)record_cmp)) {
		dbus_sdp_record_free(rec);
		return error_service_already_exists(conn, msg);
	}

	id2str(rec->identifier, id_ptr);
	reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &id_ptr,
			DBUS_TYPE_INVALID);
	if (!reply) {
		dbus_sdp_record_free(rec);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	/* FIXME: register the service */

	/* Only add a D-Bus unique name listener if there isn't one already registered */
	memset(&ref, 0, sizeof(ref));
	bacpy(&ref.provider, BDADDR_ANY);

	if (!slist_find(sdp_records, &ref, (cmp_func_t)record_cmp))
		name_listener_add(conn, rec->owner, (name_cb_t)owner_exited, dbus_data);

	sdp_records = slist_append(sdp_records, rec);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult unregister_rfcomm(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct dbus_sdp_record *rec, ref;
	struct slist *match;
	DBusMessage *reply;
	DBusError err;
	const char *owner, *identifier;

	owner = dbus_message_get_sender(msg);

	dbus_error_init(&err);
	dbus_message_get_args(msg, &err,
			DBUS_TYPE_STRING, &identifier,
			DBUS_TYPE_INVALID);
	
	if (dbus_error_is_set(&err)) {
		error("Can't extract message arguments:%s", err.message);
		dbus_error_free(&err);
		return error_invalid_arguments(conn, msg);
	}

	memset(&ref, 0, sizeof(ref));
	
	ref.uuid = RFCOMM_UUID;
	ref.identifier = str2id(identifier);
	hci_devba(dbus_data->dev_id, &ref.provider);

	match = slist_find(sdp_records, &ref, (cmp_func_t)record_cmp);
	if (!match)
		return error_service_does_not_exist(conn, msg);

	rec = match->data;
	
	if (strcmp(rec->owner, owner))
		return error_not_authorized(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* FIXME: unregister the service */

	sdp_records = slist_remove(sdp_records, rec);
	dbus_sdp_record_free(rec);

	bacpy(&ref.provider, BDADDR_ANY);
	ref.uuid = 0x0000;

	/* Only remove the D-Bus unique name listener if there are no more record using this name */
	if (!slist_find(sdp_records, &ref, (cmp_func_t)record_cmp))
		name_listener_remove(conn, ref.name, (name_cb_t)owner_exited, dbus_data);

	return send_reply_and_unref(conn, reply);
}

static struct service_data sdp_services[] = {
	{ "GetIdentifiers",		get_identifiers			},
	{ "GetIdentifiersByService",	get_identifiers_by_service	},
	{ "GetUUID",			get_uuid			},
	{ "GetName",			get_name			},
	{ "RegisterRFCOMM",		register_rfcomm			},
	{ "UnregisterRFCOMM",		unregister_rfcomm		},
	{ NULL, NULL }
};

DBusHandlerResult handle_sdp_method(DBusConnection *conn, DBusMessage *msg, void *data)
{
	service_handler_func_t handler;

	handler = find_service_handler(sdp_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

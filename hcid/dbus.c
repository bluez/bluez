#include <stdio.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>

#include "hcid.h"
#include "glib-ectomy.h"

static DBusConnection *connection;

#define TIMEOUT (30 * 1000)		// 30 seconds

#define SERVICE_NAME "org.handhelds.gpe.bluez"
#define INTERFACE_NAME SERVICE_NAME ".PinAgent"
#define REQUEST_NAME "PinRequest"
#define PATH_NAME "/org/handhelds/gpe/bluez/PinAgent"

#define WRONG_ARGS_ERROR "org.handhelds.gpe.bluez.Error.WrongArgs"

struct pin_request
{
	int dev;
	bdaddr_t bda;
};

static void reply_handler_function(DBusPendingCall *call, void *user_data)
{
	struct pin_request *req = (struct pin_request *) user_data;
	pin_code_reply_cp pr;
	DBusMessage *message;
	DBusMessageIter iter;
	int type;
	size_t len;
	char *pin;

	message = dbus_pending_call_get_reply(call);

	if (dbus_message_is_error(message, WRONG_ARGS_ERROR))
		goto error;

	dbus_message_iter_init(message, &iter);

	type = dbus_message_iter_get_arg_type(&iter);
	if (type != DBUS_TYPE_STRING)
		goto error;

	pin = dbus_message_iter_get_string(&iter);
	len = strlen(pin);

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, &req->bda);
	memcpy(pr.pin_code, pin, len);
	pr.pin_len = len;
	hci_send_cmd(req->dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
						PIN_CODE_REPLY_CP_SIZE, &pr);

	return;

error:
	hci_send_cmd(req->dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY,
							6, &req->bda);
}


static void free_pin_req(void *req)
{
	free(req);
}

void hcid_dbus_request_pin(int dev, struct hci_conn_info *ci)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusPendingCall *pending = NULL;
	struct pin_request *req;

	message = dbus_message_new_method_call(SERVICE_NAME, PATH_NAME,
						INTERFACE_NAME, REQUEST_NAME);
	if (message == NULL) {
		syslog(LOG_ERR, "Couldn't allocate D-BUS message");
		goto failed;
	}

	req = malloc(sizeof(*req));
	req->dev = dev;
	bacpy(&req->bda, &ci->bdaddr);

	dbus_message_append_iter_init(message, &iter);

	dbus_message_iter_append_boolean(&iter, ci->out);
	dbus_message_iter_append_byte_array(&iter,
			(unsigned char *) &ci->bdaddr, sizeof(ci->bdaddr));

	if (dbus_connection_send_with_reply(connection, message,
						&pending, TIMEOUT) == FALSE) {
		syslog(LOG_ERR, "D-BUS send failed");
		goto failed;
	}

	dbus_pending_call_set_notify(pending, reply_handler_function,
							req, free_pin_req);

	dbus_connection_flush (connection);

	dbus_message_unref (message);

	return;

failed:
	dbus_message_unref (message);
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY,
							6, &ci->bdaddr);
}

gboolean watch_func(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBusWatch *watch = (DBusWatch *) data;
	int flags = 0;

	if (cond & G_IO_IN)  flags |= DBUS_WATCH_READABLE;
	if (cond & G_IO_OUT) flags |= DBUS_WATCH_WRITABLE;
	if (cond & G_IO_HUP) flags |= DBUS_WATCH_HANGUP;
	if (cond & G_IO_ERR) flags |= DBUS_WATCH_ERROR;

	dbus_watch_handle(watch, flags);

	dbus_connection_ref(connection);

	/* Dispatch messages */
	while (dbus_connection_dispatch(connection) == DBUS_DISPATCH_DATA_REMAINS);

	dbus_connection_unref(connection);

	return TRUE;
}

dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
	GIOCondition cond = G_IO_HUP | G_IO_ERR;
	GIOChannel *io;
	guint id;
	int fd, flags;

	if (!dbus_watch_get_enabled(watch))
		return TRUE;

	fd = dbus_watch_get_fd(watch);
	io = g_io_channel_unix_new(fd);
	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) cond |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE) cond |= G_IO_OUT;

	id = g_io_add_watch(io, cond, watch_func, watch);

	dbus_watch_set_data(watch, (void *) id, NULL);

	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data)
{
	guint id = (guint) dbus_watch_get_data(watch);

	dbus_watch_set_data(watch, NULL, NULL);

	if (id)
		g_io_remove_watch(id);
}

static void watch_toggled(DBusWatch *watch, void *data)
{
	/* Because we just exit on OOM, enable/disable is
	 * no different from add/remove
	 */
	if (dbus_watch_get_enabled(watch))
		add_watch(watch, data);
	else
		remove_watch(watch, data);
}

gboolean hcid_dbus_init(void)
{
	DBusError error;

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		fprintf(stderr, "Failed to open connection to system message bus: %s\n",
			error.message);
		dbus_error_free(&error);
		return FALSE;
	}

	dbus_connection_set_watch_functions(connection,
		add_watch, remove_watch, watch_toggled, NULL, NULL);

	return TRUE;
}

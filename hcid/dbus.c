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
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "glib-ectomy.h"

#include "hcid.h"
#include "dbus.h"

#ifndef DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT
#define DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT	0x00
#endif

static DBusConnection *connection;
static int default_dev = -1;

#define TIMEOUT				(30 * 1000)		/* 30 seconds */
#define DBUS_RECONNECT_TIMER		(5 * 1000 * 1000)	/* 5 sec */
#define MAX_PATH_LENGTH			64
#define MAX_CONN_NUMBER			10

#define PINAGENT_SERVICE_NAME BASE_INTERFACE ".PinAgent"
#define PINAGENT_INTERFACE PINAGENT_SERVICE_NAME
#define PIN_REQUEST "PinRequest"
#define PINAGENT_PATH BASE_PATH "/PinAgent"

struct pin_request {
	int dev;
	bdaddr_t bda;
};

typedef DBusMessage* (service_handler_func_t) (DBusMessage *, void *);

struct service_data {
	const char		*name;
	service_handler_func_t	*handler_func;
	const char		*signature;
};

struct hci_dbus_data {
	uint16_t dev_id;
	uint16_t path_id;
	uint32_t path_data;
};

typedef int register_function_t(DBusConnection *conn, uint16_t id);
typedef int unregister_function_t(DBusConnection *conn, uint16_t id);

const struct service_data *get_hci_table(void);

static int hci_dbus_reg_obj_path(DBusConnection *conn, uint16_t id);
static int hci_dbus_unreg_obj_path(DBusConnection *conn, uint16_t id);

typedef const struct service_data *get_svc_table_func_t(void);

struct profile_obj_path_data {
	uint16_t		id;
	register_function_t	*reg_func;
	unregister_function_t	*unreg_func;
	get_svc_table_func_t	*get_svc_table;	/* return the service table */
};

/*
 * D-Bus error messages functions and declarations.
 * This section should be moved to a common file 
 * in the future
 *
 */

typedef struct  {
	uint32_t code;
	const char *str;
} bluez_error_t;

typedef struct {
	char *str;
	unsigned int val;
} hci_map;

static hci_map dev_flags_map[] = {
	{ "INIT",	HCI_INIT	},
	{ "RUNNING",	HCI_RUNNING	},
	{ "RAW",	HCI_RAW		},
	{ "PSCAN",	HCI_PSCAN	},
	{ "ISCAN",	HCI_ISCAN	},
	{ "INQUIRY",	HCI_INQUIRY	},
	{ "AUTH",	HCI_AUTH	},
	{ "ENCRYPT",	HCI_ENCRYPT	},
	{ "SECMGR",	HCI_SECMGR	},
	{ NULL }
};

static const bluez_error_t dbus_error_array[] = {
	{ BLUEZ_EDBUS_UNKNOWN_METHOD,	"Method not found"		},
	{ BLUEZ_EDBUS_WRONG_SIGNATURE,	"Wrong method signature"	},
	{ BLUEZ_EDBUS_WRONG_PARAM,	"Invalid parameters"		},
	{ BLUEZ_EDBUS_RECORD_NOT_FOUND,	"No record found"		},
	{ BLUEZ_EDBUS_NO_MEM,		"No memory"			},
	{ BLUEZ_EDBUS_CONN_NOT_FOUND,	"Connection not found"		},
	{ BLUEZ_EDBUS_UNKNOWN_PATH,	"Unknown D-BUS path"		},
	{ BLUEZ_EDBUS_NOT_IMPLEMENTED,	"Method not implemented"	},
	{ 0, NULL }
};

static const bluez_error_t hci_error_array[] = {
	{ HCI_UNKNOWN_COMMAND,			"Unknown HCI Command"						},
	{ HCI_NO_CONNECTION,			"Unknown Connection Identifier"					},
	{ HCI_HARDWARE_FAILURE,			"Hardware Failure"						},
	{ HCI_PAGE_TIMEOUT,			"Page Timeout"							},
	{ HCI_AUTHENTICATION_FAILURE,		"Authentication Failure"					},
	{ HCI_PIN_OR_KEY_MISSING,		"PIN Missing"							},
	{ HCI_MEMORY_FULL,			"Memory Capacity Exceeded"					},
	{ HCI_CONNECTION_TIMEOUT,		"Connection Timeout"						},
	{ HCI_MAX_NUMBER_OF_CONNECTIONS,	"Connection Limit Exceeded"					},
	{ HCI_MAX_NUMBER_OF_SCO_CONNECTIONS,	"Synchronous Connection Limit To A Device Exceeded"		},
	{ HCI_ACL_CONNECTION_EXISTS,		"ACL Connection Already Exists"					},
	{ HCI_COMMAND_DISALLOWED,		"Command Disallowed"						},
	{ HCI_REJECTED_LIMITED_RESOURCES,	"Connection Rejected due to Limited Resources"			},
	{ HCI_REJECTED_SECURITY,		"Connection Rejected Due To Security Reasons"			},
	{ HCI_REJECTED_PERSONAL,		"Connection Rejected due to Unacceptable BD_ADDR"		},
	{ HCI_HOST_TIMEOUT,			"Connection Accept Timeout Exceeded"				},
	{ HCI_UNSUPPORTED_FEATURE,		"Unsupported Feature or Parameter Value"			},
	{ HCI_INVALID_PARAMETERS,		"Invalid HCI Command Parameters"				},
	{ HCI_OE_USER_ENDED_CONNECTION,		"Remote User Terminated Connection"				},
	{ HCI_OE_LOW_RESOURCES,			"Remote Device Terminated Connection due to Low Resources"	},
	{ HCI_OE_POWER_OFF,			"Remote Device Terminated Connection due to Power Off"		},
	{ HCI_CONNECTION_TERMINATED,		"Connection Terminated By Local Host"				},
	{ HCI_REPEATED_ATTEMPTS,		"Repeated Attempts"						},
	{ HCI_PAIRING_NOT_ALLOWED,		"Pairing Not Allowed"						},
	{ HCI_UNKNOWN_LMP_PDU,			"Unknown LMP PDU"						},
	{ HCI_UNSUPPORTED_REMOTE_FEATURE,	"Unsupported Remote Feature"					},
	{ HCI_SCO_OFFSET_REJECTED,		"SCO Offset Rejected"						},
	{ HCI_SCO_INTERVAL_REJECTED,		"SCO Interval Rejected"						},
	{ HCI_AIR_MODE_REJECTED,		"SCO Air Mode Rejected"						},
	{ HCI_INVALID_LMP_PARAMETERS,		"Invalid LMP Parameters"					},
	{ HCI_UNSPECIFIED_ERROR,		"Unspecified Error"						},
	{ HCI_UNSUPPORTED_LMP_PARAMETER_VALUE,	"Unsupported LMP Parameter Value"				},
	{ HCI_ROLE_CHANGE_NOT_ALLOWED,		"Role Change Not Allowed"					},
	{ HCI_LMP_RESPONSE_TIMEOUT,		"LMP Response Timeout"						},
	{ HCI_LMP_ERROR_TRANSACTION_COLLISION,	"LMP Error Transaction Collision"				},
	{ HCI_LMP_PDU_NOT_ALLOWED,		"LMP PDU Not Allowed"						},
	{ HCI_ENCRYPTION_MODE_NOT_ACCEPTED,	"Encryption Mode Not Acceptable"				},
	{ HCI_UNIT_LINK_KEY_USED,		"Link Key Can Not be Changed"					},
	{ HCI_QOS_NOT_SUPPORTED,		"Requested QoS Not Supported"					},
	{ HCI_INSTANT_PASSED,			"Instant Passed"						},
	{ HCI_PAIRING_NOT_SUPPORTED,		"Pairing With Unit Key Not Supported"				},
	{ HCI_TRANSACTION_COLLISION,		"Different Transaction Collision"				},
	{ HCI_QOS_UNACCEPTABLE_PARAMETER,	"QoS Unacceptable Parameter"					},
	{ HCI_QOS_REJECTED,			"QoS Rejected"							},
	{ HCI_CLASSIFICATION_NOT_SUPPORTED,	"Channel Classification Not Supported"				},
	{ HCI_INSUFFICIENT_SECURITY,		"Insufficient Security"						},
	{ HCI_PARAMETER_OUT_OF_RANGE,		"Parameter Out Of Mandatory Range"				},
	{ HCI_ROLE_SWITCH_PENDING,		"Role Switch Pending"						},
	{ HCI_SLOT_VIOLATION,			"Reserved Slot Violation"					},
	{ HCI_ROLE_SWITCH_FAILED,		"Role Switch Failed"						},
	{ 0, NULL },
};

static const char *bluez_dbus_error_to_str(const uint32_t ecode) 
{
	const bluez_error_t *ptr;
	uint32_t raw_code = 0;

	if (ecode & BLUEZ_ESYSTEM_OFFSET) {
		/* System error */
		raw_code = (~BLUEZ_ESYSTEM_OFFSET) & ecode;
		syslog(LOG_INFO, "%s - msg:%s", __PRETTY_FUNCTION__, strerror(raw_code));
		return strerror(raw_code);
	} else if (ecode & BLUEZ_EDBUS_OFFSET) {
		/* D-Bus error */
		for (ptr = dbus_error_array; ptr->code; ptr++) {
			if (ptr->code == ecode) {
				syslog(LOG_INFO, "%s - msg:%s", __PRETTY_FUNCTION__, ptr->str);
				return ptr->str;
			}
		}
	} else {
		/* BLUEZ_EBT_OFFSET - Bluetooth HCI errors */
		for (ptr = hci_error_array; ptr->code; ptr++) {
			if (ptr->code == ecode) {
				syslog(LOG_INFO, "%s - msg:%s", __PRETTY_FUNCTION__, ptr->str);
				return ptr->str;
			}
		}
	}

	return NULL;
}

static DBusMessage *bluez_new_failure_msg(DBusMessage *msg, const uint32_t ecode)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	const char *error_msg;

	error_msg = bluez_dbus_error_to_str(ecode);
	if (!error_msg)
		return NULL;

	reply = dbus_message_new_error(msg, ERROR_INTERFACE, error_msg);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32 ,&ecode);

	return reply;
}

/*
 * Object path register/unregister functions 
 *
 */
static struct profile_obj_path_data obj_path_table[] = {
	{ HCI_PATH_ID, hci_dbus_reg_obj_path, hci_dbus_unreg_obj_path, get_hci_table },
	/* add other profiles here */
	{ INVALID_PATH_ID, NULL, NULL, NULL }
};

/*
 * Virtual table that handle the object path hierarchy
 */
static DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data);
static DBusHandlerResult msg_func_manager(DBusConnection *conn, DBusMessage *msg, void *data);
static DBusMessage* handle_not_implemented_req(DBusMessage *msg, void *data);

static const DBusObjectPathVTable obj_dev_vtable = {
	.message_function	= &msg_func_device,
	.unregister_function	= NULL
};

static const DBusObjectPathVTable obj_mgr_vtable = {
	.message_function	= &msg_func_manager,
	.unregister_function	= NULL
};

/*
 * Services provided under the path DEVICE_PATH
 */
static DBusMessage* handle_device_up_req(DBusMessage *msg, void *data);
static DBusMessage* handle_device_down_req(DBusMessage *msg, void *data);
static DBusMessage* handle_device_set_property_req(DBusMessage *msg, void *data);
static DBusMessage* handle_device_get_property_req(DBusMessage *msg, void *data);
static DBusMessage* handle_device_set_property_req_name(DBusMessage *msg, void *data);
static DBusMessage* handle_device_get_property_req_name(DBusMessage *msg, void *data);
static DBusMessage* handle_device_set_property_req_pscan(DBusMessage *msg, void *data);
static DBusMessage* handle_device_set_property_req_iscan(DBusMessage *msg, void *data);

static const struct service_data device_services[] = {
	{ DEV_UP,		handle_device_up_req,		DEV_UP_SIGNATURE		},
	{ DEV_DOWN,		handle_device_down_req,		DEV_DOWN_SIGNATURE		},
	{ DEV_SET_PROPERTY,	handle_device_set_property_req,	DEV_SET_PROPERTY_SIGNATURE_BOOL	},
	{ DEV_SET_PROPERTY,	handle_device_set_property_req,	DEV_SET_PROPERTY_SIGNATURE_STR	},
	{ DEV_SET_PROPERTY,	handle_device_set_property_req,	DEV_SET_PROPERTY_SIGNATURE_BYTE	},
	{ DEV_GET_PROPERTY,	handle_device_get_property_req,	DEV_GET_PROPERTY_SIGNATURE	},
	{ NULL, NULL, NULL}
};

static const struct service_data set_property_services[] = {
	{ DEV_PROPERTY_AUTH,		handle_not_implemented_req,		DEV_SET_PROPERTY_SIGNATURE_BOOL		},
	{ DEV_PROPERTY_ENCRYPT,		handle_not_implemented_req,		DEV_SET_PROPERTY_SIGNATURE_BOOL		},
	{ DEV_PROPERTY_PSCAN,		handle_device_set_property_req_pscan,	DEV_SET_PROPERTY_SIGNATURE_BOOL		},
	{ DEV_PROPERTY_ISCAN,		handle_device_set_property_req_iscan,	DEV_SET_PROPERTY_SIGNATURE_BOOL		},
	{ DEV_PROPERTY_NAME,		handle_device_set_property_req_name,	DEV_SET_PROPERTY_SIGNATURE_STR		},
	{ DEV_PROPERTY_INCMODE,		handle_not_implemented_req,		DEV_SET_PROPERTY_SIGNATURE_BYTE		},
	{ NULL, NULL, NULL}
};

static const struct service_data get_property_services[] = {
	{ DEV_PROPERTY_DEV_INFO,	handle_not_implemented_req,		DEV_GET_PROPERTY_SIGNATURE 	},
	{ DEV_PROPERTY_NAME,		handle_device_get_property_req_name,	DEV_GET_PROPERTY_SIGNATURE 	},
	{ DEV_PROPERTY_INCMODE,		handle_not_implemented_req,		DEV_GET_PROPERTY_SIGNATURE 	},
	{ NULL, NULL, NULL}
};

/*
 * Services provided under the path MANAGER_PATH
 */
static DBusMessage* handle_device_list_req(DBusMessage *msg, void *data);
static DBusMessage* handle_default_device_req(DBusMessage *msg, void *data);

static const struct service_data manager_services[] = {
	{ MGR_DEVICE_LIST,	handle_device_list_req,		MGR_GET_DEV_SIGNATURE		},
	{ MGR_DEFAULT_DEVICE,	handle_default_device_req,	MGR_DEFAULT_DEV_SIGNATURE	},
	{ MGR_INIT,		handle_not_implemented_req,	NULL				},
	{ MGR_ENABLE,		handle_not_implemented_req,	NULL				},
	{ MGR_DISABLE,		handle_not_implemented_req,	NULL				},
	{ NULL, NULL, NULL }
};

/*
 * HCI D-Bus services
 */
static DBusHandlerResult hci_signal_filter(DBusConnection *conn, DBusMessage *msg, void *data);

static DBusMessage* handle_periodic_inq_req(DBusMessage *msg, void *data);
static DBusMessage* handle_cancel_periodic_inq_req(DBusMessage *msg, void *data);
static DBusMessage* handle_inq_req(DBusMessage *msg, void *data);
static DBusMessage* handle_cancel_inq_req(DBusMessage *msg, void *data);
static DBusMessage* handle_role_switch_req(DBusMessage *msg, void *data);
static DBusMessage* handle_remote_name_req(DBusMessage *msg, void *data);
static DBusMessage* handle_display_conn_req(DBusMessage *msg, void *data);
static DBusMessage* handle_auth_req(DBusMessage *msg, void *data);

static const struct service_data device_hci_services[] = {
	{ HCI_PERIODIC_INQ,		handle_periodic_inq_req,	HCI_PERIODIC_INQ_SIGNATURE		},
	{ HCI_PERIODIC_INQ,		handle_periodic_inq_req,	HCI_PERIODIC_INQ_EXT_SIGNATURE		},
	{ HCI_CANCEL_PERIODIC_INQ,	handle_cancel_periodic_inq_req,	HCI_CANCEL_PERIODIC_INQ_SIGNATURE	},
	{ HCI_ROLE_SWITCH,		handle_role_switch_req,		HCI_ROLE_SWITCH_SIGNATURE		},
	{ HCI_INQ,			handle_inq_req,			HCI_INQ_SIGNATURE			},
	{ HCI_INQ,			handle_inq_req,			HCI_INQ_EXT_SIGNATURE			},
	{ HCI_CANCEL_INQ,		handle_cancel_inq_req,		HCI_CANCEL_INQ_SIGNATURE		},
	{ HCI_REMOTE_NAME,		handle_remote_name_req,		HCI_REMOTE_NAME_SIGNATURE		},
	{ HCI_CONNECTIONS,		handle_display_conn_req,	HCI_CONNECTIONS_SIGNATURE		},
	{ HCI_AUTHENTICATE,		handle_auth_req,		HCI_AUTHENTICATE_SIGNATURE		},
	{ NULL, NULL, NULL }
};

static void reply_handler_function(DBusPendingCall *call, void *user_data)
{
	struct pin_request *req = (struct pin_request *) user_data;
	pin_code_reply_cp pr;
	DBusMessage *message;
	DBusMessageIter iter;
	int arg_type;
	int msg_type;
	size_t len;
	char *pin;
	const char *error_msg;

	message = dbus_pending_call_steal_reply(call);

	if (!message)
		goto done;

	msg_type = dbus_message_get_type(message);
	dbus_message_iter_init(message, &iter);

	if (msg_type == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_message_iter_get_basic(&iter, &error_msg);

		/* handling WRONG_ARGS_ERROR, DBUS_ERROR_NO_REPLY, DBUS_ERROR_SERVICE_UNKNOWN */
		syslog(LOG_ERR, "%s: %s", dbus_message_get_error_name(message), error_msg);
		hci_send_cmd(req->dev, OGF_LINK_CTL,
					OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);

		goto done;
	}

	/* check signature */
	arg_type = dbus_message_iter_get_arg_type(&iter);
	if (arg_type != DBUS_TYPE_STRING) {
		syslog(LOG_ERR, "Wrong reply signature: expected PIN");
		hci_send_cmd(req->dev, OGF_LINK_CTL,
					OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);
	} else {
		dbus_message_iter_get_basic(&iter, &pin);
		len = strlen(pin);

		memset(&pr, 0, sizeof(pr));
		bacpy(&pr.bdaddr, &req->bda);
		memcpy(pr.pin_code, pin, len);
		pr.pin_len = len;
		hci_send_cmd(req->dev, OGF_LINK_CTL,
			OCF_PIN_CODE_REPLY, PIN_CODE_REPLY_CP_SIZE, &pr);
	}

done:
	if (message)
		dbus_message_unref(message);

	dbus_pending_call_unref(call);
}

static void free_pin_req(void *req)
{
	free(req);
}

static gboolean register_dbus_path(const char *path, uint16_t path_id, uint16_t dev_id,
				const DBusObjectPathVTable *pvtable, gboolean fallback)
{
	gboolean ret = FALSE;
	struct hci_dbus_data *data = NULL;

	data = malloc(sizeof(struct hci_dbus_data));
	if (data == NULL) {
		syslog(LOG_ERR, "Failed to alloc memory to DBUS path register data (%s)", path);
		goto failed;
	}

	data->path_id = path_id;
	data->dev_id = dev_id;

	if (fallback) {
		if (!dbus_connection_register_fallback(connection, path, pvtable, data)) {
			syslog(LOG_ERR, "DBUS failed to register %s fallback", path);
			goto failed;
		}
	} else {
		if (!dbus_connection_register_object_path(connection, path, pvtable, data)) {
			syslog(LOG_ERR, "DBUS failed to register %s object", path);
			goto failed;
		}
	}

	ret = TRUE;

failed:
	if (!ret && data)
		free(data);

	return ret;
}

static gboolean unregister_dbus_path(const char *path)
{
	void *data;

	if (dbus_connection_get_object_path_data(connection, path, &data) && data)
		free(data);

	if (!dbus_connection_unregister_object_path (connection, path)) {
		syslog(LOG_ERR, "DBUS failed to unregister %s object", path);
		return FALSE;
	}

	return TRUE;
}

void hcid_dbus_request_pin(int dev, struct hci_conn_info *ci)
{
	DBusMessage *message = NULL;
	DBusPendingCall *pending = NULL;
	struct pin_request *req;
	uint8_t *addr = (uint8_t *) &ci->bdaddr;
	dbus_bool_t out = ci->out;

	if (!connection) {
		if (!hcid_dbus_init())
			goto failed;
	}

	message = dbus_message_new_method_call(PINAGENT_SERVICE_NAME, PINAGENT_PATH,
						PINAGENT_INTERFACE, PIN_REQUEST);
	if (message == NULL) {
		syslog(LOG_ERR, "Couldn't allocate D-BUS message");
		goto failed;
	}

	req = malloc(sizeof(*req));
	req->dev = dev;
	bacpy(&req->bda, &ci->bdaddr);

	dbus_message_append_args(message, DBUS_TYPE_BOOLEAN, &out,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&addr, sizeof(bdaddr_t), DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
						&pending, TIMEOUT) == FALSE) {
		syslog(LOG_ERR, "D-BUS send failed");
		goto failed;
	}

	dbus_pending_call_set_notify(pending, reply_handler_function,
							req, free_pin_req);

	dbus_connection_flush(connection);

	dbus_message_unref(message);

	return;

failed:
	if (message)
		dbus_message_unref(message);

	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, &ci->bdaddr);
}

void hcid_dbus_inquiry_start(bdaddr_t *local)
{
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *local_addr;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		syslog(LOG_ERR, "No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d/%s", DEVICE_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path, DEV_HCI_INTERFACE,
						BLUEZ_HCI_INQ_START);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS inquiry start message");
		goto failed;
	}

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS inquiry start message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	dbus_message_unref(message);
	bt_free(local_addr);
}

void hcid_dbus_inquiry_complete(bdaddr_t *local)
{
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *local_addr;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		syslog(LOG_ERR, "No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d/%s", DEVICE_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path, DEV_HCI_INTERFACE,
						BLUEZ_HCI_INQ_COMPLETE);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS inquiry complete message");
		goto failed;
	}

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS inquiry complete message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	dbus_message_unref(message);
	bt_free(local_addr);
}

void hcid_dbus_inquiry_result(bdaddr_t *local, bdaddr_t *peer, uint32_t class, int8_t rssi)
{
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *local_addr, *peer_addr;
	dbus_uint32_t tmp_class = class;
	dbus_int32_t tmp_rssi = rssi;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		syslog(LOG_ERR, "No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d/%s", DEVICE_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path, DEV_HCI_INTERFACE,
						BLUEZ_HCI_INQ_RESULT);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS inquiry result message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_UINT32, &tmp_class,
					DBUS_TYPE_INT32, &tmp_rssi,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS inquiry result message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	dbus_message_unref(message);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_remote_name(bdaddr_t *local, bdaddr_t *peer, char *name)
{
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *local_addr, *peer_addr;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		syslog(LOG_ERR, "No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d/%s", DEVICE_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path, DEV_HCI_INTERFACE,
						BLUEZ_HCI_REMOTE_NAME);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS remote name message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS remote name message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_remote_name_failed(bdaddr_t *local, bdaddr_t *peer, uint8_t status)
{
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *local_addr, *peer_addr;
	bdaddr_t tmp;
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		syslog(LOG_ERR, "No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d/%s", DEVICE_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path, DEV_HCI_INTERFACE,
						BLUEZ_HCI_REMOTE_NAME_FAILED);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS remote name message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_BYTE, &status,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS remote name message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

	bt_free(local_addr);
	bt_free(peer_addr);
}

void hcid_dbus_conn_complete(bdaddr_t *local, bdaddr_t *peer)
{
}

void hcid_dbus_disconn_complete(bdaddr_t *local, bdaddr_t *peer, uint8_t reason)
{
}

void hcid_dbus_auth_complete(bdaddr_t *local, bdaddr_t *peer, const uint8_t status)
{
	DBusMessage *message = NULL;
	char *local_addr, *peer_addr;
	bdaddr_t tmp;
	char path[MAX_PATH_LENGTH];
	int id;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	baswap(&tmp, peer); peer_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		syslog(LOG_ERR, "No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d/%s", DEVICE_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path, DEV_HCI_INTERFACE,
						BLUEZ_HCI_AUTH_COMPLETE);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS remote name message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &peer_addr,
					DBUS_TYPE_BYTE, &status,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS remote name message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

	bt_free(local_addr);
	bt_free(peer_addr);
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
	guint *id;
	int fd, flags;

	if (!dbus_watch_get_enabled(watch))
		return TRUE;

	id = malloc(sizeof(guint));
	if (id == NULL)
		return FALSE;

	fd = dbus_watch_get_fd(watch);
	io = g_io_channel_unix_new(fd);
	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) cond |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE) cond |= G_IO_OUT;

	*id = g_io_add_watch(io, cond, watch_func, watch);

	dbus_watch_set_data(watch, id, NULL);

	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data)
{
	guint *id = dbus_watch_get_data(watch);

	dbus_watch_set_data(watch, NULL, NULL);

	if (id) {
		g_io_remove_watch(*id);
		free(id);
	}
}

static void watch_toggled(DBusWatch *watch, void *data)
{
	/* Because we just exit on OOM, enable/disable is
	 * no different from add/remove */
	if (dbus_watch_get_enabled(watch))
		add_watch(watch, data);
	else
		remove_watch(watch, data);
}

static gboolean unregister_device_path(const char *path)
{
	char **children = NULL;

	if (!dbus_connection_list_registered(connection, path, &children))
		goto done;

	for (; *children; children++) {
		char child_path[MAX_PATH_LENGTH];

		snprintf(child_path, sizeof(child_path), "%s/%s", path, *children);

		unregister_dbus_path(child_path);
	}

	if (*children)
		dbus_free_string_array(children);

done:
	return unregister_dbus_path(path);
}

gboolean hcid_dbus_init(void)
{
	DBusError error;

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	if (dbus_error_is_set(&error)) {
		syslog(LOG_ERR, "Can't open system message bus connection: %s",
								error.message);
		dbus_error_free(&error);
		return FALSE;
	}

	dbus_connection_set_exit_on_disconnect(connection, FALSE);

	dbus_bus_request_name(connection, BASE_INTERFACE,
				DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT, &error);

	if (dbus_error_is_set(&error)) {
		syslog(LOG_ERR, "Can't get system message bus name: %s",
								error.message);
		dbus_error_free(&error);
		return FALSE;
	}

	if (!register_dbus_path(DEVICE_PATH, DEVICE_ROOT_ID, INVALID_DEV_ID,
				&obj_dev_vtable, TRUE))
		return FALSE;

	if (!register_dbus_path(MANAGER_PATH, MANAGER_ROOT_ID, INVALID_DEV_ID,
				&obj_mgr_vtable, FALSE))
		return FALSE;

	if (!dbus_connection_add_filter(connection, hci_signal_filter, NULL, NULL)) {
		syslog(LOG_ERR, "Can't add new HCI filter");
		return FALSE;
	}

	dbus_connection_set_watch_functions(connection,
			add_watch, remove_watch, watch_toggled, NULL, NULL);

	return TRUE;
}

void hcid_dbus_exit(void)
{
	char **children = NULL;

	if (!connection)
		return;

	/* Unregister all paths in Device path hierarchy */
	if (!dbus_connection_list_registered(connection, DEVICE_PATH, &children))
		goto done;

	for (; *children; children++) {
		char dev_path[MAX_PATH_LENGTH];

		snprintf(dev_path, sizeof(dev_path), "%s/%s", DEVICE_PATH, *children);

		unregister_device_path(dev_path);
	}

	if (*children)
		dbus_free_string_array(children);

done:
	unregister_dbus_path(DEVICE_PATH);
	unregister_dbus_path(MANAGER_PATH);

	dbus_connection_close(connection);
}

gboolean hcid_dbus_register_device(uint16_t id) 
{
	char path[MAX_PATH_LENGTH];
	char *pptr = path;
	gboolean ret;
	DBusMessage *message = NULL;
	int dd = -1;
	read_scan_enable_rp rp;
	struct hci_request rq;
	struct hci_dbus_data* pdata;

	snprintf(path, sizeof(path), "%s/hci%d", DEVICE_PATH, id);
	ret = register_dbus_path(path, DEVICE_PATH_ID, id, &obj_dev_vtable, FALSE);

	dd = hci_open_dev(id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed: hci%d", id);
		rp.enable = SCAN_PAGE | SCAN_INQUIRY;
	} else {
		memset(&rq, 0, sizeof(rq));
		rq.ogf    = OGF_HOST_CTL;
		rq.ocf    = OCF_READ_SCAN_ENABLE;
		rq.rparam = &rp;
		rq.rlen   = READ_SCAN_ENABLE_RP_SIZE;
	
		if (hci_send_req(dd, &rq, 500) < 0) {
			syslog(LOG_ERR, "Sending read scan enable command failed: %s (%d)",
								strerror(errno), errno);
			rp.enable = SCAN_PAGE | SCAN_INQUIRY;
		} else if (rp.status) {
			syslog(LOG_ERR, "Getting scan enable failed with status 0x%02x",
										rp.status);
			rp.enable = SCAN_PAGE | SCAN_INQUIRY;
		}
	}

	if (!dbus_connection_get_object_path_data(connection, path, (void*) &pdata))
		syslog(LOG_ERR, "Getting path data failed!");
	else
		pdata->path_data = rp.enable; /* Keep the current scan status */

	message = dbus_message_new_signal(MANAGER_PATH, MANAGER_INTERFACE,
							BLUEZ_MGR_DEV_ADDED);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS remote name message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send(connection, message, NULL)) {
		syslog(LOG_ERR, "Can't send D-BUS added device message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

	if (ret && default_dev < 0)
		default_dev = id;

	if (dd >= 0)
		close(dd);

	return ret;
}

gboolean hcid_dbus_unregister_device(uint16_t id)
{
	gboolean ret;
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];
	char *pptr = path;

	snprintf(path, sizeof(path), "%s/hci%d", DEVICE_PATH, id);

	message = dbus_message_new_signal(MANAGER_PATH, MANAGER_INTERFACE,
							BLUEZ_MGR_DEV_REMOVED);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS remote name message");
		goto failed;
	}

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send(connection, message, NULL)) {
		syslog(LOG_ERR, "Can't send D-BUS added device message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	if (message)
		dbus_message_unref(message);

	ret = unregister_device_path(path);

	/* FIXME: If there are any devices left after this removal the default
	 * device should be changed to one of them */
	if (ret && default_dev == id)
		default_dev = -1;

	return ret;
}

gboolean hcid_dbus_dev_up(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	struct profile_obj_path_data *ptr = obj_path_table;
	DBusMessage *message = NULL;

	if (!connection)
		return FALSE;

	for (; ptr->id != INVALID_PATH_ID; ptr++) {
		if (ptr->reg_func(connection, id) < 0)
			goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", DEVICE_PATH, id);

	message = dbus_message_new_signal(path, DEVICE_INTERFACE, DEV_UP);

	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS remote name message");
		goto failed;
	}

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS added device message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	/* if the signal can't be sent ignore the error */

	if (message)
		dbus_message_unref(message);

	return TRUE;
}

gboolean hcid_dbus_dev_down(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	struct profile_obj_path_data *ptr = obj_path_table;
	DBusMessage *message = NULL;

	if (!connection)
		return FALSE;

	for (; ptr->id != INVALID_PATH_ID; ptr++) {
		if (ptr->unreg_func(connection, id) < 0)
			syslog(LOG_ERR, "Unregistering profile id 0x%04x failed", ptr->id);
	}

	snprintf(path, sizeof(path), "%s/hci%d", DEVICE_PATH, id);

	message = dbus_message_new_signal(path, DEVICE_INTERFACE, DEV_DOWN);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS device removed  message");
		goto failed;
	}

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS removed device message");
		goto failed;
	}

	dbus_connection_flush(connection);

failed:
	/* if the signal can't be sent ignore the error */

	if (message)
		dbus_message_unref(message);

	return TRUE;
}

/*
 * @brief HCI object path register function
 * Detailed description: function responsible for register a new hci 
 * D-Bus path. If necessary the default path must be registered too.
 * @param conn D-Bus connection
 * @param id hci device identification
 * @return (0-Success/-1 failure)
 */
static int hci_dbus_reg_obj_path(DBusConnection *conn, uint16_t id)
{
	char path[MAX_PATH_LENGTH];

	/* register the default path*/
	snprintf(path, sizeof(path), "%s/hci%d/%s", DEVICE_PATH, id, BLUEZ_HCI);
	if (!register_dbus_path(path, HCI_PATH_ID, id, &obj_dev_vtable, FALSE))
		return -1;

	return 0;
}

/*
 * @brief HCI object path unregister function
 * Detailed description: function responsible for unregister HCI D-Bus
 * path for a detached hci device. If necessary the default path must 
 * be registered too.
 * @param conn D-Bus connection
 * @param unreg_dft register the default path(0 or !0)
 * @param id hci device identification
 * @return (0-Success/-1 failure)
 */
static int hci_dbus_unreg_obj_path(DBusConnection *conn, uint16_t id) 
{
	char path[MAX_PATH_LENGTH];

	snprintf(path, sizeof(path), "%s/hci%d/%s", DEVICE_PATH, id, BLUEZ_HCI);
	if (!unregister_dbus_path(path))
		return -1;

	return 0;
}

const struct service_data *get_hci_table(void)
{
	return device_hci_services;
}

/*****************************************************************
 *
 *  Section reserved to re-connection timer
 *
 *****************************************************************/
static void reconnect_timer_handler(int signum)
{
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr;
	int sk;
	int i;

	if (hcid_dbus_init() == FALSE)
		return;

	/* stop the timer */
	sigaction(SIGALRM, NULL, NULL);
	setitimer(ITIMER_REAL, NULL, NULL);

	/* register the device based paths */

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't open HCI socket: %s (%d)",
							strerror(errno), errno);
		return;
	}

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		syslog(LOG_ERR, "Can't allocate memory");
		goto failed;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, (void *) dl) < 0) {
		syslog(LOG_INFO, "Can't get device list: %s (%d)",
							strerror(errno), errno);
		goto failed;
	}

	/* reset the default device */
	default_dev = -1;

	for (i = 0; i < dl->dev_num; i++, dr++) {

		hcid_dbus_register_device(dr->dev_id);

		if (hci_test_bit(HCI_UP, &dr->dev_opt))
			hcid_dbus_dev_up(dr->dev_id);
	}

failed:
	if (sk >= 0)
		close(sk);

	if (dl)
		free(dl);

}

static void reconnect_timer_start(void)
{
	struct sigaction sa;
	struct itimerval timer;

	memset (&sa, 0, sizeof (sa));
	sa.sa_handler = &reconnect_timer_handler;
	sigaction(SIGALRM, &sa, NULL);

	/* expire after X  msec... */
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = DBUS_RECONNECT_TIMER;

	/* ... and every x msec after that. */
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = DBUS_RECONNECT_TIMER;

	setitimer(ITIMER_REAL, &timer, NULL);
}

/*****************************************************************
 *  
 *  Section reserved to HCI D-Bus services 
 *  
 *****************************************************************/
static DBusHandlerResult hci_signal_filter (DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	const char *iface;
	const char *method;

	if (!msg || !conn)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_get_type (msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	iface = dbus_message_get_interface(msg);
	method = dbus_message_get_member(msg);

	if ((strcmp(iface, DBUS_INTERFACE_LOCAL) == 0) &&
			(strcmp(method, "Disconnected") == 0)) {
		syslog(LOG_ERR, "Got disconnected from the system message bus");
		dbus_connection_dispatch(conn);
		dbus_connection_close(conn);
		dbus_connection_unref(conn);
		reconnect_timer_start();
		ret = DBUS_HANDLER_RESULT_HANDLED;
	} else if (strcmp(iface, DBUS_INTERFACE_DBUS) == 0) {
		if (strcmp(method, "NameOwnerChanged") == 0)
			ret = DBUS_HANDLER_RESULT_HANDLED;
		else if (strcmp(method, "NameAcquired") == 0)
			ret = DBUS_HANDLER_RESULT_HANDLED;
	}

	return ret;
}

static DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct service_data *handlers = NULL;
	DBusMessage *reply = NULL;
	struct hci_dbus_data *dbus_data = data;
	const char *method;
	const char *signature;
	const char *path;
	uint32_t error = BLUEZ_EDBUS_UNKNOWN_METHOD;
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	path = dbus_message_get_path(msg);
	method = dbus_message_get_member(msg);
	signature = dbus_message_get_signature(msg);

	if (dbus_data->path_id == DEVICE_ROOT_ID) {
		/* Device is down(path unregistered) or the path is wrong */
		ret = DBUS_HANDLER_RESULT_HANDLED;
		error = BLUEZ_EDBUS_UNKNOWN_PATH;
		goto failed;
	}

	if (dbus_data->path_id == DEVICE_PATH_ID)
		handlers = device_services;
	else {
		struct profile_obj_path_data *profile;
		for (profile = obj_path_table; profile->id != INVALID_PATH_ID; profile++) {
			if (profile->id == dbus_data->path_id) {
				handlers = profile->get_svc_table();
				break;
			}
		}
	}

	if (!handlers)
		goto failed;

	for (; handlers->name != NULL; handlers++) {
		if (strcmp(handlers->name, method))
			continue;

		ret = DBUS_HANDLER_RESULT_HANDLED;

		if (!strcmp(handlers->signature, signature)) {
			reply = handlers->handler_func(msg, data);
			error = 0;
			break;
		} else {
			/* Set the error, but continue looping incase there is
			 * another method with the same name but a different
			 * signature */
			error = BLUEZ_EDBUS_WRONG_SIGNATURE;
			continue;
		}
	}

failed:
	if (error)
		reply = bluez_new_failure_msg(msg, error);

	if (reply) {
		if (!dbus_connection_send (conn, reply, NULL))
			syslog(LOG_ERR, "Can't send reply message!");
		dbus_message_unref(reply);
	}

	return ret;
}

static DBusHandlerResult msg_func_manager(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct service_data *handlers;
	DBusMessage *reply = NULL;
	const char *iface;
	const char *method;
	const char *signature;
	const char *path;
	uint32_t error = BLUEZ_EDBUS_UNKNOWN_METHOD;
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	path = dbus_message_get_path(msg);
	iface = dbus_message_get_interface(msg);
	method = dbus_message_get_member(msg);
	signature = dbus_message_get_signature(msg);

	if (strcmp(iface, MANAGER_INTERFACE) != 0)
		return ret;

	for (handlers = manager_services; handlers->name != NULL; handlers++) {
		if (strcmp(handlers->name, method))
			continue;

		if (strcmp(handlers->signature, signature) != 0)
			error = BLUEZ_EDBUS_WRONG_SIGNATURE;
		else {
			reply = handlers->handler_func(msg, data);
			error = 0;
		}

		ret = DBUS_HANDLER_RESULT_HANDLED;
	}

	if (error)
		reply = bluez_new_failure_msg(msg, error);

	if (reply) {
		if (!dbus_connection_send (conn, reply, NULL))
			syslog(LOG_ERR, "Can't send reply message!");
		dbus_message_unref(reply);
	}

	return ret;
}

static DBusMessage* handle_periodic_inq_req(DBusMessage *msg, void *data)
{
	periodic_inquiry_cp inq_param;
	struct hci_request rq;
	uint8_t status;
	DBusMessage *reply = NULL;
	struct hci_dbus_data *dbus_data = data;
	uint8_t length, num_rsp = 0;
	uint16_t max_period;
	uint16_t min_period;
	uint32_t lap = 0x9e8b33;
	int dd = -1;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	if (dbus_message_has_signature(msg, HCI_PERIODIC_INQ_EXT_SIGNATURE))
		dbus_message_get_args(msg, NULL,
						DBUS_TYPE_BYTE, &length,
						DBUS_TYPE_UINT16, &min_period,
						DBUS_TYPE_UINT16, &max_period,
						DBUS_TYPE_UINT32, &lap,
						DBUS_TYPE_INVALID);
	else
		dbus_message_get_args(msg, NULL,
						DBUS_TYPE_BYTE, &length,
						DBUS_TYPE_UINT16, &min_period,
						DBUS_TYPE_UINT16, &max_period,
						DBUS_TYPE_INVALID);

	/* Check for valid parameters */
	if (length >= min_period || min_period >= max_period
					|| length < 0x01 || length > 0x30
					|| lap < 0x9e8b00 || lap > 0x9e8b3f) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);
		goto failed;
	}

	inq_param.num_rsp = num_rsp;
	inq_param.length  = length;

	inq_param.max_period = htobs(max_period);
	inq_param.min_period = htobs(min_period);

	inq_param.lap[0] = lap & 0xff;
	inq_param.lap[1] = (lap >> 8) & 0xff;
	inq_param.lap[2] = (lap >> 16) & 0xff;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_PERIODIC_INQUIRY;
	rq.cparam = &inq_param;
	rq.clen   = PERIODIC_INQUIRY_CP_SIZE;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending periodic inquiry command failed: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (status) {
		syslog(LOG_ERR, "Periodic inquiry failed with status 0x%02x", status);
		reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET + status);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		close(dd);

	return reply;
}

static DBusMessage* handle_cancel_periodic_inq_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	struct hci_request rq;
	struct hci_dbus_data *dbus_data = data;
	uint8_t status;
	int dd = -1;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_EXIT_PERIODIC_INQUIRY;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending exit periodic inquiry command failed: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (status) {
		syslog(LOG_ERR, "Exit periodic inquiry failed with status 0x%02x", status);
		reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET + status);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		close(dd);

	return reply;
}

static DBusMessage* handle_inq_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	inquiry_cp cp;
	evt_cmd_status rp;
	struct hci_request rq;
	struct hci_dbus_data *dbus_data = data;
	int dd = -1;
	uint8_t length = 8, num_rsp = 0;
	uint32_t lap = 0x9e8b33;

	if (dbus_message_has_signature(msg, HCI_INQ_EXT_SIGNATURE)) {
		dbus_message_get_args(msg, NULL,
						DBUS_TYPE_BYTE, &length,
						DBUS_TYPE_UINT32, &lap,
						DBUS_TYPE_INVALID);

		if (length < 0x01 || length > 0x30
					|| lap < 0x9e8b00 || lap > 0x9e8b3f) {
			reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);
			goto failed;
		}
	}

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "Unable to open device %d: %s (%d)",
					dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	memset(&cp, 0, sizeof(cp));
	cp.lap[0]  = lap & 0xff;
	cp.lap[1]  = (lap >> 8) & 0xff;
	cp.lap[2]  = (lap >> 16) & 0xff;
	cp.length  = length;
	cp.num_rsp = num_rsp;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_INQUIRY;
	rq.cparam = &cp;
	rq.clen   = INQUIRY_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Unable to start inquiry: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	return reply;
}

static DBusMessage* handle_cancel_inq_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	struct hci_request rq;
	struct hci_dbus_data *dbus_data = data;
	uint8_t status;
	int dd = -1;

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "Unable to open device %d: %s (%d)",
					dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_INQUIRY_CANCEL;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending cancel inquiry failed: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (status) {
		syslog(LOG_ERR, "Cancel inquiry failed with status 0x%02x", status);
		reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET + status);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	return reply;
}

static DBusMessage* handle_role_switch_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	char *str_bdaddr = NULL;
	struct hci_dbus_data *dbus_data = data;
	bdaddr_t bdaddr;
	uint8_t role;
	int dev_id = -1, dd = -1;

	dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &str_bdaddr,
					DBUS_TYPE_BYTE, &role,
					DBUS_TYPE_INVALID);

	str2ba(str_bdaddr, &bdaddr);

	dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);

	if (dev_id < 0) {
		syslog(LOG_ERR, "Bluetooth device failed");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	if (dbus_data->dev_id != dev_id) {
		syslog(LOG_ERR, "Connection not found");
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_CONN_NOT_FOUND);
		goto failed;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	if (hci_switch_role(dd, &bdaddr, role, 10000) < 0) {
		syslog(LOG_ERR, "Switch role request failed");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	return reply;
}

static DBusMessage* handle_remote_name_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	struct hci_dbus_data *dbus_data = data;
	int dd = -1;
	const char *str_bdaddr;
	bdaddr_t bdaddr;
	struct hci_request rq;
	remote_name_req_cp cp;
	evt_cmd_status rp;

	dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &str_bdaddr,
					DBUS_TYPE_INVALID);

	str2ba(str_bdaddr, &bdaddr);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "Unable to open device %d: %s (%d)",
					dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	memset(&cp, 0, sizeof(cp));
	cp.bdaddr = bdaddr;
	cp.pscan_rep_mode = 0x01;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_REMOTE_NAME_REQ;
	rq.cparam = &cp;
	rq.clen   = REMOTE_NAME_REQ_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Unable to send remote name request: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	return reply;
}

static DBusMessage* handle_display_conn_req(DBusMessage *msg, void *data)
{
	struct hci_conn_list_req *cl = NULL;
	struct hci_conn_info *ci = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessageIter  struct_iter;
	char addr[18];
	const char array_sig[] = HCI_CONN_INFO_STRUCT_SIGNATURE;
	const char *paddr = addr;
	struct hci_dbus_data *dbus_data = data;
	int sk = -1;
	int i;

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	cl = malloc(MAX_CONN_NUMBER * sizeof(*ci) + sizeof(*cl));
	if (!cl) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_NO_MEM);
		goto failed;
	}

	cl->dev_id = dbus_data->dev_id;
	cl->conn_num = MAX_CONN_NUMBER;
	ci = cl->conn_info;

	if (ioctl(sk, HCIGETCONNLIST, (void *) cl) < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		syslog(LOG_ERR, "Out of memory while calling dbus_message_new_method_return");
		goto failed;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, array_sig, &array_iter);

	for (i = 0; i < cl->conn_num; i++, ci++) {
		ba2str(&ci->bdaddr, addr);

		dbus_message_iter_open_container(&array_iter, DBUS_TYPE_STRUCT, NULL, &struct_iter);
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT16 ,&(ci->handle));
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING ,&paddr);
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_BYTE ,&(ci->type));
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_BYTE ,&(ci->out));
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT16 ,&(ci->state));
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_UINT32 ,&(ci->link_mode));
		dbus_message_iter_close_container(&array_iter, &struct_iter);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

failed:
	if (sk >= 0)
		close(sk);

	if (cl)
		free(cl);

	return reply;
}

static DBusMessage* handle_auth_req(DBusMessage *msg, void *data)
{
	struct hci_request rq;
	auth_requested_cp cp;
	evt_cmd_status rp;
	DBusMessage *reply = NULL;
	char *str_bdaddr = NULL;
	struct hci_dbus_data *dbus_data = data;
	struct hci_conn_info_req *cr = NULL;
	bdaddr_t bdaddr;
	int dev_id = -1;
	int dd = -1;

	dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &str_bdaddr,
					DBUS_TYPE_INVALID);

	str2ba(str_bdaddr, &bdaddr);

	dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);

	if (dev_id < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_CONN_NOT_FOUND);
		goto failed;
	}

	if (dbus_data->dev_id != dev_id) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_CONN_NOT_FOUND);
		goto failed;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_NO_MEM);
		goto failed;
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;

	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	memset(&cp, 0, sizeof(cp));
	cp.handle = cr->conn_info->handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Unable to send authentication request: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		close(dd);

	if (cr)
		free(cr);

	return reply;
}

/*****************************************************************
 *  
 *  Section reserved to local device configuration D-Bus Services
 *  
 *****************************************************************/
static DBusMessage* handle_device_up_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	struct hci_dbus_data *dbus_data = data;
	struct hci_dev_info di;
	struct hci_dev_req dr;
	int sk = -1;

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't open HCI socket: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (ioctl(sk, HCIDEVUP, dbus_data->dev_id) < 0 && errno != EALREADY) {
		syslog(LOG_ERR, "Can't init device hci%d: %s (%d)",
					dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (ioctl(sk, HCIGETDEVINFO, (void *) &di) >= 0 &&
					!hci_test_bit(HCI_RAW, &di.flags)) {
		dr.dev_id  = dbus_data->dev_id;
		dr.dev_opt = SCAN_PAGE | SCAN_INQUIRY; /* piscan */
		if (ioctl(sk, HCISETSCAN, (unsigned long) &dr) < 0) {
			syslog(LOG_ERR, "Can't set scan mode on hci%d: %s (%d)",
					dbus_data->dev_id, strerror(errno), errno);
			reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
			goto failed;
		}
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (sk >= 0)
		close(sk);

	return reply;
}

static DBusMessage* handle_device_down_req(DBusMessage *msg, void *data)
{
	DBusMessage *reply = NULL;
	struct hci_dbus_data *dbus_data = data;
	int sk = -1;

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't open HCI socket: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (ioctl(sk, HCIDEVDOWN, dbus_data->dev_id) < 0) {
		syslog(LOG_ERR, "Can't down device hci%d: %s (%d)",
					dbus_data->dev_id, strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (sk >= 0)
		close(sk);

	return reply;
}

static DBusMessage* handle_device_set_property_req(DBusMessage *msg, void *data)
{
	const struct service_data *handlers = set_property_services;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	const char *signature;
	char *str_name;
	uint32_t error = BLUEZ_EDBUS_WRONG_PARAM;

	signature = dbus_message_get_signature(msg);

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &str_name);

	for (; handlers->name != NULL; handlers++) {
		if (strcasecmp(handlers->name, str_name))
			continue;

		if (strcmp(handlers->signature, signature) == 0) {
			reply = handlers->handler_func(msg, data);
			error = 0;
			break;
		} else {
			error = BLUEZ_EDBUS_WRONG_SIGNATURE;
			break;
		}
	}

	if (error)
		reply = bluez_new_failure_msg(msg, error);

	return reply;
}

static DBusMessage* handle_device_get_property_req(DBusMessage *msg, void *data)
{
	const struct service_data *handlers = get_property_services;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	char *str_name;
	uint32_t error = BLUEZ_EDBUS_WRONG_PARAM;


	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &str_name);

	for (; handlers->name != NULL; handlers++) {
		if (!strcasecmp(handlers->name, str_name)) {
			reply = handlers->handler_func(msg, data);
			error = 0;
			break;
		}
	}

	if (error)
		reply = bluez_new_failure_msg(msg, error);

	return reply;
}

static void send_property_changed_signal(const int devid, const char *prop_name, const int prop_type, void *value)
{
	DBusMessage *message = NULL;
	char path[MAX_PATH_LENGTH];

	snprintf(path, sizeof(path)-1, "%s/hci%d", DEVICE_PATH, devid);
	path[MAX_PATH_LENGTH-1]='\0';

	message = dbus_message_new_signal(path, DEVICE_INTERFACE,
						BLUEZ_HCI_PROPERTY_CHANGED);
	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS inquiry complete message");
		goto failed;
	}

	dbus_message_append_args(message,
				DBUS_TYPE_STRING, &prop_name,
				prop_type, value,
				DBUS_TYPE_INVALID);

	if (dbus_connection_send(connection, message, NULL) == FALSE) {
		syslog(LOG_ERR, "Can't send D-BUS PropertChanged(%s) signal", prop_name);
		goto failed;
	}

failed:
	if (message)
		dbus_message_unref(message);
}

static DBusMessage* handle_device_set_property_req_name(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	char *str_name;
	int dd = -1;
	uint8_t status;
	change_local_name_cp cp;
	struct hci_request rq;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &str_name);

	if (strlen(str_name) == 0) {
		syslog(LOG_ERR, "HCI change name failed - Invalid Name!");
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);
		goto failed;
	}

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed: hci%d", dbus_data->dev_id);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	strncpy((char *) cp.name, str_name, sizeof(cp.name));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_CHANGE_LOCAL_NAME;
	rq.cparam = &cp;
	rq.clen   = CHANGE_LOCAL_NAME_CP_SIZE;
	rq.rparam = &status;
	rq.rlen   = sizeof(status);

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending change name command failed: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (status) {
		syslog(LOG_ERR, "Setting name failed with status 0x%02x", status);
		reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET + status);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		close(dd);

	return reply;
}

void hcid_dbus_setname_complete(bdaddr_t *local)
{
	char *local_addr;
	bdaddr_t tmp;
	int id;
	int dd = -1;
	read_local_name_rp rp;
	struct hci_request rq;
	const char *pname = (char*) rp.name;
	char name[249];

	baswap(&tmp, local); local_addr = batostr(&tmp);

	id = hci_devid(local_addr);
	if (id < 0) {
		syslog(LOG_ERR, "No matching device id for %s", local_addr);
		goto failed;
	}

	dd = hci_open_dev(id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed: hci%d", id);
		memset(&rq, 0, sizeof(rq));
	} else {
		memset(&rq, 0, sizeof(rq));
		rq.ogf    = OGF_HOST_CTL;
		rq.ocf    = OCF_READ_LOCAL_NAME;
		rq.rparam = &rp;
		rq.rlen   = READ_LOCAL_NAME_RP_SIZE;

		if (hci_send_req(dd, &rq, 100) < 0) {
			syslog(LOG_ERR,
				"Sending getting name command failed: %s (%d)",
				strerror(errno), errno);
			rp.name[0] = '\0';
		}

		if (rp.status) {
			syslog(LOG_ERR,
				"Getting name failed with status 0x%02x",
				rp.status);
			rp.name[0] = '\0';
		}
	}

	strncpy(name, pname, sizeof(name) - 1);
	name[248] = '\0';
	pname = name;

	send_property_changed_signal(id, DEV_PROPERTY_NAME, DBUS_TYPE_STRING, &pname);
	dbus_connection_flush(connection);

failed:
	if (dd >= 0)
		close(dd);

	bt_free(local_addr);
}

static DBusMessage* handle_device_get_property_req_name(DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply = NULL;
	int dd = -1;
	read_local_name_rp rp;
	struct hci_request rq;
	const char *pname = (char*) rp.name;
	char name[249];

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed: hci%d", dbus_data->dev_id);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_LOCAL_NAME;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_NAME_RP_SIZE;

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending getting name command failed: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (rp.status) {
		syslog(LOG_ERR, "Getting name failed with status 0x%02x", rp.status);
		reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET + rp.status);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		syslog(LOG_ERR, "Out of memory while calling dbus_message_new_method_return");
		goto failed;
	}

	strncpy(name,pname,sizeof(name)-1);
	name[248]='\0';
	pname = name;

	dbus_message_append_args(reply,
				DBUS_TYPE_STRING, &pname,
				DBUS_TYPE_INVALID);

failed:
	if (dd >= 0)
		close(dd);

	return reply;
}

static DBusMessage* write_scan_enable(DBusMessage *msg, void *data, gboolean ispscan)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	int dd = -1;
	read_scan_enable_rp rp;
	uint8_t enable;
	uint8_t status;
	uint8_t scan_change, scan_keep;
	struct hci_request rq;
	gboolean prop_value; /* new requested value for the iscan or pscan */

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &prop_value);

	dd = hci_open_dev(dbus_data->dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed: hci%d", dbus_data->dev_id);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_SCAN_ENABLE;
	rq.rparam = &rp;
	rq.rlen   = READ_SCAN_ENABLE_RP_SIZE;

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending read scan enable command failed: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (rp.status) {
		syslog(LOG_ERR, "Getting scan enable failed with status 0x%02x",
								 	rp.status);
		reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET + rp.status);
		goto failed;
        }

	if (ispscan) { /* Page scan */
		scan_change = SCAN_PAGE;
		scan_keep = SCAN_INQUIRY;
	} else { /* Inquiry scan */
		scan_change = SCAN_INQUIRY;
		scan_keep = SCAN_PAGE;
	}

	/* This is an optimization. We want to avoid overwrite the value
	if the requested scan property will not change. */
	if (prop_value && !(rp.enable & scan_change))
		/* Enable the requested scan type (e.g. page scan). Keep the
		the other type untouched. */
		enable = (rp.enable & scan_keep) | scan_change;
	else if (!prop_value && (rp.enable & scan_change))
		/* Disable the requested scan type (e.g. page scan). Keep the
		the other type untouched. */
		enable = (rp.enable & scan_keep);
	else { /* Property not changed. Do nothing. Return ok. */
		reply = dbus_message_new_method_return(msg);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_SCAN_ENABLE;
	rq.cparam = &enable;
	rq.clen   = sizeof(enable);
	rq.rparam = &status;
	rq.rlen   = sizeof(status);

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending write scan enable command failed: %s (%d)",
							strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}
	if (status) {
		syslog(LOG_ERR, "Setting scan enable failed with status 0x%02x", rp.status);
		reply = bluez_new_failure_msg(msg, BLUEZ_EBT_OFFSET + rp.status);
		goto failed;
	}
	reply = dbus_message_new_method_return(msg);

failed:
	if (dd >= 0)
		close(dd);
	return reply;

}

void hcid_dbus_setscan_enable_complete(bdaddr_t *local)
{
	char *local_addr;
	char path[MAX_PATH_LENGTH];
	bdaddr_t tmp;
	int id;
	int dd = -1;
	gboolean se;
	read_scan_enable_rp rp;
	struct hci_request rq;
	struct hci_dbus_data *pdata = NULL;
	uint32_t old_data;

	baswap(&tmp, local); local_addr = batostr(&tmp);
	id = hci_devid(local_addr);
	if (id < 0) {
		syslog(LOG_ERR, "No matching device id for %s", local_addr);
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", DEVICE_PATH, id);

	dd = hci_open_dev(id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed: hci%d", id);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_SCAN_ENABLE;
	rq.rparam = &rp;
	rq.rlen   = READ_SCAN_ENABLE_RP_SIZE;

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Sending read scan enable command failed: %s (%d)",
							strerror(errno), errno);
		goto failed;
	}

	if (rp.status) {
		syslog(LOG_ERR,
			"Getting scan enable failed with status 0x%02x",
			rp.status);
		goto failed;
	}

	if (!dbus_connection_get_object_path_data(connection, path, (void*) &pdata)) {
		syslog(LOG_ERR, "Getting path data failed!");
		goto failed;
	}

	old_data = pdata->path_data;
	pdata->path_data = rp.enable;

	/* If the new page scan flag is different from what we had, send a signal. */
	if((rp.enable & SCAN_PAGE) != (old_data & SCAN_PAGE)) {
		se = (rp.enable & SCAN_PAGE);
		send_property_changed_signal(id, DEV_PROPERTY_PSCAN, DBUS_TYPE_BOOLEAN, &se);
	}
	/* If the new inquity scan flag is different from what we had, send a signal. */
	if ((rp.enable & SCAN_INQUIRY) != (old_data & SCAN_INQUIRY)) {
		se = (rp.enable & SCAN_INQUIRY);
		send_property_changed_signal(id, DEV_PROPERTY_ISCAN, DBUS_TYPE_BOOLEAN, &se);
	}

	dbus_connection_flush(connection);

failed:
	if (dd >= 0)
		close(dd);

	bt_free(local_addr);
}

static DBusMessage* handle_device_set_property_req_pscan(DBusMessage *msg, void *data)
{
	return write_scan_enable(msg, data, TRUE);
}

static DBusMessage* handle_device_set_property_req_iscan(DBusMessage *msg, void *data)
{
	return write_scan_enable(msg, data, FALSE);
}

static DBusMessage* handle_device_list_req(DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply = NULL;
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr      = NULL;
	int sk = -1;
	int i;
	const char array_sig[] = MGR_GET_DEV_REPLY_STRUCT_SIGNATURE;

	/* Create and bind HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't open HCI socket: %s (%d)", strerror(errno), errno);
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		syslog(LOG_ERR, "Can't allocate memory");
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_NO_MEM);
		goto failed;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	/* active bluetooth adapter found */
	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		syslog(LOG_ERR, "Out of memory while calling dbus_message_new_method_return");
		goto failed;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, array_sig, &array_iter);
	dr = dl->dev_req;

	for (i = 0; i < dl->dev_num; i++, dr++) {
		char apath[MAX_PATH_LENGTH];
		char aaddr[18];
		char *paddr = aaddr;
		char *ppath = apath;
		char *ptype;
		const char *flag;
		DBusMessageIter flag_array_iter, struct_iter;
		struct hci_dev_info di;
		hci_map *mp;

		mp = dev_flags_map;
		memset(&di, 0 , sizeof(struct hci_dev_info));
		di.dev_id = dr->dev_id;

		if (ioctl(sk, HCIGETDEVINFO, &di) < 0)
			continue;

		snprintf(apath, sizeof(apath), "%s/%s", DEVICE_PATH, di.name);

		ba2str(&di.bdaddr, aaddr);
		ptype = hci_dtypetostr(di.type);

		dbus_message_iter_open_container(&array_iter,
				DBUS_TYPE_STRUCT, NULL, &struct_iter);

		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &ppath);
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &paddr);
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &ptype);

		if (hci_test_bit(HCI_UP, &dr->dev_opt))
			flag = "UP";
		else
			flag = "DOWN";

		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &flag);

		dbus_message_iter_open_container(&struct_iter,
					DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &flag_array_iter);

		while (mp->str) {
			if (hci_test_bit(mp->val, &dr->dev_opt))
				dbus_message_iter_append_basic(&flag_array_iter, DBUS_TYPE_STRING, &mp->str);
			mp++;
		}
		dbus_message_iter_close_container(&struct_iter, &flag_array_iter);
		dbus_message_iter_close_container(&array_iter, &struct_iter);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

failed:
	if (sk >= 0)
		close(sk);

	if (dl)
		free(dl);

	return reply;
}

/*****************************************************************
 *  
 *  Section reserved to Manager D-Bus services
 *  
 *****************************************************************/
static DBusMessage* handle_default_device_req(DBusMessage *msg, void *data)
{
	char path[MAX_PATH_LENGTH];
	char *pptr = path;
	DBusMessage *reply = NULL;

	if (default_dev < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL) {
		syslog(LOG_ERR, "Out of memory while calling dbus_message_new_method_return");
		goto failed;
	}

	snprintf(path, sizeof(path), "%s/hci%d", DEVICE_PATH, default_dev);
	dbus_message_append_args(reply,
					DBUS_TYPE_STRING, &pptr,
					DBUS_TYPE_INVALID);

failed:
	return reply;
}

static DBusMessage* handle_not_implemented_req(DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);
	const char *iface = dbus_message_get_interface(msg);
	const char *method = dbus_message_get_member(msg);

	syslog(LOG_INFO, "Not Implemented - path %s iface %s method %s",
							path, iface, method);

	return bluez_new_failure_msg(msg, BLUEZ_EDBUS_NOT_IMPLEMENTED);
}

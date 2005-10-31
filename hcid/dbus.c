/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
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
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "glib-ectomy.h"

#include "hcid.h"
#include "dbus.h"

static DBusConnection *connection;
static int up_adapters = 0;

#define TIMEOUT (30 * 1000)		/* 30 seconds */
#define BLUETOOTH_DEVICE_NAME_LEN    (18)
#define BLUETOOTH_DEVICE_ADDR_LEN    (18)
#define MAX_PATH_LENGTH   (64)
#define READ_REMOTE_NAME_TIMEOUT	(25000)
#define MAX_CONN_NUMBER			(10)
#define DEVICE_FLAG_NAME		(16)

#define PINAGENT_SERVICE_NAME BASE_INTERFACE ".PinAgent"
#define PINAGENT_INTERFACE PINAGENT_SERVICE_NAME
#define PIN_REQUEST "PinRequest"
#define PINAGENT_PATH BASE_PATH "/PinAgent"

struct pin_request {
	int dev;
	bdaddr_t bda;
};

typedef DBusMessage* (service_handler_func_t)(DBusMessage *, void *);

struct service_data {
	const char             *name;
	service_handler_func_t *handler_func;
	const char             *signature;
};

struct hci_dbus_data {
	uint16_t id;
};

typedef int register_function_t(DBusConnection *conn, int dft_reg, uint16_t id);
typedef int unregister_function_t(DBusConnection *conn, int unreg_dft, uint16_t id);

const struct service_data *get_hci_table(void);

static int hci_dbus_reg_obj_path(DBusConnection *conn, int dft_reg, uint16_t id);
static int hci_dbus_unreg_obj_path(DBusConnection *conn, int unreg_dft, uint16_t id);

typedef const struct service_data *get_svc_table_func_t(void);

struct profile_obj_path_data {
	const char		*name;
	int			status; /* 1:active  0:disabled */
	int			dft_reg; /* dft path registered */
	register_function_t	*reg_func;
	unregister_function_t	*unreg_func;
	get_svc_table_func_t	*get_svc_table; /* return the service table */
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
}bluez_error_t;

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
	{ BLUEZ_EDBUS_UNKNOWN_PATH,	"Device path is not registered"	},
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
	DBusMessage *reply = NULL;
	const char *error_msg = NULL;

	error_msg = bluez_dbus_error_to_str(ecode);

	if (error_msg) {
		reply = dbus_message_new_error(msg, ERROR_INTERFACE, error_msg);

		dbus_message_iter_init_append(reply, &iter);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32 ,&ecode);
	}

	return reply;
}

/*
 * Object path register/unregister functions 
 *
 */
static struct profile_obj_path_data obj_path_table[] = {
	{ BLUEZ_HCI, 1, 0, hci_dbus_reg_obj_path, hci_dbus_unreg_obj_path, get_hci_table },
	/* add other profiles here */
	{ NULL, 0, 0, NULL, NULL, NULL }
};

/*
 * Device Message handler functions object table declaration
 */
static DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data);
static DBusHandlerResult msg_func_manager(DBusConnection *conn, DBusMessage *msg, void *data);

static DBusMessage* handle_get_devices_req_device(DBusMessage *msg, void *data);
static DBusMessage* handle_get_devices_req_manager(DBusMessage *msg, void *data);
static DBusMessage* handle_not_implemented_req(DBusMessage *msg, void *data);

static const DBusObjectPathVTable obj_dev_vtable = {
	.message_function = &msg_func_device,
	.unregister_function = NULL
};

static const DBusObjectPathVTable obj_mgr_vtable = {
	.message_function = &msg_func_manager,
	.unregister_function = NULL
};

/*
 * Service provided under the path DEVICE_PATH
 * TODO add the handlers
 */
static const struct service_data dev_root_services[] = {
	{ DEV_GET_DEV,		handle_get_devices_req_device,	DEV_GET_DEV_SIGNATURE		},
	{ NULL, NULL, NULL}
};

static const struct service_data dev_services[] = {
	{ DEV_UP,		handle_not_implemented_req,	DEV_UP_SIGNATURE		},
	{ DEV_DOWN,		handle_not_implemented_req,	DEV_DOWN_SIGNATURE		},
	{ DEV_RESET,		handle_not_implemented_req,	DEV_RESET_SIGNATURE		},
	{ DEV_SET_PROPERTY,	handle_not_implemented_req,	DEV_SET_PROPERTY_SIGNATURE	},
	{ DEV_GET_PROPERTY,	handle_not_implemented_req,	DEV_GET_PROPERTY_SIGNATURE	},
	{ NULL, NULL, NULL}
};

/*
 * Manager Message handler functions object table declaration
 *
 */
static const struct service_data mgr_services[] = {
	{ MGR_GET_DEV,		handle_get_devices_req_manager,	MGR_GET_DEV_SIGNATURE	},
	{ MGR_INIT,		handle_not_implemented_req,	NULL			},
	{ MGR_ENABLE,		handle_not_implemented_req,	NULL			},
	{ MGR_DISABLE,		handle_not_implemented_req,	NULL			},
	{ NULL, NULL, NULL }
};

/*
 * HCI Manager Message handler functions object table declaration
 *
 */
static DBusHandlerResult hci_signal_filter (DBusConnection *conn, DBusMessage *msg, void *data);

static DBusMessage* handle_periodic_inq_req(DBusMessage *msg, void *data);
static DBusMessage* handle_cancel_periodic_inq_req(DBusMessage *msg, void *data);
static DBusMessage* handle_inq_req(DBusMessage *msg, void *data);
static DBusMessage* handle_cancel_inq_req(DBusMessage *msg, void *data);
static DBusMessage* handle_role_switch_req(DBusMessage *msg, void *data);
static DBusMessage* handle_remote_name_req(DBusMessage *msg, void *data);
static DBusMessage* handle_display_conn_req(DBusMessage *msg, void *data);
static DBusMessage* handle_auth_req(DBusMessage *msg, void *data);

static const struct service_data hci_services[] = {
	{ HCI_PERIODIC_INQ,		handle_periodic_inq_req,	HCI_PERIODIC_INQ_SIGNATURE		},
	{ HCI_CANCEL_PERIODIC_INQ,	handle_cancel_periodic_inq_req,	HCI_CANCEL_PERIODIC_INQ_SIGNATURE	},
	{ HCI_ROLE_SWITCH,		handle_role_switch_req,		HCI_ROLE_SWITCH_SIGNATURE		},
	{ HCI_INQ,			handle_inq_req,			HCI_INQ_SIGNATURE			},
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

	if (message) {
		msg_type = dbus_message_get_type(message);
		dbus_message_iter_init(message, &iter);
		
		if (msg_type == DBUS_MESSAGE_TYPE_ERROR) {
			dbus_message_iter_get_basic(&iter, &error_msg);

			/* handling WRONG_ARGS_ERROR, DBUS_ERROR_NO_REPLY, DBUS_ERROR_SERVICE_UNKNOWN */
			syslog(LOG_ERR, "%s: %s", dbus_message_get_error_name(message), error_msg);
			hci_send_cmd(req->dev, OGF_LINK_CTL,
					OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);
		} else {
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
				hci_send_cmd(req->dev, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
						PIN_CODE_REPLY_CP_SIZE, &pr);
			}
		}

		dbus_message_unref(message);
	}

	dbus_pending_call_unref(call);
}

static void free_pin_req(void *req)
{
	free(req);
}

static gboolean register_dbus_path(char *path, uint16_t id, const DBusObjectPathVTable *pvtable)
{
	struct hci_dbus_data *data;
	syslog(LOG_INFO,"Registering DBUS Path: %s", path);
	data = malloc(sizeof(struct hci_dbus_data));
	if (data == NULL) {
		syslog(LOG_ERR,"Failed to alloc memory to DBUS path register data (%s)", path);
		return FALSE;
	}
	data->id = id;

	if (!dbus_connection_register_object_path(connection, path, pvtable, data)) {
		syslog(LOG_ERR,"DBUS failed to register %s object", path);
		free(data);
		return FALSE;
	}
	return TRUE;
}

static gboolean unregister_dbus_path(char *path)
{
	void *data;
	syslog(LOG_INFO,"Unregistering DBUS Path: %s", path);
	if (dbus_connection_get_object_path_data(connection, path, &data) && data) 
		free(data);

	if (!dbus_connection_unregister_object_path (connection, path)) {
		syslog(LOG_ERR,"DBUS failed to unregister %s object", path);
		return FALSE;
	}
	return TRUE;
}

void hcid_dbus_request_pin(int dev, struct hci_conn_info *ci)
{
	DBusMessage *message;
	DBusPendingCall *pending = NULL;
	struct pin_request *req;
	uint8_t *addr = (uint8_t *) &ci->bdaddr;
	dbus_bool_t out = ci->out;

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
	dbus_message_unref(message);
	hci_send_cmd(dev, OGF_LINK_CTL,
				OCF_PIN_CODE_NEG_REPLY, 6, &ci->bdaddr);
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

	snprintf(path, sizeof(path), "%s/hci%d/%s", MANAGER_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path,
				BLUEZ_HCI_INTERFACE, BLUEZ_HCI_INQ_START);
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

	return;
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

	snprintf(path, sizeof(path), "%s/hci%d/%s", MANAGER_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path,
				BLUEZ_HCI_INTERFACE, BLUEZ_HCI_INQ_COMPLETE);
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

	return;
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

	snprintf(path, sizeof(path), "%s/hci%d/%s", MANAGER_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path,
				BLUEZ_HCI_INTERFACE, BLUEZ_HCI_INQ_RESULT);
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

	return;
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

	snprintf(path, sizeof(path), "%s/hci%d/%s", MANAGER_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path,
				BLUEZ_HCI_INTERFACE, BLUEZ_HCI_REMOTE_NAME);
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
	dbus_message_unref(message);

	bt_free(local_addr);
	bt_free(peer_addr);

	return;
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

	snprintf(path, sizeof(path), "%s/hci%d/%s", MANAGER_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path,
				BLUEZ_HCI_INTERFACE, BLUEZ_HCI_REMOTE_NAME_FAILED);
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
	dbus_message_unref(message);

	bt_free(local_addr);
	bt_free(peer_addr);

	return;
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

	snprintf(path, sizeof(path), "%s/hci%d/%s", MANAGER_PATH, id, BLUEZ_HCI);

	message = dbus_message_new_signal(path, BLUEZ_HCI_INTERFACE, BLUEZ_HCI_AUTH_COMPLETE);
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

gboolean hcid_dbus_init(void)
{
	struct hci_dbus_data *data;
	DBusError error;

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	if (dbus_error_is_set(&error)) {
		syslog(LOG_ERR, "Can't open system message bus connection: %s\n",
								error.message);
		dbus_error_free(&error);
		return FALSE;
	}

	dbus_bus_request_name(connection, BASE_INTERFACE,
				DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT, &error);

	if (dbus_error_is_set(&error)) {
		syslog(LOG_ERR,"Can't get system message bus name: %s\n",
								error.message);
		dbus_error_free(&error);
		return FALSE;
	}

	data = malloc(sizeof(struct hci_dbus_data));
	if (data == NULL)
		return FALSE;

	data->id = DEVICE_PATH_ID;

	if (!dbus_connection_register_fallback(connection, DEVICE_PATH,
						&obj_dev_vtable, data)) {
		syslog(LOG_ERR, "Can't register %s object", DEVICE_PATH);
		return FALSE;
	}

	data = malloc(sizeof(struct hci_dbus_data));
	if (data == NULL)
		return FALSE;

	data->id = MANAGER_PATH_ID;

	if (!dbus_connection_register_fallback(connection, MANAGER_PATH,
						&obj_mgr_vtable, data)) {
		syslog(LOG_ERR, "Can't register %s object", MANAGER_PATH);
		return FALSE;
	}

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
	char path[MAX_PATH_LENGTH];
	char fst_parent[] = MANAGER_PATH;
	char snd_parent[MAX_PATH_LENGTH];
	char **fst_level = NULL;
	char **snd_level = NULL;
	char *ptr1;
	char *ptr2;
	void *data = NULL;

	if (!connection)
		return;

	if (dbus_connection_get_object_path_data(connection,
				DEVICE_PATH, &data)) {
		if (data) {
			free(data);
			data = NULL;
		}
	}

	if (!dbus_connection_unregister_object_path(connection, DEVICE_PATH))
		syslog(LOG_ERR, "Can't unregister %s object", DEVICE_PATH);

	if (dbus_connection_get_object_path_data(connection,
				MANAGER_PATH, &data)) {
		if (data) {
			free(data);
			data = NULL;
		}
	}

	if (!dbus_connection_unregister_object_path(connection, MANAGER_PATH))
		syslog(LOG_ERR, "Can't unregister %s object", MANAGER_PATH);

	if (dbus_connection_list_registered(connection, fst_parent, &fst_level)) {

		for (; *fst_level; fst_level++) {
			ptr1 = *fst_level;
			snprintf(snd_parent, sizeof(snd_parent), "%s/%s", fst_parent, ptr1);

			if (dbus_connection_list_registered(connection, snd_parent, &snd_level)) {

				if (!(*snd_level)) {
					snprintf(path, sizeof(path), "%s/%s", MANAGER_PATH, ptr1);

					if (dbus_connection_get_object_path_data(connection,
								path, &data)) {
						if (data) {
							free(data);
							data = NULL;
						}
					}

					if (!dbus_connection_unregister_object_path(connection, path))
						syslog(LOG_ERR, "Can't unregister %s object", path);

					continue;
				}

				for (; *snd_level; snd_level++) {
					ptr2 = *snd_level;
					snprintf(path, sizeof(path), "%s/%s/%s", MANAGER_PATH, ptr1, ptr2);

					if (dbus_connection_get_object_path_data(connection,
								path, &data)) {
						if (data) {
							free(data);
							data = NULL;
						}
					}

					if (!dbus_connection_unregister_object_path(connection, path))
						syslog(LOG_ERR, "Can't unregister %s object", path);
				}

				if (*snd_level)
					dbus_free_string_array(snd_level);
			}
		}

		if (*fst_level)
			dbus_free_string_array(fst_level);
	}
}

gboolean hcid_dbus_register_device(uint16_t id) 
{
	char path[MAX_PATH_LENGTH];
	char dev[BLUETOOTH_DEVICE_NAME_LEN];
	const char *pdev = dev;

	snprintf(dev, sizeof(dev), HCI_DEVICE_NAME "%d", id);
	snprintf(path, sizeof(path), "%s/%s", DEVICE_PATH, pdev);

	/* register the default path*/
	return register_dbus_path(path, id, &obj_dev_vtable);
}

gboolean hcid_dbus_unregister_device(uint16_t id)
{
	char dev[BLUETOOTH_DEVICE_NAME_LEN];
	char path[MAX_PATH_LENGTH];
	const char *pdev = dev;

	snprintf(dev, sizeof(dev), HCI_DEVICE_NAME "%d", id);
	snprintf(path, sizeof(path), "%s/%s", DEVICE_PATH, pdev);

	return unregister_dbus_path(path);
}

gboolean hcid_dbus_register_manager(uint16_t id)
{
	char dev[BLUETOOTH_DEVICE_NAME_LEN];
	struct profile_obj_path_data *ptr = obj_path_table;
	DBusMessage *message = NULL;
	const char *pdev = dev;
	DBusMessageIter iter;
	int ret = -1; 

	if (!connection)
		return FALSE;

	for (; ptr->name; ptr++) {
		ret = ptr->reg_func(connection, ptr->dft_reg, id);
		ptr->dft_reg = 1;
	}

	if (!ret)
		up_adapters++;

	message = dbus_message_new_signal(BLUEZ_HCI_PATH,
			BLUEZ_HCI_INTERFACE, BLUEZ_HCI_DEV_ADDED);

	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS remote name message");
		goto failed;
	}

	snprintf(dev, sizeof(dev), HCI_DEVICE_NAME "%d", id);

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING ,&pdev);

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

gboolean hcid_dbus_unregister_manager(uint16_t id)
{
	char dev[BLUETOOTH_DEVICE_NAME_LEN];
	struct profile_obj_path_data *ptr = obj_path_table;
	DBusMessage *message = NULL;
	const char *pdev = dev;
	DBusMessageIter iter;
	int dft_unreg = 0;

	if (!connection)
		return FALSE;

	for (; ptr->name; ptr++) {
		dft_unreg = (up_adapters > 1) ? 0 : 1;
		up_adapters--;
		ptr->unreg_func(connection, dft_unreg, id);

		if (dft_unreg )
			ptr->dft_reg = 0;
	}

	message = dbus_message_new_signal(BLUEZ_HCI_PATH,
			BLUEZ_HCI_INTERFACE, BLUEZ_HCI_DEV_REMOVED);

	if (message == NULL) {
		syslog(LOG_ERR, "Can't allocate D-BUS device removed  message");
		goto failed;
	}

	snprintf(dev, sizeof(dev), HCI_DEVICE_NAME "%d", id);

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING ,&pdev);

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
 * @param dft_reg register the default path(0 or !0)
 * @param id hci device identification
 * @return (0-Success/-1 failure)
 */
static int hci_dbus_reg_obj_path(DBusConnection *conn, int dft_reg, uint16_t id)
{
	char path[MAX_PATH_LENGTH];

	/* register the default path*/
	if (!dft_reg) {
		snprintf(path, sizeof(path), "%s/%s/%s", MANAGER_PATH, HCI_DEFAULT_DEVICE_NAME, BLUEZ_HCI);
		register_dbus_path(path, DEFAULT_DEVICE_PATH_ID, &obj_mgr_vtable);
	}

	/* register the default path*/
	snprintf(path, sizeof(path), "%s/%s%d/%s", MANAGER_PATH, HCI_DEVICE_NAME, id, BLUEZ_HCI);
	register_dbus_path(path, id, &obj_mgr_vtable);

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
static int hci_dbus_unreg_obj_path(DBusConnection *conn, int unreg_dft, uint16_t id) 
{
	int ret = 0;
	char path[MAX_PATH_LENGTH];

	if (unreg_dft) {
		snprintf(path, sizeof(path), "%s/%s/%s", MANAGER_PATH, HCI_DEFAULT_DEVICE_NAME, BLUEZ_HCI);
		unregister_dbus_path(path);
	}

	snprintf(path, sizeof(path), "%s/%s%d/%s", MANAGER_PATH, HCI_DEVICE_NAME, id, BLUEZ_HCI);
	unregister_dbus_path(path);

	return ret;
}

const struct service_data *get_hci_table(void)
{
	return hci_services;
}

/*****************************************************************
 *  
 *  Section reserved to HCI Manaher D-Bus message handlers
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

	if (strcmp(iface, DBUS_INTERFACE_LOCAL) == 0) {
		if (strcmp(method, "Disconnected") == 0)
			ret = DBUS_HANDLER_RESULT_HANDLED;
	} else if (strcmp(iface, DBUS_INTERFACE_DBUS) == 0) {
		if (strcmp(method, "NameOwnerChanged") == 0)
			ret = DBUS_HANDLER_RESULT_HANDLED;

		if (strcmp(method, "NameAcquired") == 0)
			ret = DBUS_HANDLER_RESULT_HANDLED;
	}

	return ret;
}
/*
 * There is only one message handler function for all object paths
 *
 */

static DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct service_data *ptr_handlers = NULL;
	DBusMessage *reply = NULL;
	int type;
	const char *iface;
	const char *method;
	const char *signature;
	const char *path;
	struct hci_dbus_data *dbus_data = data;
	uint32_t result = BLUEZ_EDBUS_UNKNOWN_METHOD;
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint8_t found = 0;

	path = dbus_message_get_path(msg);
	type = dbus_message_get_type(msg);
	iface = dbus_message_get_interface(msg);
	method = dbus_message_get_member(msg);
	signature = dbus_message_get_signature(msg);

	if (strcmp(iface, DEVICE_INTERFACE))
		return ret;

	if (strcmp(path, DEVICE_PATH) > 0) {
		if (dbus_data->id == DEVICE_PATH_ID) {
			/* fallback handling. The child path IS NOT registered */
			reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_UNKNOWN_PATH);
			ret = DBUS_HANDLER_RESULT_HANDLED;
		} else {
			/* hciX code */
		}
	} else {
		/* it's the device path */
		ptr_handlers = dev_root_services;
		found = 1;
	}

	if (found && (type == DBUS_MESSAGE_TYPE_METHOD_CALL) && (method != NULL)) {

		for (; ptr_handlers->name; ptr_handlers++) {
			if (strcmp(method, ptr_handlers->name) == 0) {
				/* resetting unknown method. It's possible handle method overload */
				result = BLUEZ_EDBUS_WRONG_SIGNATURE; 
				if (strcmp(ptr_handlers->signature, signature) == 0) {
					if (ptr_handlers->handler_func) {
						reply = (ptr_handlers->handler_func) (msg, data);
						result = 0; /* resetting wrong signature*/
					} else
						syslog(LOG_INFO, "Service not implemented");

					break;
				}
				
			}
		}

		if (result) {
			reply = bluez_new_failure_msg(msg, result);
		}

		ret = DBUS_HANDLER_RESULT_HANDLED;
	}

	/* send an error or the success reply*/
	if (reply) {
		if (!dbus_connection_send (conn, reply, NULL)) {
			syslog(LOG_ERR, "Can't send reply message!");
		}
		dbus_message_unref (reply);
	}

	return ret;
}

static DBusHandlerResult msg_func_manager(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct service_data *ptr_handlers = NULL;
	DBusMessage *reply = NULL;
	int type;
	const char *iface;
	const char *method;
	const char *signature;
	const char *path;
	const char *rel_path;
	struct hci_dbus_data *dbus_data = data;
	uint32_t result = BLUEZ_EDBUS_UNKNOWN_METHOD;
	DBusHandlerResult ret = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	uint8_t found = 0;

	path = dbus_message_get_path(msg);
	type = dbus_message_get_type(msg);
	iface = dbus_message_get_interface(msg);
	method = dbus_message_get_member (msg);
	signature = dbus_message_get_signature(msg);

	syslog (LOG_INFO, "%s - path:%s, id:0x%X", __PRETTY_FUNCTION__, path, dbus_data->id);

	if (strcmp(iface, MANAGER_INTERFACE))
		return ret;

	if (strcmp(path, MANAGER_PATH) > 0) {
		/* it is device specific path */
		if (dbus_data->id == MANAGER_PATH_ID) {
			/* fallback handling. The child path IS NOT registered */
			reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_UNKNOWN_PATH);
			ret = DBUS_HANDLER_RESULT_HANDLED;
		} else {
			const struct profile_obj_path_data *mgr_child = obj_path_table;
			rel_path = strrchr(path,'/');
			rel_path++;

			if (rel_path) {
				for ( ;mgr_child->name; mgr_child++) {
					if (strcmp(mgr_child->name, rel_path) == 0) {
						ptr_handlers = mgr_child->get_svc_table();
						found = 1;
						break;
					}
				}

			}
		}
	} else {
		/* it's the manager! path */
		ptr_handlers = mgr_services;
		found = 1;
	}

	if (found && (type == DBUS_MESSAGE_TYPE_METHOD_CALL) && (method != NULL)) {

		for (; ptr_handlers->name; ptr_handlers++) {
			if (strcmp(method, ptr_handlers->name) == 0) {
				/* resetting unknown method. It's possible handle method overload */
				result = BLUEZ_EDBUS_WRONG_SIGNATURE; 
				if (strcmp(ptr_handlers->signature, signature) == 0) {
					if (ptr_handlers->handler_func) {
						reply = (ptr_handlers->handler_func)(msg, data);
						result = 0; /* resetting wrong signature*/
					} else 
						syslog(LOG_INFO, "Service not implemented");

					break;
				} 
				
			}
		}

		if (result) {
			reply = bluez_new_failure_msg(msg, result);
		}

		ret = DBUS_HANDLER_RESULT_HANDLED;
	}

	/* send an error or the success reply*/
	if (reply) {
		if (!dbus_connection_send (conn, reply, NULL)) {
			syslog(LOG_ERR, "Can't send reply message!") ;
		}
		dbus_message_unref (reply);
	}

	return ret;
}

static DBusMessage* handle_periodic_inq_req(DBusMessage *msg, void *data)
{
	write_inquiry_mode_cp inq_mode;
	periodic_inquiry_cp inq_param;
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	struct hci_dbus_data *dbus_data = data;
	uint8_t length;
	uint8_t max_period;
	uint8_t min_period;
	int dd = -1;
	int dev_id = -1;

	if (dbus_data->id == DEFAULT_DEVICE_PATH_ID) {
		dev_id = hci_get_route(NULL);
		if (dev_id < 0) {
			syslog(LOG_ERR, "Bluetooth device is not available");
			reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
			goto failed;
		
		}
	} else
		dev_id =  dbus_data->id;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &length);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &min_period);
	dbus_message_iter_next(&iter);	
	dbus_message_iter_get_basic(&iter, &max_period);

	if (length >= min_period || min_period >= max_period) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);
		goto failed;
	}

	inq_param.num_rsp = 100;
	inq_param.length  = length;

	inq_param.max_period = max_period;
	inq_param.min_period = min_period;

	/* General/Unlimited Inquiry Access Code (GIAC) */
	inq_param.lap[0] = 0x33;
	inq_param.lap[1] = 0x8b;
	inq_param.lap[2] = 0x9e;

	inq_mode.mode = 1; //INQUIRY_WITH_RSSI;

	if (hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_INQUIRY_MODE,
				WRITE_INQUIRY_MODE_CP_SIZE, &inq_mode) < 0) {
		syslog(LOG_ERR, "Can't set inquiry mode:%s.", strerror(errno));
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_PERIODIC_INQUIRY,
				PERIODIC_INQUIRY_CP_SIZE, &inq_param) < 0) {
		syslog(LOG_ERR, "Can't send HCI commands:%s.", strerror(errno));
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
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
	struct hci_dbus_data *dbus_data = data;
	int dd = -1;
	int dev_id = -1;

	if (dbus_data->id == DEFAULT_DEVICE_PATH_ID) {
		dev_id = hci_get_route(NULL);
		if (dev_id < 0) {
			syslog(LOG_ERR, "Bluetooth device is not available");
			reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
			goto failed;
		}
	} else
		dev_id = dbus_data->id;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_EXIT_PERIODIC_INQUIRY, 0 , NULL) < 0) {
		syslog(LOG_ERR, "Send hci command failed.");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
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
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	inquiry_cp cp;
	evt_cmd_status rp;
	struct hci_request rq;
	struct hci_dbus_data *dbus_data = data;
	int dev_id = -1, dd = -1;
	int8_t length;
	int8_t num_rsp;

	if (dbus_data->id == DEFAULT_DEVICE_PATH_ID) {
		if ((dev_id = hci_get_route(NULL)) < 0) {
			syslog(LOG_ERR, "Bluetooth device is not available");
			reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
			goto failed;
		}
	} else
		dev_id = dbus_data->id;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &length);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &num_rsp);

	if ((length <= 0) || (num_rsp <= 0)) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_WRONG_PARAM);
		goto failed;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "Unable to open device %d: %s", dev_id, strerror(errno));
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	memset(&cp, 0, sizeof(cp));
	cp.lap[0]  = 0x33;
	cp.lap[1]  = 0x8b;
	cp.lap[2]  = 0x9e;
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
		syslog(LOG_ERR, "Unable to start inquiry: %s", strerror(errno));
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
	int dev_id = -1, dd = -1;

	if (dbus_data->id == DEFAULT_DEVICE_PATH_ID) {
		if ((dev_id = hci_get_route(NULL)) < 0) {
			syslog(LOG_ERR, "Bluetooth device is not available");
			reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
			goto failed;
		}
	} else
		dev_id = dbus_data->id;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "Unable to open device %d: %s", dev_id, strerror(errno));
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf = OGF_LINK_CTL;
	rq.ocf = OCF_INQUIRY_CANCEL;

	if (hci_send_req(dd, &rq, 100) < 0) {
		syslog(LOG_ERR, "Unable to cancel inquiry: %s", strerror(errno));
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
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
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	char *str_bdaddr = NULL;
	struct hci_dbus_data *dbus_data = data;
	bdaddr_t bdaddr;
	uint8_t role;
	int dev_id = -1;
	int dd = -1;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &str_bdaddr);
	dbus_message_iter_next(&iter);
	dbus_message_iter_get_basic(&iter, &role);

	str2ba(str_bdaddr, &bdaddr);

	dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);

	if (dev_id < 0) {
		syslog(LOG_ERR, "Bluetooth device failed\n");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	if (dbus_data->id != DEFAULT_DEVICE_PATH_ID && dbus_data->id != dev_id) {
		syslog(LOG_ERR, "Connection not found\n");
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_CONN_NOT_FOUND);
		goto failed;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "HCI device open failed\n");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
		goto failed;
	}

	if (hci_switch_role(dd, &bdaddr, role, 10000) < 0) {
		syslog(LOG_ERR, "Switch role request failed\n");
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
	} else {
		uint8_t result = 0;
		/* return TRUE to indicate that operation was completed */
		reply = dbus_message_new_method_return(msg);
		dbus_message_iter_init_append(reply, &iter);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_BYTE, &result);
	}

failed:
	return reply;
}

static DBusMessage* handle_remote_name_req(DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	struct hci_dbus_data *dbus_data = data;
	int dev_id = -1;
	int dd = -1;
	const char *str_bdaddr;
	bdaddr_t bdaddr;
	struct hci_request rq;
	remote_name_req_cp cp;
	evt_cmd_status rp;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &str_bdaddr);

	str2ba(str_bdaddr, &bdaddr);

	if (dbus_data->id == DEFAULT_DEVICE_PATH_ID) {
		dev_id = hci_get_route(&bdaddr);
		if (dev_id  < 0) {
			syslog(LOG_ERR, "Bluetooth device is not available");
			reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
			goto failed;
		}
	} else
		dev_id = dbus_data->id;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		syslog(LOG_ERR, "Unable to open device %d: %s", dev_id, strerror(errno));
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
		syslog(LOG_ERR, "Unable to send remote name request: %s", strerror(errno));
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
	int dev_id = -1;
	int sk = -1;
	int i;

	if (dbus_data->id == DEFAULT_DEVICE_PATH_ID) {
		dev_id = hci_get_route(NULL);
		if (dev_id < 0) {
			syslog(LOG_ERR, "Bluetooth device is not available");
			reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_ENODEV);
			goto failed;
		}
	} else {
		dev_id = dbus_data->id;
	}

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

	cl->dev_id = dev_id;
	cl->conn_num = MAX_CONN_NUMBER;
	ci = cl->conn_info;

	if (ioctl(sk, HCIGETCONNLIST, (void *) cl) < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

	reply = dbus_message_new_method_return(msg);
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
	DBusMessageIter iter;
	DBusMessage *reply = NULL;
	char *str_bdaddr = NULL;
	struct hci_dbus_data *dbus_data = data;
	struct hci_conn_info_req *cr = NULL;
	bdaddr_t bdaddr;
	int dev_id = -1;
	int dd = -1;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &str_bdaddr);
	str2ba(str_bdaddr, &bdaddr);

	dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);

	if (dev_id < 0) {
		reply = bluez_new_failure_msg(msg, BLUEZ_EDBUS_CONN_NOT_FOUND);
		goto failed;
	}

	if (dbus_data->id != DEFAULT_DEVICE_PATH_ID && dbus_data->id != dev_id) {
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
		syslog(LOG_ERR, "Unable to send authentication request: %s", strerror(errno));
		reply = bluez_new_failure_msg(msg, BLUEZ_ESYSTEM_OFFSET + errno);
		goto failed;
	}

failed:
	if (dd >= 0)
		close(dd);

	if (cr)
		free(cr);

	return reply;
}

/*****************************************************************
 *  
 *  Section reserved to Manager D-Bus message handlers
 *  
 *****************************************************************/
static DBusMessage* handle_get_devices_req_device(DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessageIter flag_array_iter;
	DBusMessageIter  struct_iter;
	DBusMessage *reply = NULL;
	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr      = NULL;
	struct hci_dev_info di;
	int sk = -1;
	int i;
	char aname[BLUETOOTH_DEVICE_NAME_LEN+1];
	char aaddr[BLUETOOTH_DEVICE_ADDR_LEN];
	char aflag[DEVICE_FLAG_NAME];
	char *paddr = aaddr;
	char *pname = aname;
	char *pflag = aflag;
	char *ptype;
	const char array_sig[] = DEV_GET_DEV_REPLY_STRUCT_SIGNATURE;
	hci_map *mp;

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
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, array_sig, &array_iter);
	dr = dl->dev_req;

	for (i = 0; i < dl->dev_num; i++, dr++) {
		mp = dev_flags_map;
		memset(&di, 0 , sizeof(struct hci_dev_info));
		di.dev_id = dr->dev_id;

		if (ioctl(sk, HCIGETDEVINFO, &di) < 0)
			continue;

		strncpy(aname, di.name, BLUETOOTH_DEVICE_NAME_LEN);
		aname[BLUETOOTH_DEVICE_NAME_LEN] = '\0';

		ba2str(&di.bdaddr, aaddr);
		ptype = hci_dtypetostr(di.type);

		dbus_message_iter_open_container(&array_iter,
				DBUS_TYPE_STRUCT, NULL, &struct_iter);

		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &pname);
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &paddr);
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &ptype);

		if (hci_test_bit(HCI_UP, &dr->dev_opt)) {
			sprintf(pflag, "%s", "UP");
		} else {
			sprintf(pflag, "%s", "DOWN");
		}
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &pflag);

		dbus_message_iter_open_container(&struct_iter,
					DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &flag_array_iter);

		while (mp->str) {
			if (hci_test_bit(mp->val, &dr->dev_opt)) {
				sprintf(pflag, "%s", mp->str);
				dbus_message_iter_append_basic(&flag_array_iter, DBUS_TYPE_STRING, &pflag);
			}
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


static DBusMessage* handle_get_devices_req_manager(DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessageIter  struct_iter;
	DBusMessage *reply = NULL;

	struct hci_dev_list_req *dl = NULL;
	struct hci_dev_req *dr      = NULL;
	struct hci_dev_info di;
	int sk = -1;
	int i;

	char aname[BLUETOOTH_DEVICE_NAME_LEN];
	char aaddr[BLUETOOTH_DEVICE_ADDR_LEN];
	char *paddr = aaddr;
	char *pname = aname;
	const char array_sig[] = HCI_DEVICE_STRUCT_SIGNATURE;

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
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, array_sig, &array_iter);
	dr = dl->dev_req;

	for (i = 0; i < dl->dev_num; i++, dr++) {
		if (!hci_test_bit(HCI_UP, &dr->dev_opt))
			continue;

		memset(&di, 0 , sizeof(struct hci_dev_info));
		di.dev_id = dr->dev_id;

		if (ioctl(sk, HCIGETDEVINFO, &di) < 0)
			continue;

		strcpy(aname, di.name);
		ba2str(&di.bdaddr, aaddr);

		dbus_message_iter_open_container(&array_iter,
					DBUS_TYPE_STRUCT, NULL, &struct_iter);

		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &pname);
		dbus_message_iter_append_basic(&struct_iter, DBUS_TYPE_STRING, &paddr);

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

static DBusMessage* handle_not_implemented_req(DBusMessage *msg, void *data) 
{
	const char *path = dbus_message_get_path(msg);
	const char *iface = dbus_message_get_interface(msg);
	const char *method = dbus_message_get_member(msg);

	syslog(LOG_INFO, "Not Implemented - path %s iface %s method %s",
							path, iface, method);

	return NULL;
}

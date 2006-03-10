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
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"

typedef struct  {
	uint32_t code;
	const char *str;
} bluez_error_t;

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
		info("%s - msg:%s", __PRETTY_FUNCTION__, strerror(raw_code));
		return strerror(raw_code);
	} else if (ecode & BLUEZ_EDBUS_OFFSET) {
		/* D-Bus error */
		for (ptr = dbus_error_array; ptr->code; ptr++) {
			if (ptr->code == ecode) {
				info("%s - msg:%s", __PRETTY_FUNCTION__, ptr->str);
				return ptr->str;
			}
		}
	} else {
		/* BLUEZ_EBT_OFFSET - Bluetooth HCI errors */
		for (ptr = hci_error_array; ptr->code; ptr++) {
			if (ptr->code == ecode) {
				info("%s - msg:%s", __PRETTY_FUNCTION__, ptr->str);
				return ptr->str;
			}
		}
	}

	return NULL;
}

DBusHandlerResult bluez_new_failure_msg(DBusConnection *conn, DBusMessage *msg, const uint32_t ecode)
{
	DBusMessageIter iter;
	DBusMessage *reply;
	const char *error_msg;

	error_msg = bluez_dbus_error_to_str(ecode);
	if (!error_msg)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	reply = dbus_message_new_error(msg, ERROR_INTERFACE, error_msg);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32 ,&ecode);

	return send_reply_and_unref(conn, reply);
}

DBusHandlerResult error_failed(DBusConnection *conn, DBusMessage *msg, int err)
{
	const char *str = strerror(err);

	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".Failed", str));
}

DBusHandlerResult error_invalid_arguments(DBusConnection *conn, DBusMessage *msg)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".InvalidArguments",
							"Invalid arguments"));
}

DBusHandlerResult error_not_authorized(DBusConnection *conn, DBusMessage *msg)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NotAuthorized",
							"Not authorized"));
}

DBusHandlerResult error_out_of_memory(DBusConnection *conn, DBusMessage *msg)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".OutOfMemory",
							"Out of memory"));
}

DBusHandlerResult error_no_such_adapter(DBusConnection *conn, DBusMessage *msg)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NoSuchAdapter",
							"No such adapter"));
}

DBusHandlerResult error_unknown_address(DBusConnection *conn, DBusMessage *msg)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".UnknownAddress",
							"Unknown address"));
}

DBusHandlerResult error_not_available(DBusConnection *conn, DBusMessage *msg)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NotAvailable",
							"Not available"));
}

DBusHandlerResult error_not_connected(DBusConnection *conn, DBusMessage *msg)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NotConnected",
							"Not connected"));
}

DBusHandlerResult error_unsupported_major_class(DBusConnection *conn, DBusMessage *msg)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".UnsupportedMajorClass",
							"Unsupported Major Class"));
}

static DBusHandlerResult error_already_exists(DBusConnection *conn, DBusMessage *msg, const char *str)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".AlreadyExists", str));
}

static DBusHandlerResult error_does_not_exist(DBusConnection *conn, DBusMessage *msg, const char *str)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".DoesNotExist", str));
}

static DBusHandlerResult error_in_progress(DBusConnection *conn, DBusMessage *msg, const char *str)
{
	return send_reply_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".InProgress", str));
}

DBusHandlerResult error_bonding_already_exists(DBusConnection *conn, DBusMessage *msg)
{
	return error_already_exists(conn, msg, "Bonding already exists");
}

DBusHandlerResult error_bonding_does_not_exist(DBusConnection *conn, DBusMessage *msg)
{
	return error_does_not_exist(conn, msg, "Bonding does not exist");
}

DBusHandlerResult error_bonding_in_progress(DBusConnection *conn, DBusMessage *msg)
{
	return error_in_progress(conn, msg, "Bonding in progress");
}

DBusHandlerResult error_discover_in_progress(DBusConnection *conn, DBusMessage *msg)
{
	return error_in_progress(conn, msg, "Discover in progress");
}

DBusHandlerResult error_passkey_agent_already_exists(DBusConnection *conn, DBusMessage *msg)
{
	return error_already_exists(conn, msg, "Passkey agent already exists");
}

DBusHandlerResult error_passkey_agent_does_not_exist(DBusConnection *conn, DBusMessage *msg)
{
	return error_does_not_exist(conn, msg, "Passkey agent does not exist");
}

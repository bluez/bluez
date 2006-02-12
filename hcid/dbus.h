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

#ifndef __H_BLUEZ_DBUS_H__
#define __H_BLUEZ_DBUS_H__

#define __END_SIG__ DBUS_TYPE_INVALID_AS_STRING

#define BASE_PATH		"/org/bluez"
#define BASE_INTERFACE		"org.bluez"

#define DEVICE_PATH		BASE_PATH "/Device"
#define DEVICE_INTERFACE	BASE_INTERFACE ".Device"

#define MANAGER_PATH		BASE_PATH "/Manager"
#define MANAGER_INTERFACE	BASE_INTERFACE ".Manager"

#define ERROR_INTERFACE		BASE_INTERFACE ".Error"

#define MANAGER_PATH_MASK	(1 << 15)
#define DEVICE_PATH_MASK	(1 << 14)

/* /org/bluez/Manager */
#define MANAGER_ROOT_ID		MANAGER_PATH_MASK

/* /org/bluez/Device */
#define DEVICE_ROOT_ID		DEVICE_PATH_MASK

/* E.g. /org/bluez/Device/hci0 */
#define DEVICE_PATH_ID		(DEVICE_PATH_MASK | 0x0001)

#define INVALID_PATH_ID		0xFFFF
#define INVALID_DEV_ID		0xFFFF

#define MAX_PATH_LENGTH		64

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

DBusHandlerResult msg_func_device(DBusConnection *conn, DBusMessage *msg, void *data);
DBusHandlerResult msg_func_manager(DBusConnection *conn, DBusMessage *msg, void *data);

DBusMessage *bluez_new_failure_msg(DBusMessage *msg, const uint32_t ecode);

DBusMessage *dev_signal_factory(const int devid, const char *prop_name, const int first, ...);

DBusConnection *get_dbus_connection(void);

int get_default_dev_id(void);

/*======================================================================== 
    BlueZ D-Bus Manager service definitions "/org/bluez/Manager"
 *========================================================================*/

#define MGR_DEVICE_LIST		"DeviceList"
#define MGR_DEFAULT_DEVICE	"DefaultDevice"

/* Signals sent in the Manager path */
#define BLUEZ_MGR_DEV_ADDED		"DeviceAdded"
#define BLUEZ_MGR_DEV_REMOVED		"DeviceRemoved"

/* Manager Signatures */
#define MGR_DEVICE_LIST_SIGNATURE		__END_SIG__
#define MGR_DEFAULT_DEVICE_SIGNATURE		__END_SIG__

#define MGR_REPLY_DEVICE_LIST_SIGNATURE		DBUS_TYPE_ARRAY_AS_STRING \
						__END_SIG__

/*======================================================================== 
    BlueZ D-Bus Device path definitions "/org/bluez/Device"
 *========================================================================*/
#define DEV_GET_ADDRESS			"GetAddress"
#define DEV_GET_ALIAS			"GetAlias"
#define DEV_GET_COMPANY			"GetCompany"
#define DEV_GET_DISCOVERABLE_TO		"GetDiscoverableTimeOut"
#define DEV_GET_FEATURES		"GetFeatures"
#define DEV_GET_MANUFACTURER		"GetManufacturer"
#define DEV_GET_MODE			"GetMode"
#define DEV_GET_NAME			"GetName"
#define DEV_GET_REVISION		"GetRevision"
#define DEV_GET_VERSION			"GetVersion"
#define DEV_IS_CONNECTABLE		"IsConnectable"
#define DEV_IS_DISCOVERABLE		"IsDiscoverable"
#define DEV_SET_ALIAS			"SetAlias"
#define DEV_SET_CLASS			"SetClass"
#define DEV_SET_DISCOVERABLE_TO		"SetDiscoverableTimeOut"
#define DEV_SET_MODE			"SetMode"
#define DEV_SET_NAME			"SetName"
#define DEV_DISCOVER			"Discover"
#define DEV_DISCOVER_CACHE		"DiscoverCache"
#define DEV_DISCOVER_CANCEL		"DiscoverCancel"
#define DEV_DISCOVER_SERVICE		"DiscoverService"
#define DEV_LAST_SEEN			"LastSeen"
#define DEV_LAST_USED			"LastUsed"
#define DEV_REMOTE_ALIAS		"RemoteAlias"
#define DEV_REMOTE_NAME			"RemoteName"
#define DEV_REMOTE_VERSION		"RemoteVersion"
#define DEV_CREATE_BONDING		"CreateBonding"
#define DEV_LIST_BONDINGS		"ListBondings"
#define DEV_HAS_BONDING_NAME		"HasBonding"
#define DEV_REMOVE_BONDING		"RemoveBonding"
#define DEV_PIN_CODE_LENGTH		"PinCodeLength"
#define DEV_ENCRYPTION_KEY_SIZE		"EncryptionKeySize"

/*FIXME: maybe this section can be moved to a internal header file */
/* Device service signature */
#define DEV_GET_ADDRESS_SIGNATURE			__END_SIG__
#define DEV_GET_ALIAS_SIGNATURE				DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_GET_COMPANY_SIGNATURE			__END_SIG__
#define DEV_GET_DISCOVERABLE_TO_SIGNATURE		__END_SIG__
#define DEV_GET_FEATURES_SIGNATURE			__END_SIG__
#define DEV_GET_MANUFACTURER_SIGNATURE			__END_SIG__
#define DEV_GET_MODE_SIGNATURE				__END_SIG__
#define DEV_GET_NAME_SIGNATURE				__END_SIG__
#define DEV_GET_REVISION_SIGNATURE			__END_SIG__
#define DEV_GET_VERSION_SIGNATURE			__END_SIG__
#define DEV_IS_CONNECTABLE_SIGNATURE			__END_SIG__
#define DEV_IS_DISCOVERABLE_SIGNATURE			__END_SIG__
#define DEV_SET_ALIAS_SIGNATURE				DBUS_TYPE_STRING_AS_STRING \
							DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_SET_CLASS_SIGNATURE				DBUS_TYPE_STRING_AS_STRING \
							DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_SET_DISCOVERABLE_TO_SIGNATURE		DBUS_TYPE_UINT32_AS_STRING \
							__END_SIG__
#define DEV_SET_MODE_SIGNATURE				DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_SET_NAME_SIGNATURE				DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_DISCOVER_SIGNATURE				__END_SIG__
#define DEV_DISCOVER_CACHE_SIGNATURE			__END_SIG__
#define DEV_DISCOVER_CANCEL_SIGNATURE			__END_SIG__
#define DEV_DISCOVER_SERVICE_SIGNATURE			DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_LAST_SEEN_SIGNATURE				DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_LAST_USED_SIGNATURE				DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_REMOTE_ALIAS_SIGNATURE			DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_REMOTE_NAME_SIGNATURE			DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_REMOTE_VERSION_SIGNATURE			DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_CREATE_BONDING_SIGNATURE			DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_LIST_BONDINGS_SIGNATURE			__END_SIG__
#define DEV_HAS_BONDING_SIGNATURE			DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_REMOVE_BONDING_SIGNATURE			DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_PIN_CODE_LENGTH_SIGNATURE			DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__
#define DEV_ENCRYPTION_KEY_SIZE_SIGNATURE		DBUS_TYPE_STRING_AS_STRING \
							__END_SIG__


/* Signals sent in the Manager path */
#define	DEV_SIG_MODE_CHANGED		"ModeChanged"
#define DEV_SIG_NAME_CHANGED		"NameChanged"
#define DEV_SIG_ALIAS_CHANGED		"AliasChanged"
#define DEV_SIG_REMOTE_NAME		"RemoteName"
#define DEV_SIG_REMOTE_NAME_FAILED	"RemoteNameFailed"
#define DEV_SIG_REMOTE_ALIAS		"RemoteAlias"
#define DEV_SIG_REMOTE_VERSION		"RemoteVersion"
#define DEV_SIG_BONDING_CREATED		"BondingCreated"
#define DEV_SIG_BONDING_FAILED		"BondingFailed"
#define DEV_SIG_BONDING_REMOVED		"BondingRemoved"
#define DEV_SIG_DISCOVER_START		"DiscoverStart"
#define DEV_SIG_DISCOVER_COMPLETE	"DiscoverComplete"
#define DEV_SIG_DISCOVER_RESULT		"DiscoverResult"

/* FIXME: Change to string
 * Scanning modes, used by DEV_SET_MODE
 * off: remote devices are not allowed to find or connect to this device
 * connectable: remote devices are allowed to connect, but they are not
 *              allowed to find it.
 * discoverable: remote devices are allowed to connect and find this device
 */
#define MODE_OFF		0x00	
#define MODE_CONNECTABLE	0x01	
#define MODE_DISCOVERABLE	0x02	


/* BLUEZ_DBUS_ERROR 
 * EFailed error messages signature is : su
 * Where the first argument is a string(error message description),
 * the last  is a uint32 that contains the error class(system, dbus or hci). */

/* Error code offsets */
#define BLUEZ_EBT_OFFSET		(0x00000000) /* see Bluetooth error code */
#define BLUEZ_EBT_EXT_OFFSET		(0x00000100)
#define BLUEZ_EDBUS_OFFSET		(0x00010000)
#define BLUEZ_ESYSTEM_OFFSET		(0x00020000)
#define BLUEZ_EFUTURE_OFFSET		(0x00040000)

/* D-Bus error code, class BLUEZ_EDBUS_OFFSET */
#define BLUEZ_EDBUS_UNKNOWN_METHOD	(0x01 + BLUEZ_EDBUS_OFFSET)
#define BLUEZ_EDBUS_WRONG_SIGNATURE	(0x02 + BLUEZ_EDBUS_OFFSET)
#define BLUEZ_EDBUS_WRONG_PARAM		(0x03 + BLUEZ_EDBUS_OFFSET)
#define BLUEZ_EDBUS_RECORD_NOT_FOUND	(0x04 + BLUEZ_EDBUS_OFFSET)
#define BLUEZ_EDBUS_NO_MEM   		(0x05 + BLUEZ_EDBUS_OFFSET)
#define BLUEZ_EDBUS_CONN_NOT_FOUND	(0x06 + BLUEZ_EDBUS_OFFSET)
#define BLUEZ_EDBUS_UNKNOWN_PATH	(0x07 + BLUEZ_EDBUS_OFFSET)
#define BLUEZ_EDBUS_NOT_IMPLEMENTED	(0x08 + BLUEZ_EDBUS_OFFSET)

/* D-Bus error code, class BLUEZ_ESYSTEM_OFFSET */
#define BLUEZ_ESYSTEM_ENODEV		(ENODEV + BLUEZ_ESYSTEM_OFFSET)

/* BLUEZ_DBUS_ERR_NO_MEMORY */
#define BLUEZ_DBUS_ERR_NO_MEMORY_STR	"No memory"

#endif /* __H_BLUEZ_DBUS_H__ */

/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */
 
#define __END_SIG__ DBUS_TYPE_INVALID_AS_STRING

#define BASE_PATH		"/org/bluez"
#define BASE_INTERFACE		"org.bluez"

#define DEVICE_PATH		BASE_PATH "/Device"
#define DEVICE_INTERFACE	BASE_INTERFACE ".Device"

#define MANAGER_PATH		BASE_PATH "/Manager"
#define MANAGER_INTERFACE	BASE_INTERFACE ".Manager"

#define ERROR_INTERFACE		BASE_INTERFACE ".Error"

#define ERROR_UNKNOWN_HCI_COMMAND				0x01
#define ERROR_UNKNOWN_CONNECTION_IDENTIFIER			0x02
#define ERROR_HARDWARE_FAILURE					0x03
#define ERROR_PAGE_TIMEOUT					0x04
#define ERROR_AUTHENTICATION_FAILURE				0x05
#define ERROR_PIN_OR_KEY_MISSING				0x06
#define ERROR_MEMORY_CAPACITY_EXCEEDED				0x07
#define ERROR_CONNECTION_TIMEOUT				0x08
#define ERROR_CONNECTION_LIMIT_EXCEEDED				0x09
#define ERROR_SYNCHRONOUS_CONNECTION_LIMIT_EXCEEDED		0x0a
#define ERROR_ACL_CONNECTION_ALREADY_EXISTS			0x0b
#define ERROR_COMMAND_DISALLOWED				0x0c
#define ERROR_CONNECTION_REJECTED_DUE_TO_LIMITED_RESOURCES	0x0d
#define ERROR_CONNECTION_REJECTED_DUE_TO_SECURITY_REASONS	0x0e
#define ERROR_CONNECTION_REJECTED_DUE_TO_UNACCEPTABLE_BDADDR	0x0f
#define ERROR_CONNECTION_ACCEPT_TIMEOUT_EXCEEDED		0x10
#define ERROR_UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE		0x11
#define ERROR_INVALID_HCI_COMMAND_PARAMETERS			0x12
#define ERROR_REMOTE_USER_TERMINATED_CONNECTION			0x13
#define ERROR_REMOTE_DEVICE_TERMINATED_CONNECTION_DUE_TO	0x14

#define DEFAULT_DEVICE_PATH_ID 		(0xFFFF)
#define MANAGER_PATH_ID			(0xFFFE)
#define DEVICE_PATH_ID			(0xFFFD)

#define HCI_DEFAULT_DEVICE_NAME		"default"
#define HCI_DEVICE_NAME			"hci"

/*======================================================================== 
    BlueZ D-Bus Device service definitions "/org/bluez/Device"
 *========================================================================*/
#define DEV_UP				"Up"
#define DEV_DOWN			"Down"
#define DEV_RESET			"Reset"
#define DEV_SET_PROPERTY		"SetProperty"
#define DEV_GET_PROPERTY		"GetProperty"

#define DEV_UP_SIGNATURE		__END_SIG__
#define DEV_DOWN_SIGNATURE		__END_SIG__
#define DEV_RESET_SIGNATURE		__END_SIG__
#define DEV_SET_PROPERTY_SIGNATURE	__END_SIG__
#define DEV_GET_PROPERTY_SIGNATURE	__END_SIG__

/*======================================================================== 
    BlueZ D-Bus Manager service definitions "/org/bluez/Manager"
 *========================================================================*/

 /* ===== Manager definitions, services under DEVICE_PATH ===== */
#define MGR_GET_DEV			"DeviceList"
#define MGR_INIT			"Init"

/* Enable/Disable services controller, pan, serial, ... */
#define MGR_ENABLE			"Enable"
#define MGR_DISABLE			"Disable"

//signatures
#define MGR_GET_DEV_SIGNATURE			__END_SIG__

/* yya(ss)*/
#define MGR_GET_DEV_REPLY_SIGNATURE		DBUS_TYPE_BYTE_AS_STRING\
						DBUS_TYPE_BYTE_AS_STRING\
						DBUS_TYPE_ARRAY_AS_STRING\
						HCI_DEVICE_STRUCT_SIGNATURE\
						__END_SIG__

/* ===== HCI definitions ===== */
#define BLUEZ_HCI			"Controller"
#define BLUEZ_HCI_PATH			MANAGER_PATH "/" BLUEZ_HCI
#define BLUEZ_HCI_INTERFACE		MANAGER_INTERFACE "." BLUEZ_HCI

//HCI signals
#define BLUEZ_HCI_INQ_START		"InquiryStart"
#define BLUEZ_HCI_INQ_COMPLETE		"InquiryComplete"
#define BLUEZ_HCI_INQ_RESULT		"InquiryResult"
#define BLUEZ_HCI_REMOTE_NAME		"RemoteName"

//HCI Provided services
#define HCI_PERIODIC_INQ		"PeriodicInquiry"
#define HCI_CANCEL_PERIODIC_INQ		"CancelPeriodic"
#define HCI_INQ				"Inquiry"
#define HCI_ROLE_SWITCH			"RoleSwitch"


#define HCI_PERIODIC_INQ_SIGNATURE			DBUS_TYPE_BYTE_AS_STRING\
							DBUS_TYPE_BYTE_AS_STRING\
							DBUS_TYPE_BYTE_AS_STRING\
							__END_SIG__

#define HCI_CANCEL_PERIODIC_INQ_SIGNATURE		__END_SIG__

#define HCI_INQ_SIGNATURE				DBUS_TYPE_BYTE_AS_STRING\
							DBUS_TYPE_BYTE_AS_STRING\
							DBUS_TYPE_UINT16_AS_STRING\
							__END_SIG__

#define HCI_ROLE_SWITCH_SIGNATURE			DBUS_TYPE_STRING_AS_STRING\
							DBUS_TYPE_BYTE_AS_STRING\
							__END_SIG__

#define HCI_DEVICE_STRUCT_SIGNATURE			DBUS_STRUCT_BEGIN_CHAR_AS_STRING\
							DBUS_TYPE_STRING_AS_STRING\
							DBUS_TYPE_STRING_AS_STRING\
							DBUS_STRUCT_END_CHAR_AS_STRING

#define HCI_INQ_REPLY_SIGNATURE				DBUS_STRUCT_BEGIN_CHAR_AS_STRING\
							DBUS_TYPE_STRING_AS_STRING\
							DBUS_TYPE_UINT32_AS_STRING\
							DBUS_TYPE_UINT16_AS_STRING\
							DBUS_STRUCT_END_CHAR_AS_STRING\
							__END_SIG__

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

/* D-Bus error code, class BLUEZ_ESYSTEM_OFFSET */
#define BLUEZ_ESYSTEM_ENODEV		(ENODEV + BLUEZ_ESYSTEM_OFFSET)

/* BLUEZ_DBUS_ERR_NO_MEMORY */
#define BLUEZ_DBUS_ERR_NO_MEMORY_STR	"No memory"

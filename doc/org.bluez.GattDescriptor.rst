========================
org.bluez.GattDescriptor
========================

--------------------------------------------
BlueZ D-Bus GattDescriptor API documentation
--------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

GATT local/server and remote/client descriptor attribute representation
share the same high-level D-Bus API.

Local/Server refers to GATT based descriptors exported by a plugin or an
external application.

Remote/Client refers to GATT descriptors exported by the peer.

Interface
=========

Client
------

:Service:	org.bluez
:Interface:	org.bluez.GattDescriptor1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/service#/char#/descriptor#

Server
------

:Service:	unique name
:Interface:	org.bluez.GattDescriptor1
:Object path:	freely definable

Methods
-------

array{byte} ReadValue(dict flags)
`````````````````````````````````

Issues a request to read the value of the descriptor and returns the value if
the operation was successful.

Possible options:

:uint16 offset:

	Read start offset in bytes.

:object device (server only):

	Device object.

:string link:

	Link type (Server only).

	Possible values:

	:"BR/EDR":
	:"LE":

Possible Errors:

:org.bluez.Error.Failed:
:org.bluez.Error.InProgress:
:org.bluez.Error.NotPermitted:
:org.bluez.Error.NotAuthorized:
:org.bluez.Error.NotSupported:

void WriteValue(array{byte} value, dict flags)
``````````````````````````````````````````````

Issues a request to write the value of the descriptor.

Possible flags:

:uint16 offset:

	Write start offset in bytes.

:uint16 mtu:

	Exchanged MTU (Server only).

:object device:

	Device path (Server only).

:string link:

	Link type (Server only).

	Possible values:

	:"BR/EDR":
	:"LE":

:boolean prepare-authorize:

	True if prepare authorization request.

Possible Errors:

:org.bluez.Error.Failed:
:org.bluez.Error.InProgress:
:org.bluez.Error.NotPermitted:
:org.bluez.Error.InvalidValueLength:
:org.bluez.Error.NotAuthorized:
:org.bluez.Error.NotSupported:
:org.bluez.Error.ImproperlyConfigured:

Properties
----------

string UUID [read-only]
```````````````````````

128-bit descriptor UUID.

object Characteristic [read-only]
`````````````````````````````````

Object path of the GATT characteristic the descriptor belongs to.

array{byte} Value [read-only, optional]
```````````````````````````````````````

The cached value of the descriptor. This property gets updated only after a
successful read request, upon which a PropertiesChanged signal will be emitted.

array{string} Flags [read-only]
```````````````````````````````

Defines how the descriptor value can be used.

Possible values:

:"read":
:"write":
:"encrypt-read":
:"encrypt-write":
:"encrypt-authenticated-read":
:"encrypt-authenticated-write":
:"secure-read" (Server Only):
:"secure-write" (Server Only):
:"authorize":

uint16 Handle [read-only] (Client Only)
```````````````````````````````````````

Descriptor handle.

uint16 Handle [read-write, optional] (Server Only)
``````````````````````````````````````````````````

Descriptor handle. When available in the server it would attempt to use to
allocate into the database which may fail, to auto allocate the value 0x0000
shall be used which will cause the allocated handle to be set once registered.

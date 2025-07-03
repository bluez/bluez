============================
org.bluez.GattCharacteristic
============================

------------------------------------------------
BlueZ D-Bus GattCharacteristic API documentation
------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

GATT local/server and remote/client characteristic attribute representation
share the same high-level D-Bus API.

Local/Server refers to GATT based characteristics exported by a plugin or an
external application.

Remote/Client refers to GATT characteristics exported by the peer.

Interface
=========

Client
------

:Service:	org.bluez
:Interface:	org.bluez.GattCharacteristic1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/service#/char#

Server
------

:Service:	unique name
:Interface:	org.bluez.GattCharacteristic1
:Object path:	freely definable

Methods
-------

array{byte} ReadValue(dict options)
```````````````````````````````````

Issues a request to read the value of the characteristic and returns the value
if the operation was successful.

Possible options:

:uint16 offset:

	Read start offset in bytes.

:uint16 mtu (server only):

	Exchange MTU in bytes.

:object device (server only):

	Device object.

:string link (server only):

	Link type.

	Possible values:

	:"BR/EDR":
	:"LE":

Possible Errors:

:org.bluez.Error.Failed:

	Possible values: string 0x80 - 0x9f

:org.bluez.Error.InProgress:
:org.bluez.Error.NotPermitted:
:org.bluez.Error.NotAuthorized:
:org.bluez.Error.InvalidOffset:
:org.bluez.Error.NotSupported:

void WriteValue(array{byte} value, dict options)
````````````````````````````````````````````````

Issues a request to write the value of the characteristic.

Possible options:

:uint16 offset:

	Write start offset in bytes.

:string type:

	Possible values:

	:"command":

		Use Write without response procedure.

	:"request":

		Use Write with response procedure.

	:"reliable":

		Use Reliable Write procedure.

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

	Possible values: string 0x80 - 0x9f

:org.bluez.Error.InProgress:
:org.bluez.Error.NotPermitted:
:org.bluez.Error.InvalidValueLength:
:org.bluez.Error.NotAuthorized:
:org.bluez.Error.NotSupported:
:org.bluez.Error.ImproperlyConfigured:

fd, uint16 AcquireWrite(dict options) [optional]
````````````````````````````````````````````````

Acquire file descriptor and MTU for writing. Only sockets are supported. Usage
of WriteValue will be locked causing it to return NotPermitted error.

For server the MTU returned shall be equal or smaller than the negotiated MTU.

For client it only works with characteristic that has **WriteAcquired** property
which relies on write-without-response **Flag**.

To release the lock the client shall close the file descriptor, a HUP is
generated in case the device is disconnected.

Note: the MTU can only be negotiated once and is symmetric therefore this method
may be delayed in order to have the exchange MTU completed, because of that the
file descriptor is closed during reconnections as the MTU has to be
renegotiated.

Possible options:

:object device:

	Object Device (Server only).

:uint16 mtu:

	Exchanged MTU (Server only).

:string link:

	Link type (Server only).

	Possible values:

	:"BR/EDR":
	:"LE":

Possible Errors:

:org.bluez.Error.Failed:
:org.bluez.Error.NotSupported:

fd, uint16 AcquireNotify(dict options) [optional]
`````````````````````````````````````````````````

Acquire file descriptor and MTU for notify. Only sockets are support.

Usage of StartNotify will be locked causing it to return
**org.bluez.Error.NotPermitted**.

For server the MTU returned shall be equal or smaller than the negotiated MTU.

Only works with characteristic that has **NotifyAcquired** property which relies
on presence of **"notify" or "indicate"** **Flag** and no other client have
called **StartNotify()**.

Notification are enabled during this procedure so **StartNotify()** shall not be
called, any notification will be dispatched via file descriptor therefore the
Value property is not affected during the time where notify has been acquired.

To release the lock the client shall close the file descriptor, a HUP is
generated in case the device is disconnected.

As a client if indication procedure is used the confirmation is generated
automatically once received, for a server if the file descriptor is writable
(POLLOUT) then upon receiving a confirmation from the client one byte (0x01) is
written to the file descriptor.

Note: the MTU can only be negotiated once and is symmetric therefore this method
may be delayed in order to have the exchange MTU completed, because of that the
file descriptor is closed during reconnections as the MTU has to be
renegotiated.

Possible options:

:object device:

	Object Device (Server only).

:uint16 mtu:

	Exchanged MTU (Server only).

:string link:

	Link type (Server only).

	Possible values:

	:"BR/EDR":
	:"LE":

Possible Errors:

:org.bluez.Error.Failed:
:org.bluez.Error.NotSupported:
:org.bluez.Error.NotPermitted:

void StartNotify()
``````````````````

Starts a notification session from this characteristic if it supports value
notifications or indications.

Possible Errors:

:org.bluez.Error.Failed:
:org.bluez.Error.NotPermitted:
:org.bluez.Error.InProgress:
:org.bluez.Error.NotConnected:
:org.bluez.Error.NotSupported:

void StopNotify()
`````````````````

Stops or cancel session previously created by **StartNotify()**.

Note that notifications from a characteristic are shared between sessions thus
calling StopNotify will release a single session.

Possible Errors:

:org.bluez.Error.Failed:

void Confirm() [noreply, optional] (Server only)
````````````````````````````````````````````````

Confirms value was received.

Possible Errors:

org.bluez.Error.Failed

Properties
----------

string UUID [read-only]
```````````````````````

128-bit characteristic UUID.

object Service [read-only]
``````````````````````````

Object path of the GATT service the characteristic belongs to.

array{byte} Value [read-only, optional]
```````````````````````````````````````

The cached value of the characteristic. This property gets updated only after a
successful read request and when a notification or indication is received, upon
which a PropertiesChanged signal will be emitted.

boolean WriteAcquired [read-only, optional]
```````````````````````````````````````````

True, if this characteristic has been acquired by any client using AcquireWrite.

For client properties is omitted in case 'write-without-response' flag is not
set.

For server the presence of this property indicates that AcquireWrite is
supported.

boolean NotifyAcquired [read-only, optional]
````````````````````````````````````````````

True, if this characteristic has been acquired by any client using
AcquireNotify.

For client this properties is omitted in case 'notify' flag is not set.

For server the presence of this property indicates that AcquireNotify is
supported.

boolean Notifying [read-only, optional]
```````````````````````````````````````

True, if notifications or indications on this characteristic are currently
enabled.

array{string} Flags [read-only]
```````````````````````````````

Defines how the characteristic value can be used. See Core spec
"Table 3.5: Characteristic Properties bit field", and
"Table 3.8: Characteristic Extended Properties bit field".

The "x-notify" and "x-indicate" flags restrict access to notifications and
indications by imposing write restrictions on a characteristic's client
characteristic configuration descriptor.

Possible values:

:"broadcast":
:"read":
:"write-without-response":
:"write":
:"notify":
:"indicate":
:"authenticated-signed-writes":
:"extended-properties":
:"reliable-write":
:"writable-auxiliaries":
:"encrypt-read":
:"encrypt-write":
:"encrypt-notify" (Server only):
:"encrypt-indicate" (Server only):
:"encrypt-authenticated-read":
:"encrypt-authenticated-write":
:"encrypt-authenticated-notify" (Server only):
:"encrypt-authenticated-indicate" (Server only):
:"secure-read" (Server only):
:"secure-write" (Server only):
:"secure-notify" (Server only):
:"secure-indicate" (Server only):
:"authorize":

uint16 Handle [read-only] (Client Only)
```````````````````````````````````````

Characteristic handle.

uint16 Handle [read-write, optional] (Server Only)
``````````````````````````````````````````````````

Characteristic handle. When available in the server it would attempt to use to
allocate into the database which may fail, to auto allocate the value 0x0000
shall be used which will cause the allocated handle to be set once registered.

uint16 MTU [read-only]
``````````````````````

Characteristic MTU, this is valid both for **ReadValue()** and **WriteValue()**
but either method can use long procedures when supported.

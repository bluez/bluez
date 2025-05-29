=======================
org.bluez.NetworkServer
=======================

-------------------------------------------
BlueZ D-Bus NetworkServer API documentation
-------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.NetworkServer1
:Object path:	/org/bluez/{hci0,hci1,...}


Methods
-------

void Register(string uuid, string bridge)
`````````````````````````````````````````

Registers server for the provided UUID.

Every new connection to this server will be added the bridge interface.

Possible uuid values:

:"panu", "00001115-0000-1000-8000-00805f9b34fb":

	Personal Network User role.

:"nap", "00001116-0000-1000-8000-00805f9b34fb":

	Network Access Point role.

:"gn", "00001117-0000-1000-8000-00805f9b34fb":

	Group Network role.

Initially no network server SDP is provided. Only after this method a SDP record
will be available and the BNEP server will be ready for incoming connections.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.AlreadyExists:
:org.bluez.Error.Failed:

void Unregister(string uuid)
````````````````````````````

Unregisters the server for provided UUID which was previously registered with
**Register()** method.

All servers will be automatically unregistered when the calling application
terminates.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.Failed:

=====================
org.bluez.GattService
=====================

-------------------------------------------------
BlueZ D-Bus GattService API documentation
-------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

GATT local/server and remote/client services share the same high-level D-Bus
API.

Local/Server refers to GATT based service exported by a plugin or an external
application.

Remote/Client refers to GATT services exported by the peer.

Interface
=========

Client
------

:Service:	org.bluez
:Interface:	org.bluez.GattService1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/service#

Server
------

:Service:	unique name
:Interface:	org.bluez.GattService1
:Object path:	freely definable

Properties
----------

string UUID [read-only]
```````````````````````

128-bit service UUID.

boolean Primary [read-only]
```````````````````````````

Indicates whether or not this GATT service is a primary service. If false, the
service is secondary.

object Device [read-only, optional]
```````````````````````````````````

Object path of the Bluetooth device the service belongs to. Only present on
services from remote devices.

array{object} Includes [read-only, optional]
````````````````````````````````````````````

Array of object paths representing the included services of this service.

uint16 Handle [read-only] (client only)
```````````````````````````````````````

Service handle.

uint16 Handle [read-write, optional] (Server Only)
``````````````````````````````````````````````````

Service handle. When available in the server it would attempt to use to allocate
into the database which may fail, to auto allocate the value 0x0000 shall be
used which will cause the allocated handle to be set once registered.

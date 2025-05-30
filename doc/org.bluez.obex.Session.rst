======================
org.bluez.obex.Session
======================

-----------------------------------------
BlueZ D-Bus OBEX Client API documentation
-----------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.Session1
:Object path:	/org/bluez/obex/server/session{#} or
		/org/bluez/obex/client/session{#}

Methods
-------

string GetCapabilities()
````````````````````````

Get remote device capabilities.

Possible errors:

:org.bluez.obex.Error.NotSupported:
:org.bluez.obex.Error.Failed:

Properties
----------

string Source [readonly]
````````````````````````

Bluetooth adapter address

string Destination [readonly]
`````````````````````````````

Bluetooth device address

byte Channel [readonly]
```````````````````````

Bluetooth channel

uint16 PSM [readonly]
```````````````````````

Bluetooth L2CAP PSM

string Target [readonly]
````````````````````````

Target UUID

string Root [readonly]
``````````````````````

Root path

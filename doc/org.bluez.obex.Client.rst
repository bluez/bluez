=====================
org.bluez.obex.Client
=====================

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
:Interface:	org.bluez.obex.Client1
:Object path:	/org/bluez/obex

Methods
-------

object CreateSession(string destination, dict args)
```````````````````````````````````````````````````

Connects to the destination address and then proceed to create an OBEX session
object which implements **org.bluez.obex.Session(5)** interface.

The last parameter is a dictionary to hold optional or type-specific parameters.

Possible args values:

:string Target:

	Type of session to be created.

	Possible values:

	:"ftp":
	:"map":
	:"opp":
	:"pbap":
	:"sync":
	:"bip-avrcp":

:string Source:

	Local address to be used.

:byte Channel:

	Channel to be used.

:uint16 PSM:

	L2CAP PSM to be used.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

void RemoveSession(object session)
``````````````````````````````````

Disconnects and removes session previously created by **CreateSession()**
aborting any pending transfers.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.NotAuthorized:

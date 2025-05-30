=======================
org.bluez.obex.Transfer
=======================

-------------------------------------------
BlueZ D-Bus OBEX Transfer API documentation
-------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.Transfer1
:Object path:	[Session object path]/transfer{#}

Methods
-------

void Cancel()
`````````````

Cancels the current transference.

Possible errors:

:org.bluez.obex.Error.NotAuthorized:
:org.bluez.obex.Error.InProgress:
:org.bluez.obex.Error.Failed:

void Suspend()
``````````````

Suspends transference.

Possible errors:

:org.bluez.obex.Error.NotAuthorized:
:org.bluez.obex.Error.NotInProgress:

	If transfer is still in with **Status** **"queued"**.

void Resume()
`````````````

Resumes transference previously suspended with use of **Suspend()** method.

Possible errors:

:org.bluez.obex.Error.NotAuthorized:
:org.bluez.obex.Error.NotInProgress:

	If transfer is still in with **Status** **"queued"**.

Properties
----------

string Status [readonly]
````````````````````````

Indicates the current status of the transfer.

Possible values:

	:"queued":
	:"active":
	:"suspended":
	:"complete":
	:"error":

object Session [readonly]
`````````````````````````

The object path of the session the transfer belongs to.

string Name [readonly, optional]
````````````````````````````````

Name of the object being transferred.

Either Name or Type or both will be present.

string Type [readonly, optional]
````````````````````````````````

Type of the object transferred being transferred.

Either Name or Type or both will be present.

uint64 Time [readonly, optional]
````````````````````````````````

Time of the object being transferred if this is provided by the remote party.

uint64 Size [readonly, optional]
````````````````````````````````

Size of the object being transferred.

If the size is unknown, then this property will not be present.

uint64 Transferred [readonly, optional]
```````````````````````````````````````

Number of bytes transferred.

For transfers with **Status** set to **"queued"**, this value will not be
present.

string Filename [readonly, optional]
````````````````````````````````````

Complete name of the file being received or sent.

For incoming object push transaction, this will be the proposed default location
and name. It can be overwritten by the **AuthorizePush()** in
**org.bluez.obex.Agent(5)** and will be then updated accordingly.

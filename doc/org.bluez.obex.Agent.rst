====================
org.bluez.obex.Agent
====================

----------------------------------------
BlueZ D-Bus OBEX Agent API documentation
----------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	unique name
:Interface:	org.bluez.obex.Agent1
:Object path:	freely definable

Methods
-------

void Release()
``````````````

This method gets called when **obexd(8)** daemon unregisters the agent.

An agent can use it to do cleanup tasks. There is no need to unregister the
agent, because when this method gets called it has already been unregistered.

string AuthorizePush(object transfer)
`````````````````````````````````````

This method gets called when the **obexd(8)** needs to accept/reject a Bluetooth
object push request.

Returns the full path (including the filename) or the folder name suffixed with
'/' where the object shall be stored.

The transfer object, see **org.bluez.obex.Transfer(5)** will contain a Filename
property that contains the default location and name that can be returned.

Possible errors:

:org.bluez.obex.Error.Rejected:
:org.bluez.obex.Error.Canceled:

void Cancel()
`````````````

This method gets called to indicate that the agent request failed before a reply
was returned. It cancels the previous request.

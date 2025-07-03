===================
org.bluez.DeviceSet
===================

---------------------------------------
BlueZ D-Bus DeviceSet API documentation
---------------------------------------

:Version: BlueZ
:Date: September 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.DeviceSet1
:Object path:	[variable prefix]/{hci0,hci1,...}/set_{sirk}

Methods
-------

void Connect() [experimental]
`````````````````````````````

Connects all **devices** members of the set, each member is connected in
sequence as they were added/loaded following the same procedure as described in
**Device1.Connect**.

Possible errors:

:org.bluez.Error.NotReady:
:org.bluez.Error.Failed:
:org.bluez.Error.InProgress:
:org.bluez.Error.AlreadyConnected:

void Disconnect() [experimental]
````````````````````````````````

Disconnects all **devices** members of the set, each member is disconnected in
sequence as they were connected following the same procedure as described in
**Device1.Disconnect**.

Possible errors:

:org.bluez.Error.NotConnected:

Properties
----------

object Adapter [readonly, experimental]
```````````````````````````````````````

The object path of the adapter the set belongs to.

bool AutoConnect [read-write, experimental]
```````````````````````````````````````````

Indicates if the **devices** members of the set shall be automatically connected
once any of its members is connected.

array(object) Devices [ready-only, experimental]
````````````````````````````````````````````````

List of devices objects that are members of the set.

byte Size [read-only, experimental]
```````````````````````````````````

Set members size.

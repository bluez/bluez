=================
org.bluez.Network
=================

-------------------------------------
BlueZ D-Bus Network API documentation
-------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Network1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}

Methods
-------

string Connect(string uuid)
```````````````````````````

Connects to the network device and return the network interface name.

Possible uuid values:

:"panu", "00001115-0000-1000-8000-00805f9b34fb":

	Personal Network User role.

:"nap", "00001116-0000-1000-8000-00805f9b34fb":

	Network Access Point role.

:"gn", "00001117-0000-1000-8000-00805f9b34fb":

	Group Network role.

The connection will be closed and network device released either upon calling
**Disconnect()** or when the client disappears from the message bus.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:
:org.bluez.Error.InProgress:
:org.bluez.Error.Failed:

void Disconnect()
`````````````````

Disconnects from the network device.

To abort a connection attempt in case of errors or timeouts in the client it is
fine to call this method.

Possible errors:

:org.bluez.Error.Failed:
:org.bluez.Error.NotConnected:

Properties
----------

boolean Connected [readonly]
````````````````````````````

Indicates if the device is connected.

string Interface [readonly, optional]
`````````````````````````````````````

Indicates the network interface name when available.

string UUID [readonly, optional]
````````````````````````````````

Indicates the connection role when available.

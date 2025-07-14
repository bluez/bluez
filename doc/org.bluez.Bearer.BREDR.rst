======================
org.bluez.Bearer.BREDR
======================

------------------------------------------
BlueZ D-Bus Bearer BREDR API documentation
------------------------------------------

:Version: BlueZ
:Date: July 2025
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Bearer.BREDR1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}

Methods
-------

void Connect() [experimental]
`````````````````````````````

Connects all BREDR profiles the remote device supports that can be connected to
and have been flagged as auto-connectable. If only subset of profiles is already
connected it will try to connect currently disconnected ones.

If at least one profile was connected successfully this method will indicate
success.

Possible errors:

:org.bluez.Error.NotReady:
:org.bluez.Error.Failed:
:org.bluez.Error.InProgress:
:org.bluez.Error.AlreadyConnected:

void Disconnect() [experimental]
````````````````````````````````

Disconnects all connected profiles and then terminates low-level ACL connection.

ACL connection will be terminated even if some profiles were not disconnected
properly e.g. due to misbehaving device.

This method can be also used to cancel a preceding Connect call before a reply
to it has been received.

For non-trusted devices connected calling this method will disable incoming
connections until Connect method is called again.

Possible errors:

:org.bluez.Error.NotConnected:

Signals
-------

void Disconnected(string reason, string message) [experimental]
```````````````````````````````````````````````````````````````

This signal is launched when a device is disconnected, with the reason of the
disconnection.

This could be used by client application, depending on internal policy, to try
to reconnect to the device in case of timeout or unknown disconnection, or to
try to connect to another device.

Possible reasons:

:org.bluez.Reason.Unknown:

:org.bluez.Reason.Timeout:

	Connection timeout.

	The link supervision timeout has expired for a connection or the
	synchronization timeout has expired for a broadcast.

:org.bluez.Reason.Local:

	Connection terminated by local host.

	The local device terminated the connection, terminated synchronization
	with a broadcaster, or terminated broadcasting packets.

:org.bluez.Reason.Remote:

	Connection terminated by remote host.

	This disconnection can be due to:

	- the user on the remote device either terminated the connection or
	  stopped broadcasting packets,

	- the remote device terminated the connection because of low
	  resources,

	- the remote device terminated the connection because the device is
	  about to power off.

:org.bluez.Reason.Authentication:

	Connection terminated due to an authentication failure.

:org.bluez.Reason.Suspend:

	Connection terminated by local host for suspend.

Properties
----------

object Adapter [readonly, experimental]
```````````````````````````````````````

The object path of the adapter the set belongs to.


boolean Paired [readonly, experimental]
```````````````````````````````````````

Indicates if the remote device is paired to BREDR bearer.

Paired means the pairing process where devices exchange the information to
establish an encrypted connection has been completed.

boolean Bonded [readonly, experimental]
```````````````````````````````````````

Indicates if the remote device is bonded to BREDR bearer.

Bonded means the information exchanged on pairing process has been stored and
will be persisted.

boolean Connected [readonly, experimental]
``````````````````````````````````````````

Indicates if the remote device is currently connected to BREDR bearer.

A PropertiesChanged signal indicate changes to this status.

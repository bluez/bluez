================
org.bluez.Device
================

------------------------------------
BlueZ D-Bus Device API documentation
------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Device1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}

Methods
-------

void Connect()
``````````````

Connects all profiles the remote device supports that can be connected to and
have been flagged as auto-connectable. If only subset of profiles is already
connected it will try to connect currently disconnected ones.

If at least one profile was connected successfully this method will indicate
success.

For dual-mode devices only one bearer is connected at time, the conditions are
in the following order:

1. Connect the disconnected bearer if already connected.

2. Connect first the bonded bearer. If no bearers are bonded or both are skip
   and check latest seen bearer.

3. Connect last used bearer, in case the timestamps are the same BR/EDR
   takes precedence, or in case **PreferredBearer** has been set to a specific
   bearer then that is used instead.

Possible errors:

:org.bluez.Error.NotReady:
:org.bluez.Error.Failed:
:org.bluez.Error.InProgress:
:org.bluez.Error.AlreadyConnected:

void Disconnect()
`````````````````

Disconnects all connected profiles and then terminates low-level ACL connection.

ACL connection will be terminated even if some profiles were not disconnected
properly e.g. due to misbehaving device.

This method can be also used to cancel a preceding Connect call before a reply
to it has been received.

For non-trusted devices connected over LE bearer calling this method will
disable incoming connections until Connect method is called again.

Possible errors:

:org.bluez.Error.NotConnected:

void ConnectProfile(string uuid)
````````````````````````````````

Connects a specific profile of this device. The UUID provided is the remote
service UUID for the profile.

Possible errors:

:org.bluez.Error.Failed:
:org.bluez.Error.InProgress:
:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotAvailable:
:org.bluez.Error.NotReady:

void DisconnectProfile(string uuid)
```````````````````````````````````

Disconnects a specific profile of this device. The profile needs to be
registered client profile.

There is no connection tracking for a profile, so as long as the profile is
registered this will always succeed.

Possible errors:

:org.bluez.Error.Failed:
:org.bluez.Error.InProgress:
:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:

void Pair()
```````````

Connects to the remote device and initiate pairing procedure then proceed with
service discovery.

If the application has registered its own agent, then that specific agent will
be used. Otherwise it will use the default agent.

Only for applications like a pairing wizard it would make sense to have its own
agent. In almost all other cases the default agent will handle this just fine.

In case there is no application agent and also no default agent present, this
method will fail.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.Failed:
:org.bluez.Error.AlreadyExists:
:org.bluez.Error.AuthenticationCanceled:
:org.bluez.Error.AuthenticationFailed:
:org.bluez.Error.AuthenticationRejected:
:org.bluez.Error.AuthenticationTimeout:
:org.bluez.Error.ConnectionAttemptFailed:

void CancelPairing()
````````````````````

Cancels a pairing operation initiated by the **Pair** method.

Possible errors:

:org.bluez.Error.DoesNotExist:
:org.bluez.Error.Failed:

array{array{byte}} GetServiceRecords() [experimental]
`````````````````````````````````````````````````````

Returns all currently known BR/EDR service records for the device. Each
individual byte array represents a raw SDP record, as defined by the Bluetooth
Service Discovery Protocol specification.

This method is intended to be only used by compatibility layers like Wine, that
need to provide access to raw SDP records to support foreign Bluetooth APIs.

General applications should instead use the Profile API for services-related
functionality.

Possible errors:

:org.bluez.Error.Failed:
:org.bluez.Error.NotReady:
:org.bluez.Error.NotConnected:
:org.bluez.Error.DoesNotExist:

Signals
-------

void Disconnected(string reason, string message)
````````````````````````````````````````````````

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

string Address [readonly]
`````````````````````````

The Bluetooth device address of the remote device.

string AddressType [readonly]
`````````````````````````````

The Bluetooth device Address Type. For dual-mode and BR/EDR only devices this
defaults to "public". Single mode LE devices may have either value.

If remote device uses privacy than before pairing this represents address type
used for connection and Identity Address after pairing.

Possible values:

:"public":

	Public address

:"random":

	Random address

string Name [readonly, optional]
````````````````````````````````

The Bluetooth remote name.

This value is only present for completeness. It is better to always use the
**Alias** property when displaying the devices name.

If the **Alias** property is unset, it will reflect this value which makes it
more convenient.

string Icon [readonly, optional]
````````````````````````````````

Proposed icon name according to the freedesktop.org icon naming specification.

uint32 Class [readonly, optional]
`````````````````````````````````

The Bluetooth class of device of the remote device.

uint16 Appearance [readonly, optional]
``````````````````````````````````````

External appearance of device, as found on GAP service.

array{string} UUIDs [readonly, optional]
````````````````````````````````````````

List of 128-bit UUIDs that represents the available remote services.

boolean Paired [readonly]
`````````````````````````

Indicates if the remote device is paired. Paired means the pairing process where
devices exchange the information to establish an encrypted connection has been
completed.

boolean Bonded [readonly]
`````````````````````````

Indicates if the remote device is bonded. Bonded means the information exchanged
on pairing process has been stored and will be persisted.

boolean Connected [readonly]
````````````````````````````

Indicates if the remote device is currently connected.

A PropertiesChanged signal indicate changes to this status.

boolean Trusted [readwrite]
```````````````````````````

Indicates if the remote is seen as trusted.

This setting can be changed by the application.

boolean Blocked [readwrite]
```````````````````````````

If set to true any incoming connections from the device will be immediately
rejected.

Any device drivers will also be removed and no new ones will be probed as long
as the device is blocked.

boolean WakeAllowed [readwrite]
```````````````````````````````

If set to true this device will be allowed to wake the host from system suspend.

string Alias [readwrite]
````````````````````````

The name alias for the remote device. The alias can be used to have a different
friendly name for the remote device.

In case no alias is set, it will return the remote device name. Setting an empty
string as alias will convert it back to the remote device name.

When resetting the alias with an empty string, the property will default back to
the remote name.

object Adapter [readonly]
`````````````````````````

The object path of the adapter the device belongs to.

boolean LegacyPairing [readonly]
````````````````````````````````

Set to true if the device only supports the pre-2.1 pairing mechanism.

This property is useful during device discovery to anticipate whether legacy or
simple pairing will occur if pairing is initiated.

Note that this property can exhibit false-positives in the case of Bluetooth 2.1
(or newer) devices that have disabled Extended Inquiry Response support.

boolean CablePairing [readonly]
```````````````````````````````

Set to true if the device was cable paired and it doesn't support the canonical
bonding with encryption, e.g. the Sixaxis gamepad.

If true, BlueZ will establish a connection without enforcing encryption.

string Modalias [readonly, optional]
````````````````````````````````````

Remote Device ID information in modalias format used by the kernel and udev.

int16 RSSI [readonly, optional]
```````````````````````````````

Received Signal Strength Indicator of the remote device (inquiry or
advertising).

int16 TxPower [readonly, optional]
``````````````````````````````````

Advertised transmitted power level (inquiry or advertising).

dict ManufacturerData [readonly, optional]
``````````````````````````````````````````

Manufacturer specific advertisement data. Keys are 16 bits Manufacturer ID
followed by its byte array value.

dict ServiceData [readonly, optional]
`````````````````````````````````````

Service advertisement data. Keys are the UUIDs in string format followed by its
byte array value.

bool ServicesResolved [readonly]
````````````````````````````````

Indicate whether or not service discovery has been resolved.

array{byte} AdvertisingFlags [readonly]
```````````````````````````````````````

The Advertising Data Flags of the remote device.

dict AdvertisingData [readonly]
```````````````````````````````

The Advertising Data of the remote device. Keys are 1 byte AD Type followed by
data as byte array.

Note: Only types considered safe to be handled by application are exposed.

Possible values:

:<type>:

	<byte array>

Example:

	<Transport Discovery> <Organization Flags...>
	0x26                   0x01         0x01...

array{object, dict} Sets [readonly, experimental]
`````````````````````````````````````````````````

The object paths of the sets the device belongs to followed by a dictionary
which can contain the following:

:byte Rank:

	Rank of the device in the Set.

string PreferredBearer [readwrite, optional, experimental]
``````````````````````````````````````````````````````````

Indicate the preferred bearer when initiating a connection, only available for
dual-mode devices.

When changing from "bredr" to "le" the device will be removed from the
'auto-connect' list so it won't automatically be connected when adverting.

Note: Changes only take effect when the device is disconnected.

Possible values:

:"last-used":

	Connect to last used bearer first. Default.

:"bredr":

	Connect to BR/EDR first.

:"le":

	Connect to LE first.

:"last-seen":

	Connect to last seen bearer first.

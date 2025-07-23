=================
org.bluez.Adapter
=================

-------------------------------------
BlueZ D-Bus Adapter API documentation
-------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Adapter1
:Object path:	[variable prefix]/{hci0,hci1,...}

Methods
-------

void StartDiscovery()
`````````````````````

Starts device discovery session which may include starting an inquiry and/or
scanning procedures and remote device name resolving.

Use **StopDiscovery** to release the sessions acquired.

This process will start creating Device objects as new devices are discovered.

During discovery RSSI delta-threshold is imposed.

Each client can request a single device discovery session per adapter.

Possible errors:

:org.bluez.Error.NotReady:
:org.bluez.Error.Failed:
:org.bluez.Error.InProgress:

void StopDiscovery()
````````````````````

Stops device discovery session started by **StartDiscovery**.

Note that a discovery procedure is shared between all discovery sessions thus
calling StopDiscovery will only release a single session and discovery will stop
when all sessions from all clients have finished.

Possible errors:

:org.bluez.Error.NotReady:
:org.bluez.Error.Failed:
:org.bluez.Error.NotAuthorized:

void RemoveDevice(object device)
````````````````````````````````

Removes the remote device object at the given path including cached information
such as bonding information.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.Failed:

void SetDiscoveryFilter(dict filter)
````````````````````````````````````

Sets the device discovery filter for the caller. When this method is called with
no filter parameter, filter is removed.

Possible filter values:

:array{string} UUIDs:

	Filter by service UUIDs, empty means match *any* UUID.

	When a remote device is found that advertises any UUID from
	UUIDs, it will be reported if:

	- **Pathloss** and **RSSI** are both empty.
	- only **Pathloss** param is set, device advertise TX power, and
	  computed pathloss is less than Pathloss param.
	- only **RSSI** param is set, and received RSSI is higher
	  than RSSI param.

:int16 RSSI:

	RSSI threshold value.

	PropertiesChanged signals will be emitted for already existing Device
	objects, with updated RSSI value. If one or more discovery filters have
	been set, the RSSI delta-threshold, that is imposed by StartDiscovery by
	default, will not be applied.

:uint16 Pathloss:

	Pathloss threshold value.

	PropertiesChanged signals will be emitted for already existing Device
	objects, with updated Pathloss value.

:string Transport (Default "auto"):

	Transport parameter determines the type of scan.

	Possible values:

	:"auto":

		Interleaved scan, use LE, BREDR, or both, depending on
		what's currently enabled.

	:"bredr":

		BR/EDR inquiry only.

	:"le":

		LE scan only.


:bool DuplicateData (Default false):

	Disables duplicate detection of advertisement data.

	When enabled PropertiesChanged signals will be generated for either
	ManufacturerData and ServiceData every time they are discovered.

:bool Discoverable (Default false):

	Make adapter discoverable while discovering, if the adapter is already
	discoverable setting this filter won't do anything.

:string Pattern (Default none):

	Discover devices where the pattern matches either the prefix of the
	address or device name which is convenient way to limited the number of
	device objects created during a discovery.

	When set disregards device discoverable flags.

	Note: The pattern matching is ignored if there are other client that
	don't set any pattern as it work as a logical OR, also setting empty
	string "" pattern will match any device found.

:bool AutoConnect (Default false):

	Connect to discovered devices automatically if a Pattern has
	been set and it matches the device address or name and it is
	connectable.

When discovery filter is set, Device objects will be created as new devices with
matching criteria are discovered regardless of they are connectable or
discoverable which enables listening to non-connectable and non-discoverable
devices.

When multiple clients call SetDiscoveryFilter, their filters are internally
merged, and notifications about new devices are sent to all clients. Therefore,
each client must check that device updates actually match its filter.

When SetDiscoveryFilter is called multiple times by the same client, last filter
passed will be active for given client.

SetDiscoveryFilter can be called before StartDiscovery.
It is useful when client will create first discovery session, to ensure that
proper scan will be started right after call to StartDiscovery.

Possible errors:

:org.bluez.Error.NotReady:
:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

array{string} GetDiscoveryFilters()
```````````````````````````````````

Returns available filters that can be given to **SetDiscoveryFilter**.

Possible errors: None

object ConnectDevice(dict properties) [experimental]
````````````````````````````````````````````````````

Connects to device without need of performing General Discovery.

Connection mechanism is similar to Connect method on **org.bluez.Device1(5)**
interface with exception that this method returns success when physical
connection is established and you can specify bearer to connect with parameter.

After this method returns, services discovery will continue and any supported
profile will be connected. There is no need for calling Connect on Device1 after
this call. If connection was successful this method returns object path to
created device object or device that already exist.

Possible properties values:

:string Address (Mandatory):

	The Bluetooth device address of the remote device.

:string AddressType (Default "BR/EDR"):

	The Bluetooth device Address Type. This is address type that should be
	used for initial connection.

	Possible values:

	:"public":

		Public address

	:"random":

		Random address

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.AlreadyExists:
:org.bluez.Error.NotSupported:
:org.bluez.Error.NotReady:
:org.bluez.Error.Failed:

Properties
----------

string Address [readonly]
`````````````````````````

The Bluetooth device address.

string AddressType [readonly]
`````````````````````````````

The Bluetooth Address Type. For dual-mode and BR/EDR only adapter this defaults
to "public". Single mode LE adapters may have either value. With privacy enabled
this contains type of Identity Address and not type of address used for
connection.

Possible values:

:"public":

	Public address.


:"random":

	Random address.

string Name [readonly]
``````````````````````

The Bluetooth system name (pretty hostname).

This property is either a static system default or controlled by an external
daemon providing access to the pretty hostname configuration.

string Alias [readwrite]
````````````````````````

The Bluetooth friendly name. This value can be changed.

In case no alias is set, it will return the system provided name. Setting an
empty string as alias will convert it back to the system provided name.

When resetting the alias with an empty string, the property will default back to
system name.

On a well configured system, this property never needs to be changed since it
defaults to the system name and provides the pretty hostname.

Only if the local name needs to be different from the pretty hostname, this
property should be used as last resort.

uint32 Class [readonly]
```````````````````````

The Bluetooth class of device.

This property represents the value that is either automatically configured by
DMI/ACPI information or provided as static configuration.

boolean Connectable [readwrite]
```````````````````````````````

Set an adapter to connectable or non-connectable. This is a global setting and
should only be used by the settings application.

Setting this property to false will set the Discoverable property of the adapter
to false as well, which will not be reverted if Connectable is set back to true.

If required, the application will need to manually set Discoverable to true.

Note that this property only affects incoming connections.

boolean Powered [readwrite]
```````````````````````````

Switch an adapter on or off. This will also set the appropriate connectable
state of the controller.

The value of this property is not persistent. After restart or unplugging of the
adapter it will reset back to false.

string PowerState [readonly, experimental]
``````````````````````````````````````````

The power state of an adapter.

The power state will show whether the adapter is turning off, or turning on, as
well as being on or off.

Possible values:

:"on":

	Powered on.

:"off":

	Powered off

:"off-enabling":

	Transitioning from "off" to "on".

:"on-disabling":

	Transitioning from "on" to "off".

:"off-blocked":

	Blocked by rfkill.

boolean Discoverable [readwrite] (Default: false)
`````````````````````````````````````````````````

Switch an adapter to discoverable or non-discoverable to either make it visible
or hide it. This is a global setting and should only be used by the settings
application.

If the DiscoverableTimeout is set to a non-zero value then the system will set
this value back to false after the timer expired.

In case the adapter is switched off, setting this value will fail.

When changing the Powered property the new state of this property will be
updated via a PropertiesChanged signal.

boolean Pairable [readwrite] (Default: true)
````````````````````````````````````````````

Switch an adapter to pairable or non-pairable. This is a global setting and
should only be used by the settings application.

Note that this property only affects incoming pairing requests.

uint32 PairableTimeout [readwrite] (Default: 0)
```````````````````````````````````````````````

The pairable timeout in seconds. A value of zero means that the timeout is
disabled and it will stay in pairable mode forever.

uint32 DiscoverableTimeout [readwrite] (Default: 180)
`````````````````````````````````````````````````````

The discoverable timeout in seconds. A value of zero means that the timeout is
disabled and it will stay in discoverable/limited mode forever.

boolean Discovering [readonly]
``````````````````````````````

Indicates that a device discovery procedure is active.

array{string} UUIDs [readonly]
``````````````````````````````

List of 128-bit UUIDs that represents the available local services.

string Modalias [readonly, optional]
````````````````````````````````````

Local Device ID information in modalias format used by the kernel and udev.

array{string} Roles [readonly]
``````````````````````````````

List of supported roles.

Possible values:

:"central":

	Supports the central role.

:"peripheral":

	Supports the peripheral role.

:"central-peripheral":

	Supports both roles concurrently.

array{string} ExperimentalFeatures [readonly, optional]
```````````````````````````````````````````````````````

List of 128-bit UUIDs that represents the experimental features currently
enabled.

uint16 Manufacturer [readonly]
``````````````````````````````

The manufacturer of the device, as a uint16 company identifier defined by the
Core Bluetooth Specification.

byte Version [readonly]
```````````````````````

The Bluetooth version supported by the device, as a core version code defined by
the Core Bluetooth Specification.

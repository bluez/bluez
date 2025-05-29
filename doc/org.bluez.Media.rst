===============
org.bluez.Media
===============

-----------------------------------
BlueZ D-Bus Media API documentation
-----------------------------------

:Version: BlueZ
:Date: April 2025
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Media1
:Object path:	[variable prefix]/{hci0,hci1,...}

Methods
-------

void RegisterEndpoint(object endpoint, dict properties)
```````````````````````````````````````````````````````

Register a local end point to sender, the sender can register as many end points
as it likes.

Note: If the sender disconnects the end points are automatically unregistered.

possible properties:

:string UUID:

	UUID of the profile which the endpoint is for.

	UUID must be in the list of SupportedUUIDS.

:byte Codec:

	Assigned number of codec that the endpoint implements. The
	values should match the profile specification which is
	indicated by the UUID.

:uint32_t Vendor [Optional]:

	Vendor-specific Company ID, Codec ID tuple that the endpoint implements.

	It shall be set to appropriate value when Vendor Specific Codec (0xff)
	is used.

:array{byte} Capabilities:

	Capabilities blob, it is used as it is so the size and byte order must
	match.

:array{byte} Metadata [Optional]:

	Metadata blob, it is used as it is so the size and byte order must
	match.

Possible Errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:

	emitted when interface for the end-point is disabled

void UnregisterEndpoint(object endpoint)
````````````````````````````````````````
Unregister sender end point.

void RegisterPlayer(object player, dict properties)
```````````````````````````````````````````````````

Register a media player object to sender, the sender can register as many
objects as it likes.

Object must implement at least **org.mpris.MediaPlayer2.Player** as defined in
MPRIS 2.2 spec:

http://specifications.freedesktop.org/mpris-spec/latest/

Note: If the sender disconnects its objects are automatically unregistered.

Possible Errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:

void UnregisterPlayer(object player)
````````````````````````````````````

Unregister sender media player.

void RegisterApplication(object root, dict options)
```````````````````````````````````````````````````

Register endpoints an player objects within root object which must implement
**org.freedesktop.DBus.ObjectManager**.

The application object path together with the D-Bus system bus connection ID
define the identification of the application.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.AlreadyExists:

void UnregisterApplication(object application)
``````````````````````````````````````````````

This unregisters the services that has been previously registered.

The object path parameter must match the same value that has been used on
registration.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.DoesNotExist:

Properties
----------

array{string} SupportedUUIDs [readonly]
```````````````````````````````````````

List of 128-bit UUIDs that represents the supported Endpoint registration.

array{string} SupportedFeatures [readonly]
``````````````````````````````````````````

List of strings that represent supported special features.

Possible values:

:"tx-timestamping":

	Bluetooth TX timestamping in media stream sockets is supported by BlueZ
	and kernel.  Applications may check kernel support for specific
	timestamp types via SIOCETHTOOL.

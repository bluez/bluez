==============================
org.bluez.LEAdvertisingManager
==============================

-------------------------------------------------
BlueZ D-Bus LEAvertisingManager API documentation
-------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

The Advertising Manager allows external applications to register Advertisement
Data which should be broadcast to devices.  Advertisement Data elements must
follow the API for LE Advertisement Data described above.

:Service:	org.bluez
:Interface:	org.bluez.LEAdvertisingManager1
:Object path:	/org/bluez/{hci0,hci1,...}

Methods
-------

void RegisterAdvertisement(object advertisement, dict options)
``````````````````````````````````````````````````````````````

Registers an advertisement object to be sent over the LE Advertising channel.

The service must implement **org.bluez.LEAdvertisement(5)** interface.

Possible errors:

:org.bluez.Error.InvalidArguments:

	Indicates that the object has invalid or conflicting properties.

:org.bluez.Error.AlreadyExists:

	Indicates the object is already registered.

:org.bluez.Error.InvalidLength:

	Indicates that the data provided generates a data packet which is too
	long.

:org.bluez.Error.NotPermitted:

	Indicates the maximum number of advertisement instances has been
	reached.

void UnregisterAdvertisement(object advertisement)
``````````````````````````````````````````````````

Unregisters an advertisement that has been previously registered using
**RegisterAdvertisement()**.

The object path parameter must match the same value that has been used on
registration.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.DoesNotExist:

Properties
----------

byte ActiveInstances [readonly]
```````````````````````````````

Number of active advertising instances.

byte SupportedInstances [readonly]
``````````````````````````````````

Number of available advertising instances.

array{string} SupportedIncludes [readonly]
``````````````````````````````````````````

List of supported system includes.

Possible values:

:"tx-power":
:"appearance":
:"local-name":
:"rsi":

array{string} SupportedSecondaryChannels [readonly]
```````````````````````````````````````````````````

List of supported Secondary channels. Secondary channels can be used to
advertise with the corresponding PHY.

Possible values:

:"1M":
:"2M":
:"Coded":

dict SupportedCapabilities [readonly]
`````````````````````````````````````

Enumerates Advertising-related controller capabilities useful to the client.

Possible Values:

:byte MaxAdvLen:

	Max advertising data length

:byte MaxScnRspLen:

	Max advertising scan response length

:int16 MinTxPower:

	Min advertising tx power (dBm)

:int16 MaxTxPower:

	Max advertising tx power (dBm)

array{string} SupportedFeatures [readonly,optional]
```````````````````````````````````````````````````

List of supported platform features. If no features are available on the
platform, the SupportedFeatures array will be empty.

Possible values:

:"CanSetTxPower":

	Indicates whether platform can specify tx power on each advertising
	instance.

:"HardwareOffload":

	Indicates whether multiple advertising will be offloaded to the
	controller.

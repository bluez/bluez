=========================
org.bluez.LEAdvertisement
=========================

---------------------------------------------
BlueZ D-Bus LEAdvertisement API documentation
---------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

Advertising packets are structured data which is broadcast on the LE Advertising
channels and available for all devices in range.  Because of the limited space
available in LE Advertising packets, each packet's contents must be carefully
controlled.

**bluetoothd(8)** acts as a store for the Advertisement Data which is meant to
be sent. It constructs the correct Advertisement Data from the structured
data and configured the kernel to send the correct advertisement.

Interface
=========

Specifies the Advertisement Data to be broadcast and some advertising
parameters.  Properties which are not present will not be included in the
data.  Required advertisement data types will always be included.
All UUIDs are 128-bit versions in the API, and 16 or 32-bit
versions of the same UUID will be used in the advertising data as appropriate.

:Service:	org.bluez
:Interface:	org.bluez.LEAdvertisement1
:Object path:	freely definable

Methods
-------

void Release() [noreply]
````````````````````````

This method gets called when the **bluetoothd(8)** removes the Advertisement.

A client can use it to do cleanup tasks. There is no need to call
**UnregisterAdvertisement()** because when this method gets called it has
already been unregistered.

Properties
----------

string Type [readonly]
``````````````````````

Determines the type of advertising packet requested.

Possible values:

:"broadcast":
:"peripheral":

array{string} ServiceUUIDs [readonly, optional]
```````````````````````````````````````````````

List of UUIDs to include in the "Service UUID" field of the Advertising Data.

dict ManufacturerData [readonly, optional]
``````````````````````````````````````````

Manufacturer Data fields to include in the Advertising Data.

Keys are the Manufacturer ID to associate with the data.

array{string} SolicitUUIDs [readonly, optional]
```````````````````````````````````````````````

List of UUIDs to include in the "Service Solicitation" field of the Advertising
Data.

dict ServiceData [readonly, optional]
`````````````````````````````````````

Service Data elements to include in the Advertising Data.

The keys are the UUID to associate with the data.

dict Data [readonly, optional]
``````````````````````````````

Advertising Data to include.

Key is the advertising type and value is the data as byte array.

Note: Types already handled by other properties shall not be used.

Possible values:

:<type>:

	<byte array>

Example:
	<Transport Discovery> <Organization Flags...>
	0x26                   0x01         0x01...

array{string} ScanResponseServiceUUIDs [readonly, optional, experimental]
`````````````````````````````````````````````````````````````````````````

List of UUIDs to include in the "Service UUID" field of the Scan Response Data.

dict ScanResponseManufacturerData [readonly, optional, experimental]
````````````````````````````````````````````````````````````````````

Manufacturer Data fields to include in the Scan Response Data.

Keys are the Manufacturer ID to associate with the data.

array{string} ScanResponseSolicitUUIDs [readonly, optional, experimental]
`````````````````````````````````````````````````````````````````````````

List of UUIDs to include in the "Service Solicitation" field of the Scan
Response Data.

dict ScanResponseServiceData [readonly, optional, experimental]
```````````````````````````````````````````````````````````````

Service Data elements to include in the Scan Response Data.

The keys are the UUID to associate with the data.

dict ScanResponseData [readonly, optional, experimental]
````````````````````````````````````````````````````````

Scan Response Data to include.

Key is the advertising type and value is the data as byte array.

bool Discoverable [readonly, optional]
``````````````````````````````````````

Advertise as general discoverable. When present this will override adapter
Discoverable property.

Note: This property shall not be set when **Type** is set to "broadcast".

uint16 DiscoverableTimeout [readonly, optional]
```````````````````````````````````````````````

The discoverable timeout in seconds. A value of zero means that the timeout is
disabled and it will stay in discoverable/limited mode forever.

Note: This property shall not be set when **Type** is set to "broadcast".

array{string} Includes [readonly, optional]
```````````````````````````````````````````

List of features to be included in the advertising packet.

Possible values:

See **org.bluez.LEAdvertisingManager(5)** **SupportedIncludes** property.

string LocalName [readonly, optional]
`````````````````````````````````````

Local name to be used in the advertising report. If the string is too big to
fit into the packet it will be truncated.

If this property is available 'local-name' cannot be present in the
**Includes**.

uint16 Appearance [readonly, optional]
``````````````````````````````````````

Appearance to be used in the advertising report.

Possible values: as found on GAP Service.

uint16 Duration [readonly, optional]
````````````````````````````````````

Rotation duration of the advertisement in seconds.

If there are other applications advertising no duration is set the default is
2 seconds.

uint16 Timeout [readonly, optional]
`````````````````````````````````````

Timeout of the advertisement in seconds. This defines the lifetime of the
advertisement.

string SecondaryChannel [readonly, optional]
````````````````````````````````````````````

Secondary channel to be used.

Primary channel is always set to "1M" except when "Coded" is set.

Possible value:

:"1M" (default):
:"2M":
:"Coded":

uint32 MinInterval [readonly, optional]
```````````````````````````````````````

Minimum advertising interval to be used by the advertising set, in milliseconds.

Acceptable values are in the range [20ms, 10,485s].

If the provided MinInterval is larger than the provided MaxInterval, the
registration will return failure.

uint32 MaxInterval [readonly, optional]
```````````````````````````````````````

Maximum advertising interval to be used by the advertising set, in milliseconds.

Acceptable values are in the range [20ms, 10,485s].

If the provided MinInterval is larger than the provided MaxInterval, the
registration will return failure.

int16 TxPower [readonly, optional]
``````````````````````````````````

Requested transmission power of this advertising set.

The provided value is used only if the "CanSetTxPower" feature is enabled on the
**org.bluez.LEAdvertisingManager(5)**.

Values must be in range [-127 to +20], where units are in dBm.

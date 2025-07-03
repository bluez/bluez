==============================
org.bluez.AdvertisementMonitor
==============================

--------------------------------------------------
BlueZ D-Bus AdvertisementMonitor API documentation
--------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

This API allows an client to specify a job of monitoring advertisements by
registering the root of hierarchy and then exposing advertisement monitors
under the root with filtering conditions, thresholds of RSSI and timers
of RSSI thresholds.

Once a monitoring job is activated by **bluetoothd(8)**, the client can expect
to get notified on the targeted advertisements no matter if there is an ongoing
discovery session (see **StartDiscovery()** in **org.bluez.Adapter(5)**).

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.AdvertisementMonitor1 [experimental]
:Object path:	freely definable

Methods
-------

void Release() [noreply]
````````````````````````

This gets called as a signal for a client to perform clean-up when:

- Monitor cannot be activated after it was exposed
- Monitor has been deactivated.

void Activate() [noreply]
`````````````````````````

After a monitor was exposed, this gets called as a signal for client to get
acknowledged when a monitor has been activated, so the client can expect to
receive calls on **DeviceFound()** or **DeviceLost()**.

void DeviceFound(object device) [noreply]
`````````````````````````````````````````

This gets called to notify the client of finding the targeted device.

Once receiving the call, the client should start to monitor the corresponding
device to retrieve the changes on RSSI and advertisement content.

void DeviceLost(object device) [noreply]
````````````````````````````````````````

This gets called to notify the client of losing the targeted device.

Once receiving this call, the client should stop monitoring the corresponding
device.

Properties
----------

string Type [read-only]
```````````````````````

The type of the monitor. See **SupportedMonitorTypes** in
**org.bluez.AdvertisementMonitorManager(5)** for the available options.

int16 RSSILowThreshold [read-only, optional]
````````````````````````````````````````````

Used in conjunction with **RSSILowTimeout** to determine whether a device
becomes out-of-range.

Valid range is -127 to 20 (dBm), while 127 indicates unset.

int16 RSSIHighThreshold [read-only, optional]
`````````````````````````````````````````````

Used in conjunction with RSSIHighTimeout to determine whether a device becomes
in-range.

Valid range is -127 to 20 (dBm), while 127 indicates unset.

uint16 RSSILowTimeout [read-only, optional]
```````````````````````````````````````````

The time it takes to consider a device as out-of-range. If this many seconds
elapses without receiving any signal at least as strong as **RSSILowThreshold**,
a currently in-range device will be considered as out-of-range (lost). Valid
range is 1 to 300 (seconds), while 0 indicates unset.

uint16 RSSIHighTimeout [read-only, optional]
````````````````````````````````````````````

The time it takes to consider a device as in-range. If this many seconds elapses
while we continuously receive signals at least as strong as
**RSSIHighThreshold**, a currently out-of-range device will be considered as
in-range (found).

Valid range is 1 to 300 (seconds), while 0 indicates unset.

uint16 RSSISamplingPeriod [read-only, optional]
```````````````````````````````````````````````

Grouping rules on how to propagate the received advertisement packets to the
client.

Possible values:

:0:
	All advertisement packets from in-range devices would be
	propagated.

:255:
	Only the first advertisement packet of in-range devices would be
	propagated. If the device becomes lost, then the first packet when it is
	found again will also be propagated.

:1 to 254:
	Advertisement packets would be grouped into 100ms * N time period.
	Packets in the same group will only be reported once, with the RSSI
	value being averaged out.

	Currently this is unimplemented in user space, so the value is only
	used to be forwarded to the kernel.

array{(uint8, uint8, array{byte})} Patterns [read-only, optional]
`````````````````````````````````````````````````````````````````

If the **Type** property is set to **"or_patterns"**, then this property must
exist and have at least one entry in the array.

The structure of a pattern contains the following:

:uint8 start_position:

	The index in an AD data field where the search should start. The
	beginning of an AD data field is index 0.

:uint8 AD_data_type:

	See https://www.bluetooth.com/specifications/assigned-numbers/
	generic-access-profile/ for the possible allowed value.

:array{byte} content_of_pattern:

	This is the value of the pattern. The maximum length of the bytes is 31.

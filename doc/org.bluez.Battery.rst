=================
org.bluez.Battery
=================

-------------------------------------
BlueZ D-Bus Battery API documentation
-------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Battery1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}

Properties
----------

byte Percentage [readonly]
``````````````````````````

The percentage of battery left as an unsigned 8-bit integer.

string Source [readonly, optional]
``````````````````````````````````

Describes where the battery information comes from.

This property is informational only and may be useful for debugging purposes.

Providers from **org.bluez.BatteryProvider(5)** may make use of this property to
indicate where the battery report comes from (e.g. "HFP 1.7", "HID", or the
profile UUID).

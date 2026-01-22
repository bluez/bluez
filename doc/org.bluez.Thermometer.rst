=====================
org.bluez.Thermometer
=====================

------------------------------------------------
BlueZ D-Bus Health Thermometer API documentation
------------------------------------------------

:Version: BlueZ
:Date: July 2011
:Author: Santiago Carot-Nemesio <sancane@gmail.com>
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Thermometer1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX

Properties
----------

boolean Intermediate [readonly]
```````````````````````````````

True if the thermometer supports intermediate
measurement notifications.

uint16 Interval (optional) [readwrite]
``````````````````````````````````````

The Measurement Interval defines the time (in
seconds) between measurements. This interval is
not related to the intermediate measurements and
must be defined into a valid range. Setting it
to zero means that no periodic measurements will
be taken.

uint16 Maximum (optional) [readonly]
````````````````````````````````````

Defines the maximum value allowed for the interval
between periodic measurements.

uint16 Minimum (optional) [readonly]
````````````````````````````````````

Defines the minimum value allowed for the interval
between periodic measurements.

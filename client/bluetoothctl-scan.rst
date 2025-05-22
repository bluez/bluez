=================
bluetoothctl-scan
=================

------------
Scan Submenu
------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: July 2023
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [scan.commands]

Scan Commands
=============

uuids
-----

Set/Get UUIDs filter.

:Usage: **> uuids [all/uuid1 uuid2 ...]**

rssi
----

Set/Get RSSI filter, and clears pathloss.

This sets the minimum rssi value for reporting device advertisements.

The value is in dBm.

If one or more discovery filters have been set, the RSSI delta-threshold imposed
by starting discovery by default will not be applied.

:Usage: **> rssi [rssi]**
:Example: **> rssi -60**

pathloss
--------
Set/Get Pathloss filter, and clears RSSI.

This sets the maximum pathloss value for reporting device advertisements.

The value is in dB.

If one or more discovery filters have been set, the RSSI delta-threshold
imposed by starting discovery by default will not be applied.

:Usage: **> pathloss [pathloss]**
:Example: **> pathloss 4**

transport
---------

Set/Get transport filter.

Transport parameter determines the type of scan.

The default is auto.

Possible values:

- "auto": interleaved scan
- "bredr": BR/EDR inquiry
- "le": LE scan only

If "le" or "bredr" Transport is requested and the controller doesn't support it,
an org.bluez.Error.Failed error will be returned.

If "auto" transport is requested, the scan will use LE, BREDR, or both,
depending on what's currently enabled on the controller.

:Usage: **> transport [auto/bredr/le]**

duplicate-data
--------------

Set/Get duplicate data filter.

Disables duplicate detection of advertisement data.

When enabled, PropertiesChanged signals will be generated for ManufacturerData
and ServiceData every time they are discovered.

:Usage: **> duplicate-data [on/off]**

discoverable
------------

Set/Get discoverable filter.

Makes the adapter discoverable while discovering.

If the adapter is already discoverable, setting this filter won't have any
effect.

:Usage: **> discoverable [on/off]**

pattern
-------

Set/Get pattern filter.

Discover devices where the pattern matches either the prefix of the address or
the device name, which is a convenient way to limit the number of device objects
created during a discovery.

When set, it disregards device discoverable flags.

:Note: The pattern matching is ignored if there are other clients that don't
       set any pattern, as it works as a logical OR. Also, setting an empty
       string "" pattern will match any device found.

:Usage: **> pattern [value]**


auto-connect
------------

Set/Get auto-connect filter.

Connect to discovered devices automatically if pattern filter has been set and
it matches the device address or name and the device is connectable.

:Usage: **> auto-connect [on/off]**

clear
-----

Clears discovery filter.

:Usage: **> clear [uuids/rssi/pathloss/transport/duplicate-data/discoverable/pattern]**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

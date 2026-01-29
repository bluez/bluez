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
:[all/uuid1 uuid2 ...]: List of UUIDs to filter for during scanning (default: none, use "all" to scan for any UUID)
:Example Show current UUID filter settings:
	| **> uuids**
:Example Filter for Generic Access service only:
	| **> uuids 0x1800**
:Example Filter for Battery service only:
	| **> uuids 0x180F**
:Example Filter for Generic Access and Battery services:
	| **> uuids 0x1800 0x180F**
:Example Filter for Device Info, Battery, and Environmental Sensing:
	| **> uuids 0x180A 0x180F 0x181A**
:Example Filter for Generic Access using full UUID:
	| **> uuids 00001800-0000-1000-8000-00805f9b34fb**
:Example Filter using mixed short and long forms:
	| **> uuids 00001800-0000-1000-8000-00805f9b34fb 0000180f-0000-1000-8000-00805f9b34fb**
:Example Remove UUID filtering (scan for all devices):
	| **> uuids all**

rssi
----

Set/Get RSSI filter, and clears pathloss.

This sets the minimum rssi value for reporting device advertisements.

The value is in dBm.

If one or more discovery filters have been set, the RSSI delta-threshold imposed
by starting discovery by default will not be applied.

:Usage: **> rssi [rssi]**
:[rssi]: Minimum RSSI threshold value in dBm (optional, shows current if omitted)
:Example Show current RSSI filter setting:
	| **> rssi**
:Example Only report devices with RSSI ≥ -60 dBm (close range):
	| **> rssi -60**
:Example Report devices with RSSI ≥ -80 dBm (medium range):
	| **> rssi -80**
:Example Report devices with RSSI ≥ -90 dBm (extended range):
	| **> rssi -90**
:Example Report only very close devices (RSSI ≥ -40 dBm):
	| **> rssi -40**
:Example Report devices with very weak signals (maximum sensitivity):
	| **> rssi -100**

pathloss
--------
Set/Get Pathloss filter, and clears RSSI.

This sets the maximum pathloss value for reporting device advertisements.

The value is in dB.

If one or more discovery filters have been set, the RSSI delta-threshold
imposed by starting discovery by default will not be applied.

:Usage: **> pathloss [pathloss]**
:[pathloss]: Maximum pathloss threshold value in dB (optional, shows current if omitted)
:Example Show current pathloss filter setting:
	| **> pathloss**
:Example Report devices with maximum 4 dB pathloss (very close):
	| **> pathloss 4**
:Example Report devices with maximum 10 dB pathloss (close range):
	| **> pathloss 10**
:Example Report devices with maximum 20 dB pathloss (medium range):
	| **> pathloss 20**
:Example Report devices with maximum 30 dB pathloss (extended range):
	| **> pathloss 30**
:Example Report devices with maximum 50 dB pathloss (maximum range):
	| **> pathloss 50**

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
:[auto/bredr/le]: Transport type for scanning (optional, shows current if omitted)
:Example Show current transport filter setting:
	| **> transport**
:Example Use automatic transport selection (LE + BR/EDR):
	| **> transport auto**
:Example Scan only Low Energy devices:
	| **> transport le**
:Example Scan only BR/EDR (Classic Bluetooth) devices:
	| **> transport bredr**

duplicate-data
--------------

Set/Get duplicate data filter.

Disables duplicate detection of advertisement data.

When enabled, PropertiesChanged signals will be generated for ManufacturerData
and ServiceData every time they are discovered.

:Usage: **> duplicate-data [on/off]**
:[on/off]: Enable or disable duplicate advertisement data reporting (optional, shows current if omitted)
:Example Show current duplicate data filter setting:
	| **> duplicate-data**
:Example Enable reporting of duplicate advertisement data:
	| **> duplicate-data on**
:Example Disable duplicate data reporting (filter duplicates):
	| **> duplicate-data off**

discoverable
------------

Set/Get discoverable filter.

Makes the adapter discoverable while discovering.

If the adapter is already discoverable, setting this filter won't have any
effect.

:Usage: **> discoverable [on/off]**
:[on/off]: Make adapter discoverable during scanning (optional, shows current if omitted)
:Example Show current discoverable filter setting:
	| **> discoverable**
:Example Make adapter discoverable during scanning:
	| **> discoverable on**
:Example Keep adapter non-discoverable during scanning:
	| **> discoverable off**

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
:[value]: Pattern to match device address prefix or name (optional, shows current if omitted)
:Example Show current pattern filter setting:
	| **> pattern**
:Example Discover devices with "Samsung" in the name:
	| **> pattern Samsung**
:Example Discover devices with "iPhone" in the name:
	| **> pattern iPhone**
:Example Discover devices with "Headphones" in the name:
	| **> pattern Headphones**
:Example Discover devices with addresses starting with 00:11:22:
	| **> pattern 00:11:22**
:Example Discover devices with addresses starting with AA:BB:CC:
	| **> pattern AA:BB:CC**
:Example Clear pattern filter (match any device):
	| **> pattern ""**

auto-connect
------------

Set/Get auto-connect filter.

Connect to discovered devices automatically if pattern filter has been set and
it matches the device address or name and the device is connectable.

:Usage: **> auto-connect [on/off]**
:[on/off]: Automatically connect to discovered devices matching pattern filter (optional, shows current if omitted)
:Example Show current auto-connect filter setting:
	| **> auto-connect**
:Example Enable automatic connection to matching devices:
	| **> auto-connect on**
:Example Disable automatic connection (manual connection required):
	| **> auto-connect off**

clear
-----

Clears discovery filter.

:Usage: **> clear [uuids/rssi/pathloss/transport/duplicate-data/discoverable/pattern/auto-connect]**
:[uuids/rssi/pathloss/transport/duplicate-data/discoverable/pattern/auto-connect]: Specific filter(s) to clear (optional, clears all if omitted)
:Example Clear all discovery filters:
	| **> clear**
:Example Clear only UUID filter:
	| **> clear uuids**
:Example Clear only RSSI filter:
	| **> clear rssi**
:Example Clear only pathloss filter:
	| **> clear pathloss**
:Example Clear only transport filter:
	| **> clear transport**
:Example Clear only duplicate data filter:
	| **> clear duplicate-data**
:Example Clear only discoverable filter:
	| **> clear discoverable**
:Example Clear only pattern filter:
	| **> clear pattern**
:Example Clear only auto-connect filter:
	| **> clear auto-connect**
:Example Clear UUID and RSSI filters:
	| **> clear uuids rssi**
:Example Clear transport and pattern filters:
	| **> clear transport pattern**
:Example Clear pattern and auto-connect filters:
	| **> clear pattern auto-connect**
:Example Clear RSSI, pathloss, and discoverable filters:
	| **> clear rssi pathloss discoverable**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

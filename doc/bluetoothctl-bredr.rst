==================
bluetoothctl-bredr
==================

-------------
BREDR Submenu
-------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: December 2025
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [bredr.commands]

This submenu manages BR/EDR (Classic Bluetooth) bearer connections using the
**org.bluez.Device(5)** interface.

BREDR Commands
==============

list
----

List available bredr devices.

:Usage: **> list**
:Example Display all BR/EDR (Classic Bluetooth) devices that have been discovered:
	| **> list**

show
----

Show bredr bearer information on a device.

:Usage: **> show [dev]**
:Uses: **org.bluez.Device(5)** properties
:[dev]: Bluetooth device address or object path (optional, uses current device if omitted)
:Example Show BR/EDR bearer information for currently selected device:
	| **> show**
:Example Show BR/EDR bearer info for device with specified address:
	| **> show 00:11:22:33:44:55**

connect
-------

Connect device over bredr.

This command initiates a bredr connection to a remote device.

By default, it establishes the bredr connection and then connects all profiles
that marked as auto-connectable.

:Usage: **> connect <dev>**
:Uses: **org.bluez.Device(5)** method **Connect**
:<dev>: Bluetooth device address to connect to
:Example Connect to BR/EDR device:
	| **> connect 00:11:22:33:44:55**

disconnect
----------

Disconnect device over bredr.

By default this command disconnects all profiles associated with the bredr
connection, and then terminates the bredr link.

:Usage: **> disconnect <dev>**
:Uses: **org.bluez.Device(5)** method **Disconnect**
:<dev>: Bluetooth device address to disconnect from
:Example Disconnect from BR/EDR device:
	| **> disconnect 00:11:22:33:44:55**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

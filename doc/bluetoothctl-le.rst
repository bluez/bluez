===============
bluetoothctl-le
===============

----------
LE Submenu
----------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: December 2025
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [le.commands]

This submenu manages LE (Low Energy) bearer connections using the
**org.bluez.Device(5)** interface.

LE Commands
===========

list
----

List available le devices.

:Usage: **> list**
:Example Display all LE (Low Energy) devices that have been discovered:
	| **> list**

show
----

Show le bearer information on a device.

:Usage: **> show [dev]**
:Uses: **org.bluez.Device(5)** properties
:[dev]: Bluetooth device address (optional, shows all LE bearers if omitted)
:Example Show all LE bearer information:
	| **> show**
:Example Show LE bearer info for device with specified address:
	| **> show 00:11:22:33:44:55**

connect
-------

Connect device over le.

This command initiates a le connection to a remote device.

An active scan report is required before the connection can be
established. If no advertising report is received before the timeout,
a le-connection-abort-by-local error will be issued.

:Usage: **> connect <dev>**
:Uses: **org.bluez.Device(5)** method **Connect**
:<dev>: Bluetooth device address to connect to
:Example Connect to another LE device:
	| **> connect 00:11:22:33:44:55**

disconnect
----------

Disconnect device over le.

By default this command disconnects all profiles/services associated with the le
connection, and then terminates the le link.

:Usage: **> disconnect <dev>**
:Uses: **org.bluez.Device(5)** method **Disconnect**
:<dev>: Bluetooth device address to disconnect from
:Example Disconnect from another LE device:
	| **> disconnect 00:11:22:33:44:55**


RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

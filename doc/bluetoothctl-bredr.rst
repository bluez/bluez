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

BREDR Commands
==============

list
----

List available bredr devices.

:Usage: **> list**

show
----

Show bredr bearer information on a device.

:Usage: **> show [dev]**

connect
-------

Connect device over bredr.

This command initiates a bredr connection to a remote device.

By default, it establishes the bredr connection and then connects all profiles
that marked as auto-connectable.

:Usage: > connect <dev>
:Example: > connect 1C:48:F9:9D:81:5C

disconnect
----------

Disconnect device over bredr.

By default this command disconnects all profiles associated with the bredr
connection, and then terminates the bredr link.

:Usage: > disconnect <dev>
:Example: > disconnect 1C:48:F9:9D:81:5C

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

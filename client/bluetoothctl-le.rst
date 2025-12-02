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

LE Commands
===========

list
----

List available le devices.

:Usage: **> list**

show
----

Show le bearer information on a device.

:Usage: **> show [dev]**

connect
-------

Connect device over le.

This command initiates a le connection to a remote device.

An active scan report is required before the connection can be
established. If no advertising report is received before the timeout,
a le-connection-abort-by-local error will be issued.

:Usage: > connect <dev>
:Example: > connect 1C:48:F9:9D:81:5C

disconnect
----------

Disconnect device over le.

By default this command disconnects all profiles/services associated with the le
connection, and then terminates the le link.

:Usage: > disconnect <dev>
:Example: > disconnect 1C:48:F9:9D:81:5C

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

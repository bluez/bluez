======================
bluetoothctl-transport
======================

-----------------------
Media Transport Submenu
-----------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [transport.commands]

Media Transport Commands
=========================

list
----

List available transports.

:Usage: **# list**

show
----

Show transport information.

:Usage: **# show <transport>**

acquire
-------

Acquire transport.

:Usage: **# acquire <transport> [transport1...]**

release
-------

Release transport.

:Usage: **# release <transport> [transport1...]**

send
----

Send contents of a file.

:Usage: **# send <transport> <filename>**

receive
-------

Get/Set file to receive.

:Usage: **# receive <transport> [filename]**

volume
------

Get/Set transport volume.

:Usage: **# volume <transport> [value]**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

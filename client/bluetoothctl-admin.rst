==================
bluetoothctl-admin
==================

--------------------
Admin Policy Submenu
--------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [admin.commands]

Admin Policy Commands
=====================

allow
-----

Allow service UUIDs and block rest of them.

:Usage: **# allow [clear/uuid1 uuid2 ...]**
:Example: **# allow 0x1101 0x1102 0x1103**
:Example: **# allow clear**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

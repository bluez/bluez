==================
bluetoothctl-admin
==================

--------------------
Admin Policy Submenu
--------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
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

:Usage: **> allow [clear/uuid1 uuid2 ...]**
:[clear/uuid1 uuid2 ...]: List of service UUIDs to allow, or "clear" to remove all restrictions
:Example Get current allowed UUIDs list:
	| **> allow**
:Example Allow Serial Port Profile only:
	| **> allow 0x1101**
:Example Allow Serial Port Profile and LAN Access Profile:
	| **> allow 0x1101 0x1102**
:Example Allow Serial Port Profile, LAN Access Profile, and Dialup Networking Profile:
	| **> allow 0x1101 0x1102 0x1103**
:Example Allow Advanced Audio Distribution Profile only:
	| **> allow 0x110e**
:Example Allow A2DP Source and Sink profiles:
	| **> allow 0x110e 0x110f**
:Example Allow Serial Port Profile using full UUID:
	| **> allow 00001101-0000-1000-8000-00805f9b34fb**
:Example Allow SPP and LAP using full UUIDs:
	| **> allow 00001101-0000-1000-8000-00805f9b34fb 00001102-0000-1000-8000-00805f9b34fb**
:Example Remove all UUID restrictions:
	| **> allow clear**
:Example Allow SPP, LAP, and DUN using mixed UUID formats:
	| **> allow 0x1101 00001102-0000-1000-8000-00805f9b34fb 0x1103**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

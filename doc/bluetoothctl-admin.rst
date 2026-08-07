==================
bluetoothctl-admin
==================

--------------------
Admin Policy Submenu
--------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: June 2026
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [admin.commands]

This submenu configures administrative policies using the
**org.bluez.AdminPolicySet(5)** and **org.bluez.AdminPolicyStatus(5)**
interfaces.

Admin Policy Commands
=====================

allow
-----

Allow service UUIDs and block rest of them.

:Usage: **> allow [ctrl] [clear/uuid1 uuid2 ...]**
:[ctrl]: Bluetooth controller address (optional; defaults to the selected controller)
:Uses: **org.bluez.AdminPolicySet(5)** property **ServiceAllowList**
:[clear/uuid1 uuid2 ...]: List of service UUIDs to allow, or "clear" to remove all restrictions
:Example Get current allowed UUIDs list:
	| **> allow**
:Example Get current allowed UUIDs list for a specific controller:
	| **> allow 00:11:22:33:44:55**
:Example Allow Serial Port Profile only:
	| **> allow 0x1101**
:Example Allow Serial Port Profile on a specific controller:
	| **> allow 00:11:22:33:44:55 0x1101**
:Example Allow Serial Port Profile and LAN Access Profile:
	| **> allow 0x1101 0x1102**
:Example Allow Serial Port Profile and LAN Access Profile on a specific controller:
	| **> allow 00:11:22:33:44:55 0x1101 0x1102**
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
:Example Remove all UUID restrictions on a specific controller:
	| **> allow 00:11:22:33:44:55 clear**
:Example Allow SPP, LAP, and DUN using mixed UUID formats:
	| **> allow 0x1101 00001102-0000-1000-8000-00805f9b34fb 0x1103**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

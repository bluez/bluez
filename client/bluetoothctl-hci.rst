================
bluetoothctl-hci
================

-----------
HCI Submenu
-----------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: December 2024
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [hci.commands]

Commands
========

open
----

Open HCI channel.

:Usage: **> open <index> <chan=raw,user>**
:Example open user channel:
	| In order to open a user channel the controller needs to be power off
	| first:
	| > power off
	| > hci.open 0 user
	| HCI index 0 user channel opened

cmd
---

Send HCI command.

:Usage: **> cmd <opcode> [parameters...]**
:Example send HCI Reset command:
	| > hci.cmd 0x0c03
	| HCI Command complete:
	|  00

send
----

Send HCI data packet.

:Usage: **> send <type=acl,sco,iso> <handle> [data...]**
:Example send ACL data packet to connection handle 0x0000:
	| > hci.send acl 0x0000

register
--------

Register HCI event handler.

:Usage: **> register <event>**

unregister
----------

Unregister HCI event handler.

:Usage: **> unregister <event>**

close
-----

Close HCI channel.

:Usage: **> close <index>**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

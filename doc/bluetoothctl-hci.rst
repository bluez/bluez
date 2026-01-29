================
bluetoothctl-hci
================

-----------
HCI Submenu
-----------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
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
:index: HCI controller index number (e.g., 0, 1, 2)
:chan: Channel type (raw or user)
:Example Open user channel (controller needs to be powered off first):
	| **> power off**
	| **> hci.open 0 user**
	| **HCI index 0 user channel opened**
:Example Open user channel for HCI controller 0:
	| **> hci.open 0 user**
:Example Open user channel for HCI controller 1:
	| **> hci.open 1 user**
:Example Open user channel for HCI controller 2:
	| **> hci.open 2 user**
:Example Open raw channel for HCI controller 0:
	| **> hci.open 0 raw**
:Example Open raw channel for HCI controller 1:
	| **> hci.open 1 raw**

cmd
---

Send HCI command.

:Usage: **> cmd <opcode> [parameters...]**
:opcode: HCI command opcode in hexadecimal format (e.g., 0x0c03)
:parameters: Optional command parameters as hexadecimal bytes
:Example Send HCI Reset command:
	| **> hci.cmd 0x0c03**
	| **HCI Command complete:**
	| **00**
:Example Send HCI Reset command (no parameters):
	| **> hci.cmd 0x0c03**
:Example Send HCI Read Local Version Information:
	| **> hci.cmd 0x1003**
:Example Send HCI Read BD Address:
	| **> hci.cmd 0x1009**
:Example Send HCI Set Event Filter with parameter 0x01:
	| **> hci.cmd 0x0c01 0x01**
:Example Send LE Set Advertising Parameters with 2 parameters:
	| **> hci.cmd 0x200f 0x00 0x08**
:Example Send LE Set Advertising Data with length and data bytes:
	| **> hci.cmd 0x2008 0x20 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08**
:Example Send HCI Set Event Mask command:
	| **> hci.cmd 0x0c05 0x02**
:Example Send HCI Write Scan Enable:
	| **> hci.cmd 0x0c2a 0x01**
:Example Send HCI Write Class of Device:
	| **> hci.cmd 0x0c23 0x00 0x08**

send
----

Send HCI data packet.

:Usage: **> send <type=acl,sco,iso> <handle> [data...]**
:type: Packet type (acl, sco, or iso)
:handle: Connection handle in hexadecimal format (e.g., 0x0000)
:data: Optional data bytes in hexadecimal format
:Example Send ACL data packet to connection handle 0x0000:
	| **> hci.send acl 0x0000**
:Example Send empty ACL packet to handle 0x0000:
	| **> hci.send acl 0x0000**
:Example Send ACL packet with "Hello" data to handle 0x0001:
	| **> hci.send acl 0x0001 0x48 0x65 0x6c 0x6c 0x6f**
:Example Send ACL packet with custom data to handle 0x0010:
	| **> hci.send acl 0x0010 0x01 0x02 0x03 0x04**
:Example Send empty SCO packet to handle 0x0000:
	| **> hci.send sco 0x0000**
:Example Send SCO packet with audio data:
	| **> hci.send sco 0x0001 0xaa 0xbb 0xcc**
:Example Send SCO packet with sine wave pattern:
	| **> hci.send sco 0x0002 0x80 0x00 0x80 0x00**
:Example Send empty ISO packet to handle 0x0000:
	| **> hci.send iso 0x0000**
:Example Send ISO packet with sample data:
	| **> hci.send iso 0x0001 0x12 0x34 0x56 0x78**
:Example Send ISO packet for LE Audio stream:
	| **> hci.send iso 0x0020 0xa0 0xa1 0xa2 0xa3**

register
--------

Register HCI event handler.

:Usage: **> register <event>**
:event: HCI event code in hexadecimal format (e.g., 0x0e)
:Example Register handler for Command Complete event:
	| **> register 0x0e**
:Example Register handler for Command Status event:
	| **> register 0x0f**
:Example Register handler for Connection Complete event:
	| **> register 0x03**
:Example Register handler for Disconnection Complete event:
	| **> register 0x05**
:Example Register handler for LE Meta events:
	| **> register 0x3e**
:Example Register handler for Inquiry Complete event:
	| **> register 0x02**
:Example Register handler for Role Change event:
	| **> register 0x22**

unregister
----------

Unregister HCI event handler.

:Usage: **> unregister <event>**
:event: HCI event code in hexadecimal format (e.g., 0x0e)
:Example Unregister Command Complete event handler:
	| **> unregister 0x0e**
:Example Unregister Command Status event handler:
	| **> unregister 0x0f**
:Example Unregister Connection Complete event handler:
	| **> unregister 0x03**
:Example Unregister Disconnection Complete event handler:
	| **> unregister 0x05**
:Example Unregister LE Meta event handler:
	| **> unregister 0x3e**

close
-----

Close HCI channel.

Closes the currently open HCI channel.

:Usage: **> close**
:Example Close the current HCI channel:
	| **> close**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

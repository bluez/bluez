======================
bluetoothctl-assistant
======================

-----------------
Assistant Submenu
-----------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: August 2024
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [assistant.commands]

Assistant Commands
==================

list
----

List available assistants.

:Usage: **> list**

show
----

Show assistant information.

:Usage: **> show [assistant]**

push
----

Send stream information to peer.

This command is used by a BAP Broadcast Assistant to send
information about a broadcast stream to a peer BAP Scan
Delegator.

The information is sent via a GATT Write Command for the
BASS Broadcast Audio Scan Control Point characteristic.

After issuing the command, the user is prompted to enter
stream metadata LTVs to send to the peer. If the auto
option is chosen, the Broadcast Assistant will send the
default metadata discovered about the stream. Otherwise,
the default metadata will be overwritten by the LTVs
entered by the user.

If the stream is encrypted, the user will also be prompted
to enter the Broadcast Code. This is the key to decrypt the
stream. On the UI level, the Broadcast Code shall be represented
as a string of at least 4 octets, and no more than 16 octets
when represented in UTF-8. The string will be sent to the peer
via GATT as an array of 16 octets.

If the auto value is chosen when prompted for the Broadcast
Code, a zero filled array will be sent to the peer. Otherwise,
the string entered by the user will be sent as an array of bytes.

:Usage: **> push <assistant>**
:Example: | **> push /org/bluez/hci0/src_05_1F_EE_F3_F8_7D/dev_00_60_37_31_7E_3F/bis1**
          | **[Assistant] Enter Metadata (auto/value): 0x03 0x02 0x04 0x00**
          | **[Assistant] Enter Broadcast Code (auto/value): Borne House**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

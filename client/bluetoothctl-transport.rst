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

:Usage: **> list**

show
----

Show transport information.

:Usage: **> show [transport]**

acquire
-------

Acquire transport.

:Usage: **> acquire <transport> [transport1...]**

Note:

If running the setup with an audio server that has LE Audio support (such as PipeWire) it will
automatically acquire transports according to the configured roles.

select
-------

Select transport. For transports created on a Broadcast Sink device only. This moves
the transport to the "broadcasting" state, pending acquire.

:Usage: **> select <transport> [transport1...]**

Note:
If running the setup with an audio server that has LE Audio support (such as PipeWire), it will
prompt it to automatically acquire the transport.

unselect
--------

Unelect transport. For transports created on a Broadcast Sink device only. This moves
the transport to the "idle" state, pending release by the audio server. If the transport
was acquired by bluetoothctl it can be released straight away, without having to be
unselected.

:Usage: **> unselect <transport> [transport1...]**

Note:
If running the setup with an audio server that has LE Audio support (such as PipeWire), it will
prompt it to automatically release the transport.

release
-------

Release transport.

:Usage: **> release <transport> [transport1...]**

Note:

Transports acquired by an audio server, can only be released by said audio server.

send
----

Send contents of a file.

:Usage: **> send <transport> <filename>**

receive
-------

Get/Set file to receive.

:Usage: **> receive <transport> [filename]**

volume
------

Get/Set transport volume.

:Usage: **> volume <transport> [value]**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

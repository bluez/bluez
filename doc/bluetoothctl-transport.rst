======================
bluetoothctl-transport
======================

-----------------------
Media Transport Submenu
-----------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
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

:Example Display all available media transports (A2DP, LE Audio, etc.):
	| **> list**

show
----

Show transport information.

:Usage: **> show [transport]**
:[transport]: Specific transport object path (optional, shows current if omitted)
:Example Show information for currently selected transport:
	| **> show**
:Example Show transport information:
	| **> show /org/bluez/hci0/dev_00_11_22_33_44_55/fd0**
:Example Show Broadcast Isochronous Stream transport:
	| **> show /org/bluez/hci0/dev_11_22_33_44_55_66/bis1**

acquire
-------

Acquire transport.

:Usage: **> acquire <transport> [transport1...]**
:<transport>: Media transport object path to acquire for audio streaming
:[transport1...]: Additional transport paths for multi-stream acquisition (optional)
:Example Acquire transport:
	| **> acquire /org/bluez/hci0/dev_00_11_22_33_44_55/fd0**
:Example Acquire multiple transports:
	| **> acquire /org/bluez/hci0/dev_00_11_22_33_44_55/fd0 /org/bluez/hci0/dev_00_11_22_33_44_55/fd1**

Note:

If running the setup with an audio server that has LE Audio support (such as PipeWire) it will
automatically acquire transports according to the configured roles.

select
-------

Select transport. For transports created on a Broadcast Sink device only. This moves
the transport to the "broadcasting" state, pending acquire.

:Usage: **> select <transport> [transport1...]**
:<transport>: Broadcast sink transport path to move to broadcasting state
:[transport1...]: Additional transport paths for multi-stream selection (optional)
:Example Select single Broadcast Isochronous Stream:
	| **> select /org/bluez/hci0/dev_00_11_22_33_44_55/bis1**
:Example Select stereo broadcast streams:
	| **> select /org/bluez/hci0/dev_00_11_22_33_44_55/bis1 /org/bluez/hci0/dev_00_11_22_33_44_55/bis2**

Note:

If the select command receives a list of transports, they will first be linked using the
"Links" MediaTransport property. They will then be selected one by one, by calling
the "Select" MediaTransport method. After the first transport is acquired, the Broadcast
Sink will create fds for the associated stream and all its links. Each link can then be
acquired one by one, setting the fd for the transport and starting to receive audio.

The select command does not require a local endpoint to be registered beforehand. This is
because if the setup runs with an audio server that has LE Audio support (such as PipeWire),
the audio server is the one to register endpoints and the transports are created as a result.
Once a transport is selected, the audio server will automatically acquire.

unselect
--------

Unselect transport. For transports created on a Broadcast Sink device only. This moves
the transport to the "idle" state, pending release by the audio server. If the transport
was acquired by bluetoothctl it can be released straight away, without having to be
unselected.

:Usage: **> unselect <transport> [transport1...]**
:<transport>: Broadcast sink transport path to move to idle state
:[transport1...]: Additional transport paths for multi-stream unselection (optional)
:Example Unselect broadcast stream transport:
	| **> unselect /org/bluez/hci0/dev_00_11_22_33_44_55/bis1**
:Example Unselect multiple broadcast streams:
	| **> unselect /org/bluez/hci0/dev_00_11_22_33_44_55/bis1 /org/bluez/hci0/dev_00_11_22_33_44_55/bis2**

Note:
If running the setup with an audio server that has LE Audio support (such as PipeWire), it will
prompt it to automatically release the transport.

release
-------

Release transport.

:Usage: **> release <transport> [transport1...]**
:<transport>: Media transport object path to release from audio streaming
:[transport1...]: Additional transport paths for multi-stream release (optional)
:Example Release transport:
	| **> release /org/bluez/hci0/dev_00_11_22_33_44_55/fd0**
:Example Release multiple transports:
	| **> release /org/bluez/hci0/dev_00_11_22_33_44_55/fd0 /org/bluez/hci0/dev_00_11_22_33_44_55/fd1**

Note:

Transports acquired by an audio server, can only be released by said audio server.

send
----

Send contents of a file.

:Usage: **> send <transport> <filename> [transport1...]**
:<transport>: Media transport object path to send audio data through
:<filename>: Path to audio file to transmit (supports WAV, MP3, PCM formats)
:[transport1...]: Additional transport paths for multi-stream sending (optional)
:Example Send encoded audio file via transport:
	| **> send /org/bluez/hci0/dev_00_11_22_33_44_55/fd0 /home/user/music.<format>**
:Example Send to multiple transports simultaneously:
	| **> send /org/bluez/hci0/dev_00_11_22_33_44_55/fd0 /home/user/stereo-left.<format> /org/bluez/hci0/dev_00_11_22_33_44_55/fd1 /home/user/stereo-rigth.<format>**

receive
-------

Get/Set file to receive.

:Usage: **> receive <transport> [filename]**
:<transport>: Media transport object path to receive audio data from
:[filename]: Path to save received audio data (optional, shows current if omitted)
:Example Show current receive file for transport:
	| **> receive /org/bluez/hci0/dev_00_11_22_33_44_55/fd0**
:Example Set file to receive audio data:
	| **> receive /org/bluez/hci0/dev_00_11_22_33_44_55/fd0 /tmp/recorded_audio.wav**
:Example Set file for broadcast audio capture (note quotes):
	| **> receive /org/bluez/hci0/dev_11_22_33_44_55_66/bis1 "/home/user/My Recordings/broadcast.wav"**

volume
------

Get/Set transport volume.

:Usage: **> volume <transport> [value]**
:<transport>: Media transport object path to control volume for
:[value]: Volume level (0-127, optional, shows current if omitted)
:Example Show current volume level:
	| **> volume /org/bluez/hci0/dev_00_11_22_33_44_55/fd0**
:Example Set volume to 100:
	| **> volume /org/bluez/hci0/dev_00_11_22_33_44_55/fd0 100**

metadata
--------

Get/Set Transport Metadata.

:Usage: **> metadata <transport> [value...]**
:<transport>: Media transport object path
:[value...]: Metadata value as hex string (optional, shows current if omitted)
:Example Show current metadata for transport:
	| **> metadata /org/bluez/hci0/dev_00_11_22_33_44_55/fd0**
:Example Set metadata value:
	| **> metadata /org/bluez/hci0/dev_00_11_22_33_44_55/fd0 0x03020100**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

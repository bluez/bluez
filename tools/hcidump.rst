=======
hcidump
=======

--------------
Parse HCI data
--------------

:Authors: - Maxim Krasnyansky <maxk@qualcomm.com>
          - Marcel Holtmann <marcel@holtmann.org>
          - Fabrizio Gennari <fabrizio.gennari@philips.com>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: Nov 12, 2002
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**hcidump** -h

**hcidump** [OPTIONS ...] [FILTERS]

DESCRIPTION
===========

**hcidump(1)** reads raw HCI data coming from and going to a Bluetooth device
(which can be specified with the option **-i**, default is the first available
one) and prints to screen commands, events and data in a human-readable form.
Optionally, the dump can be written to a file rather than parsed, and the dump
file can be parsed in a subsequent moment.

OPTIONS
=======

-i <hciX>
    Data is read from *hciX*, which must be the name of an installed Bluetooth
    device. If not specified, and if **-r** option is not set, data is read from
    the first available Bluetooth device.

-l <len>, --snap-len=<len>
    Sets max length of processed packets to *len*.

-p <psm>, --psm=<psm>
    Sets default Protocol Service Multiplexer to *psm*.

-m <compid>, --manufacturer=<compid>
    Sets default company id for manufacturer to *compid*.

-w <file>, --save-dump=<file>
    Parse output is not printed to screen, instead data read from device is
    saved in *file*. The saved dump file can be subsequently parsed with
    option **-r**.

-r <file>, --read-dump=<file>
    Data is not read from a Bluetooth device, but from *file*. *file* is
    created with option **-t**, **--timestamp** prepend a time stamp to every
    packet.

-a, --ascii
    For every packet, not only is the packet type displayed, but also all data
    in ASCII.

-x, --hex
    For every packet, not only is the packet type displayed, but also all data
    in hex.

-X, --ext
    For every packet, not only is the packet type displayed, but also all data
    in hex and ASCII.

-R, --raw
    For every packet, only the raw data is displayed.

-C <psm>, --cmtp=<psm>
    Sets the PSM value for the CAPI Message Transport Protocol.

-H <psm>, --hcrp=<psm>
    Sets the PSM value for the Hardcopy Control Channel.

-O <channel>, --obex=<channel>
    Sets the RFCOMM channel value for the Object Exchange Protocol.

-P <channel>, --ppp=<channel>
    Sets the RFCOMM channel value for the Point-to-Point Protocol.

-D <file>, --pppdump=<file>
    Extract PPP traffic with pppdump format.

-A <file>, --audio=<file>
    Extract SCO audio data.

-Y, --novendor
    Don't display any vendor commands or events and don't show any pin code or
    link key in plain text.

-h
    Prints usage info and exits

FILTERS
=======

filter is a space-separated list of packet categories: available categories are
*lmp*, *hci*, *sco*, *l2cap*, *rfcomm*, *sdp*, *bnep*, *cmtp*, *hidp*, *hcrp*,
*avdtp*, *avctp*, *obex*, *capi* and *ppp*. If filters are used, only packets
belonging to the specified categories are dumped. By default, all packets are
dumped.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

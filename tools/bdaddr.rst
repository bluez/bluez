======
bdaddr
======

-------------------------------------------------
Utility for changing the Bluetooth device address
-------------------------------------------------

:Authors: - Marcel Holtmann <marcel@holtmann.org>
          - Adam Laurie <adam@algroup.co.uk>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: Sep 27, 2005
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bdaddr**

**bdaddr** -h

**bdaddr** [-i <*dev*>] [-r] [-t] [*new_bdaddr*]

DESCRIPTION
===========

**bdaddr(1)** is used to query or set the local Bluetooth device address
(BD_ADDR). If run with no arguments, **bdaddr** prints the chip manufacturer's
name, and the current BD_ADDR. If the IEEE OUI index file "oui.txt" is
installed on the system, the BD_ADDR owner will be displayed. If the optional
[*new_bdaddr*]  argument is given, the device will be reprogrammed with that
address. This can either be permanent or temporary, as specified by the -t
flag. In both cases, the device must be reset before the new address will
become active. This can be done with a 'soft' reset by specifying the  -r
flag, or a 'hard' reset by removing and replugging the device. A 'hard' reset
will cause the address to revert to the current non-volatile value.

**bdaddr** uses manufacturer specific commands to set the address, and is
therefore device specific. For this reason, not all devices are supported,
and not all options are supported on all devices. Current supported
manufacturers are: **Ericsson**, **Cambridge Silicon Radio (CSR)**,
**Texas  Instruments (TI)**, **Zeevo** and **ST Microelectronics (ST)**.

OPTIONS
=======

-h      Gives a list of possible commands.

-i <dev>    Specify a particular device to operate on. If not specified,
            default is the first available device.

-r          Reset device and make new BD_ADDR active.  CSR devices only.

-t          Temporary change. Do not write to non-volatile memory.
            CSR devices only.

FILES
=====

/usr/share/misc/oui.txt
    IEEE Organizationally Unique Identifier consolidated file.
    Manually update from: http://standards.ieee.org/regauth/oui/oui.txt


RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

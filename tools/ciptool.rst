========
ciptool
========

------------------------------------------
Bluetooth Common ISDN Access Profile (CIP)
------------------------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: June 3, 2003
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**ciptool** [*OPTIONS*] *COMMANDS*

DESCRIPTION
===========

**ciptool(1)** is used to set up, maintain, and inspect the CIP configuration
of the Bluetooth subsystem in the Linux kernel.

OPTIONS
=======

-i <hciX|BDADDR>    The command is applied to device *hciX* , which must be the
                    name or the address of an installed Bluetooth device.

                    If not specified, the command will be use the first
                    available Bluetooth device.

-h, --help          Show help options

COMMANDS
========

show
    Display information about the connected devices.

search
    Search for Bluetooth devices and connect to first one that offers CIP
    support.

connect <*BDADDR*> [*PSM*]
    Connect the local device to the remote Bluetooth device on the specified
    *PSM* number. If no *PSM* is specified,  it will use the SDP to retrieve
    it from the remote device.

release [*BDADDR*]
    Release a connection to the specific device. If no *BDADDR* is given and
    only one device is connected this will be released.

loopback <*BDADDR*> [*PSM*]
    Create a connection to the remote device for Bluetooth testing. This
    command will not provide a CAPI controller, because it is only for
    testing the CAPI Message Transport Protocol.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

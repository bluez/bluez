======
l2ping
======

------------------------------------------
Send L2CAP echo request and receive answer
------------------------------------------

:Authors: - Maxim Krasnyansky <maxk@qualcomm.com>
          - Marcel Holtmann <marcel@holtmann.org>
          - Nils Faerber <nils@kernelconcepts.de>
          - Adam Laurie <adam@algroup.co.uk>.
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: Jan 22, 2002
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**l2ping** [*OPTIONS*] *bd_addr*

DESCRIPTION
===========

**l2ping(1)** sends a L2CAP echo request to the Bluetooth MAC address bd_addr
given in dotted hex notation.

OPTIONS
=======

-i <hciX>       The command is applied to device *hciX*, which must be the
                name of an installed Bluetooth device (X = 0, 1, 2, ...)
                If not specified, the command will be sent to the first
                available Bluetooth device.

-s size         The size of the data packets to be sent.

-c count        Send count number of packets then exit.

-t timeout      Wait timeout seconds for the response.

-d delay        Wait delay seconds between pings.

-f              Kind of flood ping. Use with care! It reduces the delay time
                between packets to 0.

-r              Reverse ping (gnip?). Send echo response instead of echo
                request.

-v              Verify response payload is identical to request payload.
                It is not required for remote stacks to return the request
                payload, but most stacks do (including Bluez).

bd_addr
    The Bluetooth MAC address to be pinged in dotted hex notation
    like **01:02:03:ab:cd:ef** or **01:EF:cd:aB:02:03**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

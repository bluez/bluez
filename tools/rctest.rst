======
rctest
======

--------------
RFCOMM testing
--------------

:Authors: - Maxim Krasnyansky <maxk@qualcomm.com>
          - Marcel Holtmann <marcel@holtmann.org>
          - Filippo Giunchedi <filippo@debian.org>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: Jul 6, 2009
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**rctest** <*MODE*> [*OPTIONS*] [*bdaddr*]

DESCRIPTION
===========

**rctest(1)** is used to test RFCOMM communications on the BlueZ stack

MODES
=====

-r      listen and receive
-w      listen and send
-d      listen and dump incoming data
-s      connect and send
-u      connect and receive
-n      connect and be silent
-c      connect, disconnect, connect, ...
-m      multiple connects

OPTIONS
=======
-b bytes        send/receive bytes

-i device       select the specified device

-P channel      select the specified channel

-U uuid         select the specified uuid

-L seconds      enable SO_LINGER options for seconds

-W seconds      enable deferred setup for seconds

-B filename     use data packets from filename

-N num          send num frames

-C num          send num frames before delay (default: 1)

-D milliseconds     delay milliseconds after sending num frames (default: 0)

-A              request authentication

-E              request encryption

-S              secure connection

-M              become central

-T              enable timestamps

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

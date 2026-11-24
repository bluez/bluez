========
btattach
========

------------------------------------
Attach serial devices to BlueZ stack
------------------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2015
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**btattach** [**-B** *device*] [**-A** *device*] [**-P** *protocol*] [**-R**]

DESCRIPTION
===========

**btattach(1)** is used to attach a serial UART to the Bluetooth stack as a
transport interface.

OPTIONS
=======

-B device, --brder device   Attach a BR/EDR controller

-A device, --amp device     Attach an AMP controller

-P protocol, --protocol protocol    Specify the protocol type for talking to the
                                    device.

                                    Supported values are:

.. list-table::
   :header-rows: 1
   :widths: auto

   * - *protocol*

   * - h4

   * - bcsp

   * - 3wire

   * - h4ds

   * - ll

   * - ath3k

   * - intel

   * - bcm

   * - qca

-S baudrate, --speed baudrate       Specify which baudrate to use

-N, --noflowctl            Disable flow control

-v, --version              Show version

-h, --help                 Show help options

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

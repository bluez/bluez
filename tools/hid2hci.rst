========
hid2hci
========

-------------------------------------------
Bluetooth HID to HCI mode switching utility
-------------------------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: May 15, 2009
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**hid2hci** [*OPTIONS*]

DESCRIPTION
===========

**hid2hci(1)** is used to set up switch supported Bluetooth devices into the
HCI mode and back.

OPTIONS
=======

--mode=[*mode*]         Sets the mode to the device into. The possible values
                        for *mode* are **hid**, **hci**.

--method=[*method*]     Which vendor method to use for switching the device.
                        The possible values for *method* are **csr**, **csr2**,
                        **logitech-hdi**, **dell**.

--devpath               Specifies the device path in /sys

--help                  Gives a list of possible options.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

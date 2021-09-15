=========
hciconfig
=========

---------------------------
Configure Bluetooth devices
---------------------------

:Authors: - Maxim Krasnyansky <maxk@qualcomm.com>
          - Marcel Holtmann <marcel@holtmann.org>
          - Fabrizio Gennari <fabrizio.gennari@philips.com>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: Nov 11, 2002
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**hciconfig** -h

**hciconfig** [-a]

**hciconfig** [-a] *hciX* [*COMMAND* [*PARAMETERS*]]

DESCRIPTION
===========

**hciconfig(1)** is used to configure Bluetooth devices. *hciX* is the name of a
Bluetooth device installed in the system. If hciX is not given, hciconfig
prints name and basic information about all the Bluetooth devices installed
in the system.

If *hciX* is given but no command is given, it prints basic information on
device *hciX* only. Basic information is interface type, BD address, ACL MTU,
SCO MTU, flags (up, init, running, raw, page scan enabled, inquiry scan
enabled, inquiry, authentication enabled, encryption enabled).

OPTIONS
=======

-a, --all   Print features, packet type, link policy, link mode, class, Version
            other than the basic info.
-h, --help  Show help options

COMMANDS
========

up
    Open and initialize HCI device.

down
    Close HCI device.

reset
    Reset HCI device.

rstat
    Reset statistic counters.

auth
    Enable authentication (sets device to security mode 3).

noauth
    Disable authentication.

encrypt
    Enable encryption (sets device to security mode 3).

noencrypt
    Disable encryption.

secmgr
    Enable security manager (current kernel support is limited).

nosecmgr
    Disable security manager.

piscan
    Enable page and inquiry scan.

noscan
    Disable page and inquiry scan.

iscan
    Enable inquiry scan, disable page scan.

pscan
    Enable page scan, disable inquiry scan.

ptype [*type*]
    With  no *type* , displays the current packet types. Otherwise, all the
    packet types specified by *type* are set. *type* is a comma-separated list
    of packet types, where the possible packet types are **DM1**, **DM3**,
    **DM5**, **DH1**, **DH3**, **DH5**, **HV1**, **HV2**, **HV3**.

name [*name*]
    With no *name*, prints local name. Otherwise, sets local name to *name*.

class [*class*]
    With  no *class*, prints class of device. Otherwise, sets class of device
    to *class*. *class* is a 24-bit hex number describing the class of device,
    as specified in section 1.2 of the Bluetooth Assigned Numers document.

voice [*voice*]
    With no *voice*, prints voice setting. Otherwise, sets voice setting to
    *voice*. *voice* is a 16-bit hex number describing the voice setting.

iac [*iac*]
    With no *iac*, prints the current IAC setting. Otherwise, sets the IAC to
    *iac*.

inqtpl [*level*]
    With no *level*, prints out the current inquiry transmit power level.
    Otherwise, sets inquiry transmit power level to *level*.

inqmode [*mode*]
    With no *mode*, prints out the current inquiry mode. Otherwise, sets
    inquiry mode to *mode*.

 .. list-table::
    :header-rows: 1
    :widths: auto

    * - *mode*
      - Description

    * - 0
      - Standard Inquiry

    * - 1
      - Inquiry with RSSI

    * - 2
      - Inquiry with RSSI or Extended Inquiry

inqdata [*data*]
    With no *data*, prints out the current inquiry data. Otherwise, sets
    inquiry data to *data*.

inqtype [*type*]
    With no *type*, prints out the current inquiry scan type. Otherwise, sets
    inquiry scan type to *type*.

inqparams [*win:int*]
    With no *win:int*, prints inquiry scan window and interval. Otherwise,
    sets inquiry scan window  to *win* slots and inquiry scan interval to
    *int* slots.

pageparms [*win:int*]
    With no *win:int*, prints page scan window and interval. Otherwise,
    sets page scan window to *win* slots and page scan interval to *int* slots.

pageto [*to*]
    With no *to*, prints page timeout. Otherwise, sets page timeout *to* to
    slots.

afhmode [*mode*]
    With no *mode*, prints out the current AFH mode. Otherwise, sets AFH mode
    to *mode*.

.. list-table::
   :header-rows: 1
   :widths: auto

   * - *mode*
     - Description

   * - 0
     - Enable

   * - 1
     - Disable

sspmode [*mode*]
    With no *mode*, prints out the current Simple Pairing mode. Otherwise,
    sets Simple Pairing mode to *mode*.

.. list-table::
   :header-rows: 1
   :widths: auto

   * - *mode*
     - Description

   * - 0
     - Enable

   * - 1
     - Disable

aclmtu *mtu:pkt*
    Sets ACL MTU to *mtu* bytes and ACL buffer size to *pkt* packets.

scomtu *mtu:pkt*
    Sets SCO MTU to *mtu* bytes and SCO buffer size to *pkt* packets.

delkey <*bdaddr*>
    This command deletes the stored link key for *bdaddr* from the device.

oobdata
    Get local OOB data (invalidates previously read data).

commands
    Display supported commands.

features
    Display device features.

version
    Display version information.

revision
    Display revision information.

lm [*mode*]
    With no *mode*, prints link mode. **CENTRAL** or **PERIPHERAL** mean,
    respectively, to ask to become central or to remain peripheral when a
    connection request comes in. The additional keyword **ACCEPT** means that
    baseband connections will be accepted even if there are no listening
    *AF_BLUETOOTH* sockets. *mode* is **NONE** or a comma-separated list of
    keywords, where possible keywords are **CENTRAL** and **ACCEPT**. **NONE**
    sets link policy to the default behaviour of remaining peripheral and not
    accepting baseband connections when there are no listening *AF_BLUETOOTH*
    sockets.  If **CENTRAL** is  present, the device will ask to become central
    if a connection request comes in. If **ACCEPT** is present, the device will
    accept baseband connections even when there are no listening *AF_BLUETOOTH*
    sockets.

block <*bdaddr*>
    Add a device to the reject list

unblock <*bdaddr*>
    Remove a device from the reject list

lerandaddr <*bdaddr*>
    Set LE Random Address

leadv [*type*]
    Enable LE Advertising.

.. list-table::
    :header-rows: 1
    :widths: auto

    * - *type*
      - Description

    * - 0
      - Connectable undirected advertising (default)

    * - 3
      - Non connectable undirected advertising

noleadv
    Disable LE Advertising

lestates
    Display the supported LE states

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

=======
hcitool
=======

-------------------------------
Configure Bluetooth connections
-------------------------------

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

**hcitool** -h

**hcitool** *COMMAND* --help

**hcitool** [-i *hciX*] [*COMMAND* [*PARAMETERS*]]

DESCRIPTION
===========

**hcitool(1)** is used to configure Bluetooth connections and send some special
command to Bluetooth devices. If no **command** is given, or if the option
**-h** is used, *hcitool* prints some usage information and exits.

OPTIONS
=======

-i <hciX>   The command is applied to device *hciX*, which must be the name of
            an installed Bluetooth device. If not specified, the command will
            be sent to the first available Bluetooth device.

-h          Gives a list of possible commands

COMMANDS
========

dev
    Display local devices

inq
    Inquire remote devices. For each discovered device, Bluetooth device
    address, clock offset and class are printed.

scan
    Inquire remote devices. For each discovered device, device name are printed.

name <*bdaddr*>
    Print device name of remote device with Bluetooth address *bdaddr*.

info <*bdaddr*>
    Print device name, version and supported features of remote device with
    Bluetooth address *bdaddr*.

spinq
    Start periodic inquiry process. No inquiry results are printed.

epinq
    Exit periodic inquiry process.

cmd <*ogf*> <*ocf*> [*parameters*]
    Submit an arbitrary HCI command to local device. *ogf*, *ocf* and
    parameters are hexadecimal bytes.

con
    Display active baseband connections

cc [--*role*\=c|p] [--*pkt-type*\=<*ptype*>] <*bdaddr*>
    Create baseband connection to remote device with Bluetooth address *bdaddr*.

    Option **--pkt-type** specifies a list  of  allowed packet types.
    <*ptype*> is a comma-separated list of packet types, where the possible
    packet types are **DM1**, **DM3**, **DM5**, **DH1**, **DH3**, **DH5**,
    **HV1**, **HV2**, **HV3**. Default is to allow all packet types.

    Option  **--role** can have value **c** (do not allow role switch, stay
    central) or **p** (allow role switch, become peripheral if the peer asks to
    become central). Default is **c**.

dc <*bdaddr*> [*reason*]
    Delete baseband connection from remote device with Bluetooth address
    *bdaddr*.

    The reason can be one of the Bluetooth HCI error codes.
    Default is **19** for user ended connections. The value must be given in
    decimal.

sr <*bdaddr*> <*role*>
    Switch role for the baseband connection from the remote device to
    **central** or **peripheral**.

cpt <*bdaddr*> <*ptypes*>
    Change packet types for baseband connection to device with Bluetooth
    address *bdaddr*. *ptypes* is a comma-separated list of packet types,
    where the possible packet types are **DM1**, **DM3**, **DM5**, **DH1**,
    **DH3**, **DH5**, **HV1**, **HV2**, **HV3**.

rssi <*bdaddr*>
    Display received signal strength information for the connection to the
    device with Bluetooth address *bdaddr*.

lq <*bdaddr*>
    Display link quality for the connection to the device with Bluetooth
    address *bdaddr*.

tpl <*bdaddr*> [*type*]
    Display transmit power level for the connection to the device with
    Bluetooth address *bdaddr*.

    The *type* can be **0** for the current transmit power level (which is
    default) or **1** for the maximum transmit power level.

afh <*bdaddr*>
    Display AFH channel map for the connection to the device with Bluetooth
    address *bdaddr*.

lp <*bdaddr*> [*value*]
    With no value, displays link policy settings for the connection to the
    device with Bluetooth address *bdaddr*.

    If *value* is given, sets the link policy settings for that connection to
    *value*. Possible values are **RSWITCH**, **HOLD**, **SNIFF** and **PARK**.

lst <*bdaddr*> [*value*]
    With no value, displays link supervision timeout for the connection to
    the device with Bluetooth address *bdaddr*.

    If *value* is given, sets the link supervision timeout for that connection
    to *value* slots, or to infinite if value is 0.

auth <*bdaddr*>
    Request authentication for the device with Bluetooth address *bdaddr*.

enc <*bdaddr*> [*encrypt*]
    **enable** or **disable** the encryption for the device with Bluetooth
    address *bdaddr*.

key <*bdaddr*>
    Change the connection link key for the device with Bluetooth address
    *bdaddr*.

clkoff <*bdaddr*>
    Read the clock offset for the device with Bluetooth address *bdaddr*.

clock [*bdaddr*] [*clock*]
    Read the clock for the device with Bluetooth address *bdaddr*.

    The *clock* can be **0** for the local clock or **1** for the piconet
    clock (which is default).

lescan [--*privacy*] [--*passive*] [--*acceptlist*] [--*discovery*\=g|l] [--*duplicates*]
    Start LE scan

leinfo [--*static*] [--*random*] <*bdaddr*>
    Get LE remote information

lealadd [--*random*] <*bdaddr*>
    Add device to LE Accept List

lealrm <*bdaddr*>
    Remove device from LE Accept List

lealsz
    Read size of LE Accept List

lealclr
    Clear LE Accept List

lerladd [--*local_irk*] [--*peer_irk*] [--*random*] <*bdaddr*>
    Add device to LE Resolving List

lerlrm <*bdaddr*>
    Remove device from LE Resolving List

lerlclr
    Clear LE Resolving List

lerlsz
    Read size of LE Resolving List

lerlon
    Enable LE Address Resolution

lerloff
    Disable LE Address Resolution

lecc [--*static*] [--*random*] <*bdaddr*> | [--*acceptlist*]
    Create a LE Connection

ledc <*handle*> [*reason*]
    Disconnect a LE Connection

lecup <*handle*> <*min*> <*max*> <*latency*> <*timeout*>
    LE Connection Update

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

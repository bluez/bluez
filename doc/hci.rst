===
hci
===

----------------------
Bluetooth HCI protocol
----------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: October 2024
:Manual section: 7
:Manual group: Linux System Administration

SYNOPSIS
========

.. code-block::

    #include <sys/socket.h>
    #include <bluetooth/bluetooth.h>
    #include <bluetooth/hci.h>

    hci_socket = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);

DESCRIPTION
===========

Bluetooth Host Controller Interface (HCI) is the standard protocol to
communicate with Bluetooth adapters. HCI protocol provides a uniform command
method for the Host to access Controller capabilities and to control connections
to other Controllers.

SOCKET ADDRESS
==============

.. code-block::

    struct sockaddr_hci {
        sa_family_t    hci_family;
        unsigned short hci_dev;
        unsigned short hci_channel;
    };

Possible values for hci_channel:

.. csv-table::
    :header: "Define", "Value", "Description"
    :widths: auto

    **HCI_CHANNEL_RAW**, 0x00, Raw channel - Used for raw HCI communication
    **HCI_CHANNEL_USER**, 0x01, User channel - Used for userspace HCI communication (disables kernel processing)
    **HCI_CHANNEL_MONITOR**, 0x02, Monitor channel - Used for monitoring HCI traffic (btmon(1))
    **HCI_CHANNEL_CONTROL**, 0x03, Control channel - Used to manage local adapters (bluetoothd(7))
    **HCI_CHANNEL_LOGGING**, 0x04, Logging channel - Used to inject logging messages (bluetoothd(7))

Example:

.. code-block::

    struct sockaddr_hci addr;

    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = HCI_DEV_NONE;
    addr.hci_channel = HCI_CHANNEL_CONTROL;

SOCKET OPTIONS
==============

The socket options listed below can be set by using **setsockopt(2)** and read
with **getsockopt(2)** with the socket level set to SOL_BLUETOOTH or SOL_HCI
(HCI_FILTER).

HCI_FILTER (since Linux 2.6)
----------------------------

Filter by HCI events, requires hci_channel to be set to HCI_CHANNEL_RAW,
possible values:

.. code-block::

    struct hci_filter {
        uint32_t type_mask;
        uint32_t event_mask[2];
        uint16_t opcode;
    };

Example:

.. code-block::

    struct hci_filter flt;

    memset(&flt, 0, sizeof(flt));
    flt.type_mask = 1 << BT_H4_EVT_PKT;
    flt.event_mask[0] = 0xffffffff;
    flt.event_mask[1] = 0xffffffff;

    setsockopt(fd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt));

BT_SNDBUF (since Linux 5.16)
----------------------------

Set send buffer size, requires hci_channel to be set to HCI_CHANNEL_MONITOR,
HCI_CHANNEL_CONTROL or HCI_CHANNEL_LOGGING.

Default value is 1028.

Example:

.. code-block::

    uint16_t mtu = UINT16_MAX;
    int err;

    err = setsockopt(fd, SOL_BLUETOOTH, BT_SNDMTU, &mtu, sizeof(mtu));

BT_RCVBUF (since Linux 5.16)
----------------------------

Set receive buffer size, requires hci_channel to be set to HCI_CHANNEL_MONITOR,
HCI_CHANNEL_CONTROL or HCI_CHANNEL_LOGGING.

Default value is 1028.

Example:

.. code-block::

    uint16_t mtu;
    socklen_t len;
    int err;

    len = sizeof(mtu);
    err = getsockopt(sock, SOL_BLUETOOTH, BT_RCVMTU, mtu, &len);

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

SEE ALSO
========

socket(7)

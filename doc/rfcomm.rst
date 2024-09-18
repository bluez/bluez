======
rfcomm
======

---------------
RFCOMM protocol
---------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: May 2024
:Manual section: 7
:Manual group: Linux System Administration

SYNOPSIS
========

.. code-block::

    #include <sys/socket.h>
    #include <bluetooth/bluetooth.h>
    #include <bluetooth/rfcomm.h>

    rfcomm_socket = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);

DESCRIPTION
===========

The RFCOMM protocol provides emulation of serial ports over the L2CAP(7)
protocol. The protocol is based on the ETSI standard TS 07.10.

RFCOMM is a simple transport protocol, with additional provisions for emulating
the 9 circuits of RS-232 (EIATIA-232-E) serial ports.

SOCKET ADDRESS
==============

.. code-block::

    struct sockaddr_rc {
        sa_family_t rc_family;
        unsigned short rc_bdaddr;
        unsigned char rc_channel;
    };

Example:

.. code-block::

    struct sockaddr_rc addr;

    memset(&addr, 0, sizeof(addr));
    addr.rc_family = AF_BLUETOOTH;
    bacpy(&addr.rc_bdaddr, bdaddr);
    addr.rc_channel = channel;

SOCKET OPTIONS
==============

The socket options listed below can be set by using **setsockopt(2)** and read
with **getsockopt(2)** with the socket level set to SOL_BLUETOOTH.

BT_SECURITY (since Linux 2.6.30)
--------------------------------

Channel security level, possible values:

.. csv-table::
    :header: "Value", "Security Level", "Link Key Type", "Encryption"
    :widths: auto

    **BT_SECURITY_SDP**, 0 (SDP Only), None, Not required
    **BT_SECURITY_LOW**, 1 (Low), Unauthenticated, Not required
    **BT_SECURITY_MEDIUM**, 2 (Medium - default), Unauthenticated, Desired
    **BT_SECURITY_HIGH**, 3 (High), Authenticated, Required
    **BT_SECURITY_FIPS** (since Linux 3.15), 4 (Secure Only), Authenticated (P-256 based Secure Simple Pairing and Secure Authentication), Required

Example:

.. code-block::

    int level = BT_SECURITY_HIGH;
    int err = setsockopt(rfcomm_socket, SOL_BLUETOOTH, BT_SECURITY, &level,
                         sizeof(level));
    if (err == -1) {
        perror("setsockopt");
        return 1;
    }

BT_DEFER_SETUP (since Linux 2.6.30)
-----------------------------------

Channel defer connection setup, this control if the connection procedure
needs to be authorized by userspace before responding which allows
authorization at profile level, possible values:

.. csv-table::
    :header: "Value", "Description", "Authorization"
    :widths: auto

    **0**, Disable (default), Not required
    **1**, Enable, Required

Example:

.. code-block::

    int defer_setup = 1;
    int err = setsockopt(rfcomm_socket, SOL_BLUETOOTH, BT_DEFER_SETUP,
                         &defer_setup, sizeof(defer_setup));
    if (err == -1) {
        perror("setsockopt");
        return err;
    }

    err = listen(rfcomm_socket, 5);
    if (err) {
        perror("listen");
        return err;
    }

    struct sockaddr_rc remote_addr = {0};
    socklen_t addr_len = sizeof(remote_addr);
    int new_socket = accept(rfcomm_socket, (struct sockaddr*)&remote_addr,
                            &addr_len);
    if (new_socket < 0) {
        perror("accept");
        return new_socket;
    }

    /* To complete the connection setup of new_socket read 1 byte */
    char c;
    struct pollfd pfd;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = new_socket;
    pfd.events = POLLOUT;

    err = poll(&pfd, 1, 0);
    if (err) {
        perror("poll");
        return err;
    }

    if (!(pfd.revents & POLLOUT)) {
        err = read(sk, &c, 1);
        if (err < 0) {
            perror("read");
            return err;
        }
    }

BT_FLUSHABLE (since Linux 2.6.39)
---------------------------------

Channel flushable flag, this control if the channel data can be flushed or
not, possible values:

.. csv-table::
    :header: "Define", "Value", "Description"
    :widths: auto

    **BT_FLUSHABLE_OFF**, 0x00 (default), Do not flush data
    **BT_FLUSHABLE_ON**, 0x01, Flush data

BT_POWER (since Linux 3.1)
--------------------------

Channel power policy, this control if the channel shall force exit of sniff
mode or not, possible values:

.. csv-table::
    :header: "Define", "Value", "Description"
    :widths: auto

    **BT_POWER_FORCE_ACTIVE_OFF**, 0x00 (default), Don't force exit of sniff mode
    **BT_POWER_FORCE_ACTIVE_ON**, 0x01, Force exit of sniff mode

BT_CHANNEL_POLICY (since Linux 3.10)
------------------------------------

High-speed (AMP) channel policy, possible values:

.. csv-table::
    :header: "Define", "Value", "Description"
    :widths: auto

    **BT_CHANNEL_POLICY_BREDR_ONLY**, 0 (default), BR/EDR only
    **BT_CHANNEL_POLICY_BREDR_PREFERRED**, 1, BR/EDR Preferred
    **BT_CHANNEL_POLICY_BREDR_PREFERRED**, 2, AMP Preferred

BT_PHY (since Linux 5.10)
-------------------------

Channel supported PHY(s), possible values:

.. csv-table::
    :header: "Define", "Value", "Description"
    :widths: auto

    **BT_PHY_BR_1M_1SLOT**, BIT 0, BR 1Mbps 1SLOT
    **BT_PHY_BR_1M_3SLOT**, BIT 1, BR 1Mbps 3SLOT
    **BT_PHY_BR_1M_5SLOT**, BIT 2, BR 1Mbps 5SLOT
    **BT_PHY_BR_2M_1SLOT**, BIT 3, EDR 2Mbps 1SLOT
    **BT_PHY_BR_2M_3SLOT**, BIT 4, EDR 2Mbps 3SLOT
    **BT_PHY_BR_2M_5SLOT**, BIT 5, EDR 2Mbps 5SLOT
    **BT_PHY_BR_3M_1SLOT**, BIT 6, EDR 3Mbps 1SLOT
    **BT_PHY_BR_3M_3SLOT**, BIT 7, EDR 3Mbps 3SLOT
    **BT_PHY_BR_3M_5SLOT**, BIT 8, EDR 3Mbps 5SLOT

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

SEE ALSO
========

socket(7), rctest(1)

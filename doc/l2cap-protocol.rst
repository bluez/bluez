=====
l2cap
=====

--------------
L2CAP protocol
--------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: May 2024
:Manual section: 7
:Manual group: Linux System Administration

SYNOPSIS
========

.. code-block::

    #include <sys/socket.h>
    #include <bluetooth/bluetooth.h>
    #include <bluetooth/l2cap.h>

    l2cap_socket = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);

DESCRIPTION
===========

L2CAP is a protocol that provides an interface for higher-level protocols to
send and receive data over a Bluetooth connection. L2CAP sits on top of the
Bluetooth Host Controller Interface (HCI) and provides a set of channels that
can be used by higher-level protocols to transmit data.

L2CAP provides a number of services to higher-level protocols, including
segmentation and reassembly of large data packets and flow control to prevent
overloading of the receiver. L2CAP also supports multiple channels per
connection, allowing for concurrent data transmission using different protocols.

SOCKET ADDRESS
==============

.. code-block::

    struct sockaddr_l2 {
        sa_family_t	l2_family;
        unsigned short	l2_psm;
        bdaddr_t	l2_bdaddr;
        unsigned short	l2_cid;
        uint8_t		l2_bdaddr_type;
    };

Example:

.. code-block::

    struct sockaddr_l2 addr;

    memset(&addr, 0, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    bacpy(&addr.l2_bdaddr, bdaddr);

    if (cid)
        addr.l2_cid = htobs(cid);
    else
        addr.l2_psm = htobs(psm);

    addr.l2_bdaddr_type = bdaddr_type;

SOCKET OPTIONS (SOL_BLUETOOTH)
==============================

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
    int err = setsockopt(l2cap_socket, SOL_BLUETOOTH, BT_SECURITY, &level,
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
    int err = setsockopt(l2cap_socket, SOL_BLUETOOTH, BT_DEFER_SETUP,
                         &defer_setup, sizeof(defer_setup));
    if (err == -1) {
        perror("setsockopt");
        return err;
    }

    err = listen(l2cap_socket, 5);
    if (err) {
        perror("listen");
        return err;
    }

    struct sockaddr_l2 remote_addr = {0};
    socklen_t addr_len = sizeof(remote_addr);
    int new_socket = accept(l2cap_socket, (struct sockaddr*)&remote_addr,
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

    **BT_POWER_FORCE_ACTIVE_OFF**, 0x00, Don't force exit of sniff mode
    **BT_POWER_FORCE_ACTIVE_ON**, 0x01 (default), Force exit of sniff mode

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
    **BT_PHY_LE_1M_TX**, BIT 9, LE 1Mbps TX
    **BT_PHY_LE_1M_RX**, BIT 10, LE 1Mbps RX
    **BT_PHY_LE_2M_TX**, BIT 11, LE 2Mbps TX
    **BT_PHY_LE_2M_RX**, BIT 12, LE 2Mbps RX
    **BT_PHY_LE_CODED_TX**, BIT 13, LE Coded TX
    **BT_PHY_LE_CODED_RX**, BIT 14, LE Coded RX

BT_MODE (since Linux 5.10)
--------------------------

Channel Mode, possible values:

.. csv-table::
    :header: "Define", "Value", "Description", "Link"
    :widths: auto

    **BT_MODE_BASIC**, 0x00 (default), Basic mode, Any
    **BT_MODE_ERTM**, 0x01, Enhanced Retransmission mode, BR/EDR
    **BT_MODE_STREAM**, 0x02, Stream mode, BR/EDR
    **BT_MODE_LE_FLOWCTL**, 0x03, Credit based flow control mode, LE
    **BT_MODE_EXT_FLOWCTL**, 0x04, Extended Credit based flow control mode, Any


SOCKET OPTIONS (SOL_SOCKET)
===========================

``SOL_SOCKET`` level socket options that modify generic socket
features (``SO_SNDBUF``, ``SO_RCVBUF``, etc.) have their usual
meaning, see **socket(7)**.

The ``SOL_SOCKET`` level L2CAP socket options that have
Bluetooth-specific handling in kernel are listed below.

SO_TIMESTAMPING, SO_TIMESTAMP, SO_TIMESTAMPNS
---------------------------------------------

See https://docs.kernel.org/networking/timestamping.html

For L2CAP sockets, software RX timestamps are supported.  Software TX
timestamps (SOF_TIMESTAMPING_TX_SOFTWARE,
SOF_TIMESTAMPING_TX_COMPLETION) are supported since Linux 6.15.

The software RX timestamp is the time when the kernel received the
packet from the controller driver.

The ``SCM_TSTAMP_SND`` timestamp is emitted when packet is sent to the
controller driver.  The ``SCM_TSTAMP_COMPLETION`` timestamp is emitted
when controller reports the packet completed.  Other TX timestamp
types are not supported.

You can use ``SIOCETHTOOL`` to query supported flags.

The timestamps are in ``CLOCK_REALTIME`` time.

Example (Enable RX timestamping):

.. code-block::

   int flags = SOF_TIMESTAMPING_SOFTWARE |
       SOF_TIMESTAMPING_RX_SOFTWARE;
   setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));

Example (Read packet and its RX timestamp):

.. code-block::

   char data_buf[256];
   union {
       char buf[CMSG_SPACE(sizeof(struct scm_timestamping))];
       struct cmsghdr align;
   } control;
   struct iovec data = {
       .iov_base = data_buf,
       .iov_len = sizeof(data_buf),
   };
   struct msghdr msg = {
       .msg_iov = &data,
       .msg_iovlen = 1,
       .msg_control = control.buf,
       .msg_controllen = sizeof(control.buf),
   };
   struct scm_timestamping tss;

   res = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
   if (res < 0)
       goto error;

   for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
       if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING)
           memcpy(&tss, CMSG_DATA(cmsg), sizeof(tss));
   }

   tstamp_clock_realtime = tss.ts[0];

Example (Enable TX timestamping):

.. code-block::

   int flags = SOF_TIMESTAMPING_SOFTWARE |
       SOF_TIMESTAMPING_TX_SOFTWARE |
       SOF_TIMESTAMPING_TX_COMPLETION |
       SOF_TIMESTAMPING_OPT_ID;
   setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));

Example (Read TX timestamps):

.. code-block::

   union {
       char buf[2 * CMSG_SPACE(sizeof(struct scm_timestamping))];
       struct cmsghdr align;
   } control;
   struct iovec data = {
       .iov_base = NULL,
       .iov_len = 0
   };
   struct msghdr msg = {
       .msg_iov = &data,
       .msg_iovlen = 1,
       .msg_control = control.buf,
       .msg_controllen = sizeof(control.buf),
   };
   struct cmsghdr *cmsg;
   struct scm_timestamping tss;
   struct sock_extended_err serr;
   int res;

   res = recvmsg(fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
   if (res < 0)
       goto error;

   for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
       if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING)
           memcpy(&tss, CMSG_DATA(cmsg), sizeof(tss));
       else if (cmsg->cmsg_level == SOL_BLUETOOTH && cmsg->cmsg_type == BT_SCM_ERROR)
           memcpy(&serr, CMSG_DATA(cmsg), sizeof(serr));
   }

   tstamp_clock_realtime = tss.ts[0];
   tstamp_type = serr->ee_info;      /* SCM_TSTAMP_SND or SCM_TSTAMP_COMPLETION */
   tstamp_seqnum = serr->ee_data;


IOCTLS
======

The following ioctls with operation specific for L2CAP sockets are
available.

SIOCETHTOOL (since Linux 6.16-rc1)
----------------------------------

Supports only command `ETHTOOL_GET_TS_INFO`, which may be used to
query supported `SOF_TIMESTAMPING_*` flags.  The
`SOF_TIMESTAMPING_OPT_*` flags are always available as applicable.

Example:

.. code-block::

   #include <linux/ethtool.h>
   #include <linux/sockios.h>
   #include <net/if.h>
   #include <sys/socket.h>
   #include <sys/ioctl.h>

   ...

   struct ifreq ifr = {};
   struct ethtool_ts_info cmd = {};
   int sk;

   snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "hci0");
   ifr.ifr_data = (void *)&cmd;
   cmd.cmd = ETHTOOL_GET_TS_INFO;

   sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
   if (sk < 0)
       goto error;
   if (ioctl(sk, SIOCETHTOOL, &ifr))
       goto error;

   sof_available = cmd.so_timestamping;

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

SEE ALSO
========

socket(7), l2test(1)

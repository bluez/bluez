===
sco
===
-------------
SCO transport
-------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: March 2025
:Manual section: 7
:Manual group: Linux System Administration

SYNOPSIS
========

.. code-block::

    #include <sys/socket.h>
    #include <bluetooth/bluetooth.h>
    #include <bluetooth/sco.h>

    sco_socket = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);

DESCRIPTION
===========

The SCO logical transport, is a symmetric, point-to-point transport between the
Central and a specific Peripheral. The SCO logical transport reserves slots and
can therefore be considered as a circuit-switched connection between the Central
and the Peripheral.

In addition to the reserved slots, when eSCO is supported, a retransmission
window follows immediately after. Together, the reserved slots and the
retransmission window form the complete eSCO window.

SOCKET ADDRESS
==============

.. code-block::

    struct sockaddr_sco {
        sa_family_t     sco_family;
        bdaddr_t        sco_bdaddr;
    };

Example:

.. code-block::

    struct sockaddr_sco addr;

    memset(&addr, 0, sizeof(addr));
    addr.sco_family = AF_BLUETOOTH;
    bacpy(&addr.sco_bdaddr, bdaddr);

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
    int err = setsockopt(sco_socket, SOL_BLUETOOTH, BT_SECURITY, &level,
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
    int err = setsockopt(sco_socket, SOL_BLUETOOTH, BT_DEFER_SETUP,
                         &defer_setup, sizeof(defer_setup));
    if (err == -1) {
        perror("setsockopt");
        return err;
    }

    err = listen(sco_socket, 5);
    if (err) {
        perror("listen");
        return err;
    }

    struct sockaddr_sco remote_addr = {0};
    socklen_t addr_len = sizeof(remote_addr);
    int new_socket = accept(sco_socket, (struct sockaddr*)&remote_addr,
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

BT_VOICE (since Linux 3.11)
-----------------------------

Transport voice settings, possible values:

.. code-block::

    struct bt_voice {
        uint16_t setting;
    };

.. csv-table::
    :header: "Define", "Value", "Description"
    :widths: auto

    **BT_VOICE_TRANSPARENT**, 0x0003, Transparent output
    **BT_VOICE_CVSD_16BIT**, 0x0060, C-VSD output PCM 16-bit input
    **BT_VOICE_TRANSPARENT_16BIT**, 0x0063, Transparent output PCM 16-bit input

Example:

.. code-block::

    struct bt_voice voice;

    memset(&voice, 0, sizeof(voice));
    voice.setting = BT_VOICE_TRANSPARENT;
    int err = setsockopt(sco_socket, SOL_BLUETOOTH, BT_VOICE, &voice,
                         sizeof(voice));
    if (err == -1) {
        perror("setsockopt");
        return 1;
    }

BT_PKT_STATUS (since Linux 5.9)
-------------------------------

Enable reporting packet status via `BT_SCM_PKT_STATUS` CMSG on
received packets.  Possible values:

.. csv-table::
    :header: "Value", "Description"
    :widths: auto

    **0**, Disable (default)
    **1**, Enable


:BT_SCM_PKT_STATUS:

    Level ``SOL_BLUETOOTH`` CMSG with data::

        uint8_t pkt_status;

    The values are equal to the "Packet_Status_Flag" defined in
    Core Specification v6.0 Sec. 5.4.3 pp. 1877:

    .. csv-table::
        :header: "pkt_status", "Description"
        :widths: auto

        **0x0**, Correctly received data
        **0x1**, Possibly invalid data
        **0x2**, No data received
        **0x3**, Data partially lost

BT_PHY (since Linux 5.10)
-------------------------

Transport supported PHY(s), read-only (no setsockopt support). Possible values:

.. csv-table::
    :header: "Define", "Value", "Description"
    :widths: auto

    **BT_PHY_BR_1M_1SLOT**, BIT 0, BR 1Mbps 1SLOT
    **BT_PHY_BR_1M_3SLOT**, BIT 1, BR 1Mbps 3SLOT
    **BT_PHY_BR_2M_1SLOT**, BIT 3, EDR 2Mbps 1SLOT
    **BT_PHY_BR_2M_3SLOT**, BIT 4, EDR 2Mbps 3SLOT
    **BT_PHY_BR_3M_1SLOT**, BIT 6, EDR 3Mbps 1SLOT
    **BT_PHY_BR_3M_3SLOT**, BIT 7, EDR 3Mbps 3SLOT

BT_CODEC (since Linux 5.14)
---------------------------

Transport codec offload, possible values:

.. code-block::

    struct bt_codec {
        uint8_t id;
        uint16_t cid;
        uint16_t vid;
        uint8_t data_path_id;
        uint8_t num_caps;
        struct codec_caps {
            uint8_t len;
            uint8_t data[];
        } caps[];
    } __attribute__((packed));

    struct bt_codecs {
        uint8_t num_codecs;
        struct bt_codec codecs[];
    } __attribute__((packed));

Example:

.. code-block::

    char buffer[sizeof(struct bt_codecs) + sizeof(struct bt_codec)];
    struct bt_codec *codecs = (void *)buffer;

    memset(codecs, 0, sizeof(codecs));
    codec->num_codecs = 1;
    codecs->codecs[0].id = 0x05;
    codecs->codecs[0].data_path_id = 1;

    int err = setsockopt(sco_socket, SOL_BLUETOOTH, BT_CODEC, codecs,
                         sizeof(buffer));
    if (err == -1) {
        perror("setsockopt");
        return 1;
    }


SOCKET OPTIONS (SOL_SOCKET)
===========================

``SOL_SOCKET`` level socket options that modify generic socket
features (``SO_SNDBUF``, ``SO_RCVBUF``, etc.) have their usual
meaning, see **socket(7)**.

The ``SOL_SOCKET`` level SCO socket options that have
Bluetooth-specific handling in kernel are listed below.

SO_TIMESTAMPING, SO_TIMESTAMP, SO_TIMESTAMPNS
---------------------------------------------

See https://docs.kernel.org/networking/timestamping.html

For SCO sockets, software RX timestamps are supported.  Software TX
timestamps (SOF_TIMESTAMPING_TX_SOFTWARE) are supported since
Linux 6.15.

The software RX timestamp is the time when the kernel received the
packet from the controller driver.

The ``SCM_TSTAMP_SND`` timestamp is emitted when packet is sent to the
controller driver.

The ``SCM_TSTAMP_COMPLETION`` timestamp is emitted when controller
reports the packet completed.  Completion timestamps are only
supported on controllers that have SCO flow control.  Other TX
timestamp types are not supported.

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
       SOF_TIMESTAMPING_OPT_ID;
   setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));

Example (Read TX timestamps):

.. code-block::

   union {
       char buf[CMSG_SPACE(sizeof(struct scm_timestamping))];
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

The following ioctls with operation specific for SCO sockets are
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

   sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
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

socket(7), scotest(1)

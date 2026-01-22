===
iso
===
-------------
ISO transport
-------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: July 2025
:Manual section: 7
:Manual group: Linux System Administration

SYNOPSIS (since Linux 6.0 [experimental])
=========================================

.. code-block::

    #include <sys/socket.h>
    #include <bluetooth/bluetooth.h>
    #include <bluetooth/iso.h>

    iso_socket = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);

DESCRIPTION
===========

Bluetooth Isochronous Channels is a feature introduced in Bluetooth 5.2 that
allow for the transmission of multiple, synchronized audio streams between
devices.

For unicast/multi-stream audio, connected isochronous group (CIG), and
connected isochronous stream (CIS) are used. A CIG is created by the central and
it can include one or more CISs. A CIS is a point-to-point data transportation
stream between a central and a certain peripheral, and is a bidirectional
communication protocol with acknowledgment.

For broadcast audio, broadcast isochronous group (BIG) and broadcast isochronous
stream (BIS) are used. There are two types of devices: isochronous broadcaster
and synchronized receiver. A BIG is created by an isochronous broadcaster, and
it can include one or more BISs. A BIS is a one-to-many data transportation
stream.

SOCKET ADDRESS
==============

.. code-block::

    struct sockaddr_iso_bc {
        bdaddr_t	bc_bdaddr;
        uint8_t		bc_bdaddr_type;
        uint8_t		bc_sid;
        uint8_t		bc_num_bis;
        uint8_t		bc_bis[ISO_MAX_NUM_BIS];
    };

    struct sockaddr_iso {
        sa_family_t     iso_family;
        bdaddr_t        iso_bdaddr;
        uint8_t		iso_bdaddr_type;
        struct sockaddr_iso_bc iso_bc[];
    };

Unicast example:

.. code-block::

    struct sockaddr_iso addr;

    memset(&addr, 0, sizeof(addr));
    addr.iso_family = AF_BLUETOOTH;
    bacpy(&addr.iso_bdaddr, bdaddr);
    addr.iso_bdaddr_type = BDADDR_LE_PUBLIC;

Broadcast example:

.. code-block::

    struct sockaddr_iso *addr;
    size_t addr_len;

    addr_len = sizeof(*addr) + sizeof(*addr->iso_bc);

    memset(addr, 0, addr_len);
    addr->iso_family = AF_BLUETOOTH;
    bacpy(&addr->iso_bdaddr, bdaddr);
    addr->iso_bdaddr_type = BDADDR_LE_PUBLIC;

Broadcast Source (Broadcaster) example:

.. code-block::

    struct sockaddr_iso *addr;
    size_t addr_len;

    addr_len = sizeof(*addr) + sizeof(*addr->iso_bc);

    memset(addr, 0, addr_len);
    addr->iso_family = AF_BLUETOOTH;

    /* Set address to BDADR_ANY(00:00:00:00:00:00) */
    bacpy(&addr->iso_bdaddr, BADDR_ANY);
    addr->iso_bdaddr_type = BDADDR_LE_PUBLIC;

    /* Connect to Broadcast address */
    connect(iso_socket, (struct sockaddr *)addr, addr_len);

Broadcast Sink (Receiver) example:

.. code-block::

    struct sockaddr_iso *addr;
    size_t addr_len;

    addr_len = sizeof(*addr) + sizeof(*addr->iso_bc);

    memset(addr, 0, addr_len);
    addr->iso_family = AF_BLUETOOTH;

    /* Set destination to Broadcaster address */
    bacpy(&addr->iso_bdaddr, bdaddr);
    addr->iso_bdaddr_type = BDADDR_LE_PUBLIC;

    /* Bind to Broadcaster address */
    bind(iso_socket, (struct sockaddr *)addr, addr_len);

Broadcast Source (Broadcaster) or Broadcast Sink (Receiver) Periodic
Advertising Sync Transfer (PAST):

.. code-block::

    struct sockaddr_iso *addr;
    size_t addr_len;

    addr_len = sizeof(*addr) + sizeof(*addr->iso_bc);

    memset(addr, 0, addr_len);
    addr->iso_family = AF_BLUETOOTH;

    /* Set destination address to PAST destination address */
    bacpy(&addr->iso_bc->bc_bdaddr, (void *) bdaddr);
    addr->iso_bc->bc_bdaddr_type = bdaddr_type;

    /* Rebind already connected socket to PAST address */
    bind(iso_socket, (struct sockaddr *)addr, addr_len);

SOCKET OPTIONS (SOL_BLUETOOTH)
==============================

The socket options listed below can be set by using **setsockopt(2)** and read
with **getsockopt(2)** with the socket level set to SOL_BLUETOOTH.

BT_SECURITY
-----------

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
    int err = setsockopt(iso_socket, SOL_BLUETOOTH, BT_SECURITY, &level,
                         sizeof(level));
    if (err == -1) {
        perror("setsockopt");
        return 1;
    }

BT_DEFER_SETUP
--------------

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
    int err = setsockopt(iso_socket, SOL_BLUETOOTH, BT_DEFER_SETUP,
                         &defer_setup, sizeof(defer_setup));
    if (err == -1) {
        perror("setsockopt");
        return err;
    }

    err = listen(iso_socket, 5);
    if (err) {
        perror("listen");
        return err;
    }

    struct sockaddr_iso remote_addr = {0};
    socklen_t addr_len = sizeof(remote_addr);
    int new_socket = accept(iso_socket, (struct sockaddr*)&remote_addr,
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

BT_PKT_STATUS
-------------

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
    Core Specification v6.1, 5.4.5. HCI ISO Data packets:

    https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-61/out/en/host-controller-interface/host-controller-interface-functional-specification.html#UUID-9b5fb085-278b-5084-ac33-bee2839abe6b

    .. csv-table::
        :header: "pkt_status", "Description"
        :widths: auto

        **0x0**, "Valid data. The complete SDU was received correctly."
        **0x1**, "Possibly invalid data. The contents of the ISO_SDU_Fragment,
        may contain errors or part of the SDU may be missing.
        This is reported as 'data with possible errors'."
        **0x2**, "Part(s) of the SDU were not received correctly.
        This is reported as 'lost data'."

BT_PKT_SEQNUM (since Linux 6.17-rc1)
------------------------------------

Enable reporting packet ISO sequence number via `BT_SCM_PKT_SEQNUM`
CMSG on received packets.  Possible values:

.. csv-table::
    :header: "Value", "Description"
    :widths: auto

    **0**, Disable (default)
    **1**, Enable


:BT_SCM_PKT_SEQNUM:

    Level ``SOL_BLUETOOTH`` CMSG with data::

        uint16_t pkt_seqnum;

    The values are equal to the "Packet_Sequence_Number" defined in
    Core Specification v6.1, 5.4.5. HCI ISO Data packets:

    https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-61/out/en/host-controller-interface/host-controller-interface-functional-specification.html#UUID-9b5fb085-278b-5084-ac33-bee2839abe6b

Example (Enable sequence numbers):

.. code-block::

    uint32_t opt = 1;
    if (setsockopt(fd, SOL_BLUETOOTH, BT_PKT_SEQNUM, &opt, sizeof(opt)) < 0)
        goto error;

Example (Read packet and its sequence number):

.. code-block::

   char data_buf[256];
   uint16_t seqnum;
   union {
       char buf[CMSG_SPACE(sizeof(uint16_t))];
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

   res = recvmsg(fd, &msg, 0);
   if (res < 0)
       goto error;

   for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
       if (cmsg->cmsg_level == SOL_BLUETOOTH && cmsg->cmsg_type == BT_PKT_SEQNUM)
           memcpy(&seqnum, CMSG_DATA(cmsg), sizeof(seqnum));
   }

SOCKET OPTIONS (SOL_SOCKET)
===========================

``SOL_SOCKET`` level socket options that modify generic socket
features (``SO_SNDBUF``, ``SO_RCVBUF``, etc.) have their usual
meaning, see **socket(7)**.

The ``SOL_SOCKET`` level ISO socket options that have
Bluetooth-specific handling in kernel are listed below.

SO_TIMESTAMPING, SO_TIMESTAMP, SO_TIMESTAMPNS
---------------------------------------------

See https://docs.kernel.org/networking/timestamping.html

For ISO sockets, software RX timestamps are supported.  Software TX
timestamps (SOF_TIMESTAMPING_TX_SOFTWARE) are supported since
Linux 6.15.

The software RX timestamp is the time when the kernel received the
packet from the controller driver.

The ``SCM_TSTAMP_SND`` timestamp is emitted when packet is sent to the
controller driver.

The ``SCM_TSTAMP_COMPLETION`` timestamp is emitted when controller
reports the packet completed.  Completion timestamps are only
supported on controllers that have ISO flow control.  Other TX
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

The following ioctls with operation specific for ISO sockets are
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

   sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_ISO);
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

socket(7), isotest(1)

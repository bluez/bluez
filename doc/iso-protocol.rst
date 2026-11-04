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

BT_ISO_QOS
----------

Isochronous channel QoS, used by **connect(2)** and **listen(2)** to set up a
CIS (unicast) or BIS (broadcast). It is read back with **getsockopt(2)**, which
reports the parameters in use once the channel is connected. Two forms are
accepted, told apart by the option length:

- ``struct bt_iso_qos``: the original form, kept for existing applications.
- ``struct bt_iso_qos_ext``: the extended form, required
  for the fields added after the original one, such as the HDT rates.

.. code-block::

    struct bt_iso_io_qos_ext {
        uint32_t interval;
        uint16_t latency;
        uint16_t sdu;
        uint8_t  phys;
        uint8_t  rtn;
        uint16_t rates;     /* Version 1 */
    };

    struct bt_iso_ucast_qos_ext {
        uint8_t  cig;
        uint8_t  cis;
        uint8_t  sca;
        uint8_t  packing;
        uint8_t  framing;
        struct bt_iso_io_qos_ext in;
        struct bt_iso_io_qos_ext out;
    };

    struct bt_iso_bcast_qos_ext {
        uint8_t  big;
        uint8_t  bis;
        uint8_t  sync_factor;
        uint8_t  packing;
        uint8_t  framing;
        struct bt_iso_io_qos_ext in;
        struct bt_iso_io_qos_ext out;
        uint8_t  encryption;
        uint8_t  bcode[16];
        uint8_t  options;
        uint16_t skip;
        uint16_t sync_timeout;
        uint8_t  sync_cte_type;
        uint8_t  mse;
        uint16_t timeout;
    };

    struct bt_iso_qos_ext {
        uint16_t version;
        uint16_t type;
        union {         /* Shall be the last member */
            struct bt_iso_ucast_qos_ext ucast;
            struct bt_iso_bcast_qos_ext bcast;
        };
    };

``struct bt_iso_qos`` has the same fields without ``version``, ``type`` and
``rates``.

The extended form is meant to grow, by extending it rather than adding new
socket options or structs, which is what its first two fields are for:

- ``version`` tells which fields are valid. Later versions add fields, while
  applications built for an earlier version keep working with the fields
  they know.
- ``type`` tells which member of the union is in use. The QoS is usually set
  before **bind(2)** or **connect(2)**, when the socket can't tell unicast
  from broadcast, so with ``type`` ``ucast`` and ``bcast`` can each grow on
  their own, by adding fields at their end, without the kernel having to
  guess which one it was given. That is also why the union is the last
  member.

version:

.. csv-table::
    :header: "Value", "Description"
    :widths: auto

    **BT_ISO_QOS_VERSION_1 (0x0001)**, Adds ``rates`` to each direction

type:

.. csv-table::
    :header: "Value", "Description"
    :widths: auto

    **BT_ISO_QOS_ANY (0x0000)**, "Set by **connect(2)** or **listen(2)**,
    possible with version 1 fields since the unicast ones are a prefix of the
    broadcast ones"
    **BT_ISO_QOS_UCAST (0x0001)**, Unicast (CIS) uses ``ucast``
    **BT_ISO_QOS_BCAST (0x0002)**, Broadcast (BIS) uses ``bcast``

**setsockopt(2)** fails with ``EINVAL`` for an unknown ``version`` or
``type``, and **connect(2)** or **listen(2)** fail with ``EINVAL`` if
``type`` doesn't match how the socket is used. **getsockopt(2)** returns
``struct bt_iso_qos`` if the buffer is shorter than ``struct bt_iso_qos_ext``,
otherwise ``struct bt_iso_qos_ext`` with the version and, once known, the type
in use.

phys, in each direction:

.. csv-table::
    :header: "Value", "Description"
    :widths: auto

    **BT_ISO_PHY_1M (0x01)**, LE 1M
    **BT_ISO_PHY_2M (0x02)**, LE 2M
    **BT_ISO_PHY_CODED (0x04)**, LE Coded
    **BT_ISO_PHY_HDT (0x10)**, "LE HDT, if supported by the controller, using
    ``rates``"

rates, in each direction, used with ``BT_ISO_PHY_HDT``; 0 selects every rate
the controller supports:

.. csv-table::
    :header: "Value", "Description"
    :widths: auto

    **BT_ISO_HDT_RATE_2M (0x0001)**, HDT 2M
    **BT_ISO_HDT_RATE_3M (0x0002)**, HDT 3M
    **BT_ISO_HDT_RATE_4M (0x0004)**, HDT 4M
    **BT_ISO_HDT_RATE_6M (0x0008)**, "HDT 6M, if supported in that direction"
    **BT_ISO_HDT_RATE_7_5M (0x0010)**, "HDT 7.5M, if supported in that
    direction"

Example (Unicast with the LE HDT PHY):

.. code-block::

    struct bt_iso_qos_ext qos;

    memset(&qos, 0, sizeof(qos));
    qos.version = BT_ISO_QOS_VERSION_1;
    qos.type = BT_ISO_QOS_UCAST;
    qos.ucast.cig = BT_ISO_QOS_CIG_UNSET;
    qos.ucast.cis = BT_ISO_QOS_CIS_UNSET;

    qos.ucast.out.interval = 10000;
    qos.ucast.out.latency = 10;
    qos.ucast.out.sdu = 40;
    qos.ucast.out.phys = BT_ISO_PHY_HDT;
    qos.ucast.out.rtn = 2;
    qos.ucast.out.rates = BT_ISO_HDT_RATE_4M | BT_ISO_HDT_RATE_6M;

    /* The input direction uses the same settings */
    qos.ucast.in = qos.ucast.out;

    err = setsockopt(iso_socket, SOL_BLUETOOTH, BT_ISO_QOS, &qos,
                     sizeof(qos));
    if (err == -1) {
        perror("setsockopt");
        return err;
    }

    /* connect(2) sets up the CIS */

Example (Broadcast with the LE HDT PHY at any supported rate):

.. code-block::

    struct bt_iso_qos_ext qos;

    memset(&qos, 0, sizeof(qos));
    qos.version = BT_ISO_QOS_VERSION_1;
    qos.type = BT_ISO_QOS_BCAST;
    qos.bcast.big = BT_ISO_QOS_BIG_UNSET;
    qos.bcast.bis = BT_ISO_QOS_BIS_UNSET;
    qos.bcast.sync_factor = 0x01;
    qos.bcast.sync_timeout = BT_ISO_SYNC_TIMEOUT;
    qos.bcast.timeout = BT_ISO_SYNC_TIMEOUT;

    qos.bcast.out.interval = 10000;
    qos.bcast.out.latency = 10;
    qos.bcast.out.sdu = 40;
    qos.bcast.out.phys = BT_ISO_PHY_HDT;
    qos.bcast.out.rtn = 2;
    qos.bcast.out.rates = 0; /* Every rate the controller supports */

    err = setsockopt(iso_socket, SOL_BLUETOOTH, BT_ISO_QOS, &qos,
                     sizeof(qos));

Example (Read the QoS in use, including the rates selected):

.. code-block::

    struct bt_iso_qos_ext qos;
    socklen_t len = sizeof(qos);

    err = getsockopt(iso_socket, SOL_BLUETOOTH, BT_ISO_QOS, &qos, &len);
    if (err == -1) {
        perror("getsockopt");
        return err;
    }

    if (len < sizeof(qos)) {
        /* Older kernel, only struct bt_iso_qos was returned */
    } else if (qos.type == BT_ISO_QOS_UCAST &&
               qos.ucast.out.phys == BT_ISO_PHY_HDT) {
        printf("Output HDT rates 0x%4.4x\n", qos.ucast.out.rates);
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

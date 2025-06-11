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

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

SEE ALSO
========

socket(7), scotest(1)

=======
btsnoop
=======

-------------------------------------------
BTSnoop/Monitor protocol documentation
-------------------------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: February 2026
:Manual section: 7
:Manual group: Linux System Administration

SYNOPSIS
========

This document describes the BTSnoop/Monitor formats used to record and
transport HCI/PHY traffic. The formats are used by tools such as btmon and the
BlueZ btsnoop implementation.

DESCRIPTION
===========

Opcode definitions
------------------

The following opcodes are used by the BTSnoop/Monitor formats. The numeric
values match the definitions in ``src/shared/btsnoop.h``.

.. list-table:: BTSnoop opcodes
   :header-rows: 1

   * - Name
     - Code (dec)
     - Code (hex)
     - Meaning
   * - BTSNOOP_OPCODE_NEW_INDEX
     - 0
     - 0x0000
     - New controller index (parameters: type, bus, bdaddr, name)
   * - BTSNOOP_OPCODE_DEL_INDEX
     - 1
     - 0x0001
     - Deleted controller index
   * - BTSNOOP_OPCODE_COMMAND_PKT
     - 2
     - 0x0002
     - HCI Command packet
   * - BTSNOOP_OPCODE_EVENT_PKT
     - 3
     - 0x0003
     - HCI Event packet
   * - BTSNOOP_OPCODE_ACL_TX_PKT
     - 4
     - 0x0004
     - Outgoing ACL packet
   * - BTSNOOP_OPCODE_ACL_RX_PKT
     - 5
     - 0x0005
     - Incoming ACL packet
   * - BTSNOOP_OPCODE_SCO_TX_PKT
     - 6
     - 0x0006
     - Outgoing SCO packet
   * - BTSNOOP_OPCODE_SCO_RX_PKT
     - 7
     - 0x0007
     - Incoming SCO packet
   * - BTSNOOP_OPCODE_OPEN_INDEX
     - 8
     - 0x0008
     - HCI transport for the specified controller opened
   * - BTSNOOP_OPCODE_CLOSE_INDEX
     - 9
     - 0x0009
     - HCI transport for the specified controller closed
   * - BTSNOOP_OPCODE_INDEX_INFO
     - 10
     - 0x000a
     - Index information (parameters: bdaddr, manufacturer)
   * - BTSNOOP_OPCODE_VENDOR_DIAG
     - 11
     - 0x000b
     - Vendor diagnostic information
   * - BTSNOOP_OPCODE_SYSTEM_NOTE
     - 12
     - 0x000c
     - System note
   * - BTSNOOP_OPCODE_USER_LOGGING
     - 13
     - 0x000d
     - User logging (parameters: priority, ident_len, ident)
   * - BTSNOOP_OPCODE_CTRL_OPEN
     - 14
     - 0x000e
     - Control channel opened
   * - BTSNOOP_OPCODE_CTRL_CLOSE
     - 15
     - 0x000f
     - Control channel closed
   * - BTSNOOP_OPCODE_CTRL_COMMAND
     - 16
     - 0x0010
     - Control command packet
   * - BTSNOOP_OPCODE_CTRL_EVENT
     - 17
     - 0x0011
     - Control event packet
   * - BTSNOOP_OPCODE_ISO_TX_PKT
     - 18
     - 0x0012
     - Outgoing ISO packet
   * - BTSNOOP_OPCODE_ISO_RX_PKT
     - 19
     - 0x0013
     - Incoming ISO packet

New Index
---------

Code: 0x0000

Parameters:

- Type (1 octet)
- Bus (1 octet)
- BD_Addr (6 octets)
- Name (8 octets)

This opcode indicates that a new controller instance with a given index was
added. With some transports (for example a single TTY device) the index is
implicitly 0.

Deleted Index
-------------

Code: 0x0001

Indicates that the controller with a specific index was removed.

TTY-based protocol
------------------

The TTY protocol used by btmon with the ``--tty`` option is a little-endian
packet format. Each packet uses this header::

    struct tty_hdr {
        uint16_t data_len;
        uint16_t opcode;
        uint8_t  flags;
        uint8_t  hdr_len;
        uint8_t  ext_hdr[0];
    } __attribute__ ((packed));

The payload starts at ``ext_hdr + hdr_len`` and has length
``data_len - 4 - hdr_len``.

Extended header format
----------------------

Each extension field is encoded as::

    struct {
        uint8_t type;
        uint8_t value[length];
    };

Defined types:

.. list-table:: Extended header types
   :header-rows: 1

   * - Type
     - Length
     - Meaning
   * - 1
     - 1 byte
     - Command drops (dropped HCI command packets)
   * - 2
     - 1 byte
     - Event drops (dropped HCI event packets)
   * - 3
     - 1 byte
     - ACL TX drops
   * - 4
     - 1 byte
     - ACL RX drops
   * - 5
     - 1 byte
     - SCO TX drops
   * - 6
     - 1 byte
     - SCO RX drops
   * - 7
     - 1 byte
     - Other drops
   * - 8
     - 4 bytes
     - 32-bit timestamp (1/10th ms)

The drops fields contain the number of packets the implementation had to drop
since the last reported drop count. Extension fields must be sorted by
increasing ``type`` so unknown types can be skipped and the payload location
discovered.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

SEE ALSO
========

btmon(1)

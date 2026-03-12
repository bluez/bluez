.. This file is included by btmon.rst.

L2CAP CHANNEL TRACKING
=======================

L2CAP (Logical Link Control and Adaptation Protocol) multiplexes
multiple logical channels over a single ACL connection. btmon decodes
L2CAP signaling automatically and routes data to higher-layer protocol
decoders based on the channel.

Fixed Channels
--------------

Fixed channels have pre-assigned Channel Identifiers (CIDs) and do
not require signaling to establish:

.. list-table::
   :header-rows: 1
   :widths: 10 30 60

   * - CID
     - Protocol
     - Description
   * - 0x0001
     - L2CAP Signaling (BR/EDR)
     - Channel management for classic connections
   * - 0x0002
     - Connectionless Reception
     - Connectionless L2CAP data
   * - 0x0003
     - AMP Manager
     - AMP (Alternate MAC/PHY) control
   * - 0x0004
     - ATT
     - Attribute Protocol (GATT operations)
   * - 0x0005
     - L2CAP Signaling (LE)
     - Channel management for LE connections
   * - 0x0006
     - SMP (LE)
     - Security Manager Protocol
   * - 0x0007
     - SMP (BR/EDR)
     - Security Manager over classic transport

In btmon output, fixed channel traffic is decoded directly without
any L2CAP signaling preamble. For example, ATT on CID 0x0004 appears
as::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 7    #494 [hci0] 0.004488
          ATT: Exchange MTU Request (0x02) len 2
            Client RX MTU: 517

Dynamic Channels (BR/EDR)
--------------------------

Classic Bluetooth uses L2CAP signaling on CID 0x0001 to establish
dynamic channels. Each channel is identified by a PSM (Protocol/Service
Multiplexer) that determines which protocol runs on it.

**Channel establishment**::

    > ACL Data RX: Handle 256 flags 0x02 dlen 16    #142 [hci0] 2.034556
          L2CAP: Connection Request (0x02) ident 3 len 4
            PSM: 25 (0x0019)
            Source CID: 0x0040

    < ACL Data TX: Handle 256 flags 0x00 dlen 20    #144 [hci0] 2.035002
          L2CAP: Connection Response (0x03) ident 3 len 8
            Destination CID: 0x0041
            Source CID: 0x0040
            Result: Connection successful (0x0000)
            Status: No further information available (0x0000)

After connection, configuration is exchanged::

    > ACL Data RX: Handle 256 flags 0x02 dlen 20    #146 [hci0] 2.035556
          L2CAP: Configure Request (0x04) ident 4 len 8
            Destination CID: 0x0041
            Flags: 0x0000
            Option: MTU (0x01) [2]
              MTU: 1024

    < ACL Data TX: Handle 256 flags 0x00 dlen 18    #148 [hci0] 2.036003
          L2CAP: Configure Response (0x05) ident 4 len 6
            Source CID: 0x0040
            Flags: 0x0000
            Result: Success (0x0000)

Common PSM-to-protocol mappings:

.. list-table::
   :header-rows: 1
   :widths: 12 25 63

   * - PSM
     - Protocol
     - Description
   * - 0x0001
     - SDP
     - Service Discovery Protocol
   * - 0x0003
     - RFCOMM
     - Serial port emulation (SPP, HFP, etc.)
   * - 0x000f
     - BNEP
     - Bluetooth Network Encapsulation Protocol
   * - 0x0017
     - AVCTP
     - Audio/Video Control Transport (AVRCP)
   * - 0x0019
     - AVDTP
     - Audio/Video Distribution Transport (A2DP)
   * - 0x001b
     - AVCTP Browsing
     - AVRCP browsing channel
   * - 0x001f
     - ATT (BR/EDR)
     - Attribute Protocol over classic transport
   * - 0x0027
     - EATT
     - Enhanced Attribute Protocol

LE Credit-Based Channels
--------------------------

LE connections use L2CAP signaling on CID 0x0005 for dynamic
channels. The LE Credit Based Connection mechanism provides flow
control::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 18   #600 [hci0] 1.824003
          LE L2CAP: LE Connection Request (0x14) ident 1 len 10
            PSM: 39 (0x0027)
            Source CID: 0x0040
            MTU: 517
            MPS: 251
            Credits: 10

    > ACL Data RX: Handle 2048 flags 0x02 dlen 18   #602 [hci0] 1.886556
          LE L2CAP: LE Connection Response (0x15) ident 1 len 10
            Destination CID: 0x0041
            MTU: 517
            MPS: 251
            Credits: 10
            Result: Connection successful (0x0000)

EATT (Enhanced ATT) uses PSM 0x0027 over LE Credit-Based channels to
provide multiple parallel ATT bearers.

Connection Parameter Updates
-----------------------------

LE peripherals frequently request connection parameter changes via
L2CAP signaling::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 16   #493 [hci0] 0.003915
          LE L2CAP: Connection Parameter Update Request (0x12) ident 1 len 8
            Min interval: 24
            Max interval: 40
            Peripheral latency: 0
            Timeout multiplier: 256

    > ACL Data RX: Handle 2048 flags 0x02 dlen 10   #495 [hci0] 0.066003
          LE L2CAP: Connection Parameter Update Response (0x13) ident 1 len 2
            Result: Connection Parameters accepted (0x0000)

A result of ``Connection Parameters rejected (0x0001)`` means the
central denied the request.

Automating L2CAP Analysis
--------------------------

**Find all L2CAP channel establishments**::

    grep -n "Connection Request\|Connection Response\|LE Connection Request\|LE Connection Response" output.txt

**Track PSM usage** (identifies which protocols are active)::

    grep -n "PSM:" output.txt

**Find connection parameter update issues**::

    grep -n "Parameter Update Request\|Parameter Update Response\|Parameters rejected" output.txt

**Find EATT channel setup**::

    grep -n "PSM: 39\|Enhanced Credit" output.txt

**Trace a specific L2CAP channel**: To follow traffic on a dynamic
channel, note the Source CID and Destination CID from the Connection
Request/Response pair. Then search for those CIDs in subsequent data
frames.

.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

===============
Headset Profile
===============
(TCRL 2023-1, HSP.ICS.p6)

Versions
========
**Table 0: Major Versions (X.Y)**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_0_1     |          | HSP v1.1 DeprecatedTo be withdrawn (C.1)     |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_0_2     | x        | HSP v1.2 (C.1)                               |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support one and only one of HSP 0/1 "HSP v1.1" OR HSP 0/2 "HSP v1.2".

Roles
=====
**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_1_1     | x        | Audio Gateway (AG) (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_1_2     |          | Headset (HS) (C.1)                           |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one of HSP 1/1 "Audio Gateway (AG)" OR HSP 1/2 "Headset (HS)".

Audio Gateway Role
==================
**Table 2: Application Features (AG)**

Prerequisite: HSP 1/1 "Audio Gateway (AG)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_2_1     | x        | Incoming audio connection establishment (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_2     |          | Ring (AT command) (C.3)                      |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_3     |          | Inband ring tone (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_4     |          | Outgoing audio connection establishment (O)  |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_5     | x        | Audio connection release from HS (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_6     |          | Audio connection release from AG (C.5)       |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_7     | x        | Audio connection transfer: AG to HS (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_8     | x        | Audio connection transfer: HS to AG (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_9     |          | Remote audio volume control (C.1)            |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_10    |          | HS informs AG about local changes of audio   |
|                  |          | volume (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_11    |          | Audio volume setting storage by HS (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_12    |          | Remote microphone gain control (C.2)         |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_13    |          | HS informs AG about local changes of         |
|                  |          | microphone gain (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_14    |          | Microphone gain setting storage by HS (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2_15    | x        | Connection Handling with Detach/Page (M)     |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF HSP 2/10 "HS informs AG about local changes of audio volume", otherwise Optional.
- C.2: Mandatory IF HSP 2/13 "HS informs AG about local changes of microphone gain", otherwise Optional.
- C.3: Excluded IF HSP 2/3 "Inband ring tone" AND HSP 4/1 "E2112/TSE 1134 (212): Show that in-band ringing and RING are mutually exclusive", otherwise Optional.
- C.5: Mandatory IF HSP 0/1 "HSP v1.1", otherwise Optional.

Audio Gateway Role
==================
**Table 2a: GAP Requirements**

Prerequisite: HSP 1/1 "Audio Gateway (AG)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_2a_1    | x        | Initiation of general inquiry (M)            |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Audio Gateway Role
==================
**Table 2b: SDP Requirements**

Prerequisite: HSP 1/1 "Audio Gateway (AG)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_2b_1    | x        | ProtocolDescriptorList (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_2b_2    | x        | BluetoothProfileDescriptorList (M)           |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Audio Gateway Role
==================
**Table 2c: RFCOMM Requirements**

Prerequisite: HSP 1/1 "Audio Gateway (AG)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_2c_1    | x        | RFCOMM with TS 07.10 (M)                     |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Headset Role
============
**Table 3: Application Features (HS)**

Prerequisite: HSP 1/2 "Headset (HS)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_3_1     |          | Incoming audio connection establishment (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_2     |          | Ring (AT command) (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_3     |          | Inband ring tone (M)                         |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_4     |          | Outgoing audio connection establishment (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_5     |          | Audio connection release from HS (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_6     |          | Audio connection release from AG (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_7     |          | Audio connection transfer: AG to HS (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_8     |          | Audio connection transfer: HS to AG (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_9     |          | Remote audio volume control (C.1)            |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_10    |          | HS informs AG about local changes of audio   |
|                  |          | volume (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_11    |          | Audio volume setting storage by HS (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_12    |          | Remote microphone gain control (C.2)         |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_13    |          | HS informs AG about local changes of         |
|                  |          | microphone gain (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_14    |          | Microphone gain setting storage by HS (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3_15    |          | Connection Handling with Detach/Page (M)     |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF HSP 3/10 "HS informs AG about local changes of audio volume", otherwise Optional.
- C.2: Mandatory IF HSP 3/13 "HS informs AG about local changes of microphone gain", otherwise Optional.

Headset Role
============
**Table 3a: GAP Requirements**

Prerequisite: HSP 1/2 "Headset (HS)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_3a_1    |          | Non-discoverable mode (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3a_2    |          | General discoverable mode (M)                |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Headset Role
============
**Table 3b: SDP Requirements**

Prerequisite: HSP 1/2 "Headset (HS)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_3b_1    |          | ProtocolDescriptorList (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_HSP_3b_2    |          | BluetoothProfileDescriptorList (M)           |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Headset Role
============
**Table 3c: RFCOMM Requirements**

Prerequisite: HSP 1/2 "Headset (HS)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_3c_1    |          | RFCOMM with TS 07.10 (M)                     |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Errata Service Releases
=======================
**Table 4: Errata Service Releases (ESR)**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HSP_4_1     |          | E2112/TSE 1134 (212): Show that in-band      |
|                  |          | ringing and RING are mutually exclusive (C.1)|
+------------------+----------+----------------------------------------------+

- C.1: Excluded IF HSP 0/2 "HSP v1.2", otherwise Optional.

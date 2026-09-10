.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

============================
Audio Stream Control Service
============================
(TCRL pkg103, ASCS.ICS.p5)

Versions
========

**Table 0: X.Y Versions**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_0_1    | x        | ASCS v1.0 (M)                                |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 1: X.Y.Z Versions**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_1_1    |          | ASCS v1.0.1 (O)                              |
+------------------+----------+----------------------------------------------+

- O: Optional

Transports
==========

**Table 2: Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_2_1    |          | Service supported over BR/EDR (C.1, C.3)     |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_2_2    | x        | Service supported over LE (C.2, C.3)         |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Service IF CORE 41/2 "LE Core Configuration" OR CORE
  40/1 "Core-Controller".
- C.2: Excluded for this Service IF CORE 41/1 "BR/EDR Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.3: Mandatory to support at least one.

Features
========

**Table 3: Included Services**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_3_1    | x        | Published Audio Capabilities Service (M)     |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 4: Features**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_4_1    |          | Support Multiple ASEs (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_4_2    |          | Support Multiple Sink ASEs (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_4_3    |          | Support Multiple Source ASEs (C.2)           |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF ASCS 4/1 "Support Multiple ASEs" AND ASCS 5/1 "Sink ASE
  characteristic", otherwise Excluded.
- C.2: Optional IF ASCS 4/1 "Support Multiple ASEs" AND ASCS 5/2 "Source ASE
  characteristic", otherwise Excluded.

**Table 5: Included Characteristics**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_5_1    | x        | Sink ASE characteristic (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_5_2    | x        | Source ASE characteristic (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_5_3    | x        | ASE Control Point characteristic (M)         |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory to support at least one.

**Table 6: ASE Control Operations**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_6_1    | x        | Config Codec (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_6_2    | x        | Config QoS (M)                               |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_6_3    | x        | Enable (M)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_6_4    | x        | Receiver Start Ready (M)                     |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_6_5    | x        | Disable (M)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_6_6    | x        | Receiver Stop Ready (C.1)                    |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_6_7    | x        | Update Metadata (M)                          |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_6_8    | x        | Release (M)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_6_9    | x        | Released (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF ASCS 5/2 "Source ASE characteristic", otherwise Excluded.

**Table 7: Server-Initiated ASE Control Operations**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_7_1    |          | Autonomous Config Codec (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_7_2    | x        | Autonomous Receiver Start Ready (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_7_3    |          | Autonomous Disable (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_7_4    |          | Autonomous Update Metadata (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_7_5    |          | Autonomous Release (O)                       |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 8: ASE State Transitions**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_8_1    | x        | Released transition to Codec Configured state|
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_8_2    | x        | Released transition to Idle state (C.1)      |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

GATT requirements
=================

**Table 9: GATT Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_9_1    | x        | Write Without Response (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_9_2    | x        | Write Characteristic Value (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_9_3    | x        | Write Long Characteristic Value (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_9_4    | x        | Single Notification (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_9_5    | x        | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_9_6    | x        | Write Characteristic Descriptor (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_9_7    |          | Enhanced ATT bearer (BR/EDR or LE) (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_9_8    |          | GATT Server over BR/EDR (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_ASCS_9_9    | x        | GATT Server over LE (C.2)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF ASCS 2/1 "Service supported over BR/EDR", otherwise not
  defined.
- C.2: Mandatory IF ASCS 2/2 "Service supported over LE", otherwise not
  defined.

SDP requirements
================

**Table 10: SDP Requirements**

Prerequisite: ASCS 2/1 "Service supported over BR/EDR"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_ASCS_10_1   |          | SDP record present for ASCS (M)              |
+------------------+----------+----------------------------------------------+

- M: Mandatory

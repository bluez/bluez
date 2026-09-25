.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

=====================
Media Control Service
=====================
(TCRL pkg103, MCS.ICS.p5)

Service support
===============

**Table 0b: Service Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_0b_1    |          | Media Control Service (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_0b_2    | x        | Generic Media Control Service (C.1)          |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

MCS versions
============

**Table 0: X.Y Versions**

Prerequisite: MCS 0b/1 "Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_0_1     |          | MCS v1.0 (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 0a: X.Y.Z Versions**

Prerequisite: MCS 0b/1 "Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_0a_1    |          | MCS v1.0.1 (O)                               |
+------------------+----------+----------------------------------------------+

- O: Optional

MCS transports
==============

**Table 1: Transport Requirements**

Prerequisite: MCS 0b/1 "Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_1_1     |          | Service supported over BR/EDR (C.1, C.3)     |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_1_2     |          | Service supported over LE (C.2, C.3)         |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Service IF CORE 41/2 "LE Core Configuration" OR CORE
  40/1 "Core-Controller".
- C.2: Excluded for this Service IF CORE 41/1 "BR/EDR Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.3: Mandatory to support at least one.

MCS Service requirements
========================

**Table 2: Media Control Service Requirements**

Prerequisite: MCS 0b/1 "Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_2_1     |          | Media Control Service (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_2     |          | Object Transfer Service (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_3     |          | Media Player Name Characteristic (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_4     |          | Media Player Name - Read Long Support (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_5     |          | Media Player Icon Object ID Characteristic   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_6     |          | Media Player Icon URL Characteristic (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_7     |          | Track Changed Characteristic (M)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_8     |          | Track Title Characteristic (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_9     |          | Track Title - Read Long Support (O)          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_10    |          | Track Duration Characteristic (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_11    |          | Track Position Characteristic (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_12    |          | Playback Speed Characteristic (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_13    |          | Seeking Speed Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_14    |          | Current Track Segments Object ID             |
|                  |          | Characteristic (C.2)                         |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_15    |          | Current Track Object ID Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_16    |          | Next Track Object ID Characteristic (C.2)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_17    |          | Parent Group Object ID Characteristic (C.2)  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_18    |          | Current Group Object ID Characteristic (C.2) |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_19    |          | Playing Order Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_20    |          | Playing Order Supported Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_21    |          | Media State Characteristic (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_22    |          | Media Control Point Characteristic (M)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_23    |          | Media Control Point Opcodes Supported        |
|                  |          | Characteristic (M)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_24    |          | Search Results Object ID Characteristic (O)  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_25    |          | Search Control Point Characteristic (C.3)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_2_26    |          | Content Control ID Characteristic (M)        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF MCS 2/5 "Media Player Icon Object ID Characteristic" OR
  MCS 2/14 "Current Track Segments Object ID Characteristic" OR MCS 2/15
  "Current Track Object ID Characteristic" OR MCS 2/16 "Next Track Object ID
  Characteristic" OR MCS 2/17 "Parent Group Object ID Characteristic" OR MCS
  2/18 "Current Group Object ID Characteristic" OR MCS 2/24 "Search Results
  Object ID Characteristic", otherwise not defined.
- C.2: Mandatory IF MCS 2/15 "Current Track Object ID Characteristic",
  otherwise Excluded.
- C.3: Mandatory IF MCS 2/24 "Search Results Object ID Characteristic",
  otherwise Excluded.

**Table 3: Media Control Point Opcode Requirements**

Prerequisite: MCS 2/22 "Media Control Point Characteristic"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_3_1     |          | Play (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_2     |          | Pause (C.1)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_3     |          | Fast Rewind (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_4     |          | Fast Forward (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_5     |          | Stop (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_6     |          | Move Relative (C.1)                          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_7     |          | Previous Segment (C.1)                       |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_8     |          | Next Segment (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_9     |          | First Segment (C.1)                          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_10    |          | Last Segment (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_11    |          | Goto Segment (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_12    |          | Previous Track (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_13    |          | Next Track (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_14    |          | First Track (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_15    |          | Last Track (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_16    |          | Goto Track (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_17    |          | Previous Group (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_18    |          | Next Group (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_19    |          | First Group (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_20    |          | Last Group (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_3_21    |          | Goto Group (C.1)                             |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

**Table 4: Media State Requirements**

Prerequisite: MCS 0b/1 "Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_4_1     |          | Play (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_4_2     |          | Pause (C.2)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_4_3     |          | Seeking (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_4_4     |          | Inactive (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF MCS 3/1 "Play", otherwise Excluded.
- C.2: Optional IF MCS 3/2 "Pause", otherwise Excluded.

MCS GATT requirements
=====================

**Table 5: GATT Requirements**

Prerequisite: MCS 0b/1 "Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_5_1     |          | Write Without Response (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_5_2     |          | Single Notification (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_5_3     |          | Write Characteristic Descriptor (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_5_4     |          | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_5_5     |          | GATT Server over BR/EDR (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_5_6     |          | GATT Server over LE (C.2)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF MCS 1/1 "Service supported over BR/EDR", otherwise not
  defined.
- C.2: Mandatory IF MCS 1/2 "Service supported over LE", otherwise not
  defined.

MCS SDP requirements
====================

**Table 6: SDP Requirements**

Prerequisite: MCS 1/1 "Service supported over BR/EDR"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_6_1     |          | SDP record present for MCS (M)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory

GMCS versions
=============

**Table 20: X.Y Versions**

Prerequisite: MCS 0b/2 "Generic Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_20_1    | x        | GMCS v1.0 (M)                                |
+------------------+----------+----------------------------------------------+

- M: Mandatory

GMCS versions
=============

**Table 20a: X.Y.Z Versions**

Prerequisite: MCS 0b/2 "Generic Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_20a_1   |          | GMCS v1.0.1 (O)                              |
+------------------+----------+----------------------------------------------+

- O: Optional

GMCS transports
===============

**Table 21: Transport Requirements**

Prerequisite: MCS 0b/2 "Generic Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_21_1    |          | Service supported over BR/EDR (C.1, C.3)     |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_21_2    | x        | Service supported over LE (C.2, C.3)         |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Service IF CORE 41/2 "LE Core Configuration" OR CORE
  40/1 "Core-Controller".
- C.2: Excluded for this Service IF CORE 41/1 "BR/EDR Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.3: Mandatory to support at least one.

GMCS Service requirements
=========================

**Table 22: Generic Media Control Service Requirements**

Prerequisite: MCS 0b/2 "Generic Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_22_1    | x        | Generic Media Control Service (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_2    |          | Object Transfer Service (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_3    | x        | Media Player Name Characteristic (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_4    |          | Media Player Name Read Long Supported (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_5    |          | Media Player Icon Object ID Characteristic   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_6    |          | Media Player Icon URL Characteristic (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_7    | x        | Track Changed Characteristic (M)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_8    | x        | Track Title Characteristic (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_9    |          | Track Title Read Long Supported (O)          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_10   | x        | Track Duration Characteristic (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_11   | x        | Track Position Characteristic (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_12   |          | Playback Speed Characteristic (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_13   |          | Seeking Speed Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_14   |          | Current Track Segments Object ID             |
|                  |          | Characteristic (C.2)                         |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_15   |          | Current Track Object ID Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_16   |          | Next Track Object ID Characteristic (C.2)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_17   |          | Parent Group Object ID Characteristic (C.2)  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_18   |          | Current Group Object ID Characteristic (C.2) |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_19   |          | Playing Order Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_20   |          | Playing Order Supported Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_21   | x        | Media State Characteristic (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_22   | x        | Media Control Point Characteristic (M)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_23   | x        | Media Control Point Opcodes Supported        |
|                  |          | Characteristic (M)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_24   |          | Search Results Object ID Characteristic (O)  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_25   |          | Search Control Point Characteristic (C.3)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_22_26   | x        | Content Control ID Characteristic (M)        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF MCS 22/5 "Media Player Icon Object ID Characteristic" OR
  MCS 22/14 "Current Track Segments Object ID Characteristic" OR MCS 22/15
  "Current Track Object ID Characteristic" OR MCS 22/16 "Next Track Object ID
  Characteristic" OR MCS 22/17 "Parent Group Object ID Characteristic" OR MCS
  22/18 "Current Group Object ID Characteristic" OR MCS 22/24 "Search Results
  Object ID Characteristic", otherwise not defined.
- C.2: Mandatory IF MCS 22/15 "Current Track Object ID Characteristic",
  otherwise Excluded.
- C.3: Mandatory IF MCS 22/24 "Search Results Object ID Characteristic",
  otherwise Excluded.

**Table 23: Generic Media Control Point Opcode Requirements**

Prerequisite: MCS 22/22 "Media Control Point Characteristic"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_23_1    | x        | Play (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_2    | x        | Pause (C.1)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_3    | x        | Fast Rewind (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_4    | x        | Fast Forward (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_5    | x        | Stop (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_6    |          | Move Relative (C.1)                          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_7    |          | Previous Segment (C.1)                       |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_8    |          | Next Segment (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_9    |          | First Segment (C.1)                          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_10   |          | Last Segment (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_11   |          | Goto Segment (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_12   | x        | Previous Track (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_13   | x        | Next Track (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_14   |          | First Track (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_15   |          | Last Track (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_16   |          | Goto Track (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_17   |          | Previous Group (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_18   |          | Next Group (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_19   |          | First Group (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_20   |          | Last Group (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_23_21   |          | Goto Group (C.1)                             |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

**Table 24: Media State Supported Requirements**

Prerequisite: MCS 0b/2 "Generic Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_24_1    | x        | Play (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_24_2    | x        | Pause (C.2)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_24_3    |          | Seeking (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_24_4    | x        | Inactive (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF MCS 23/1 "Play", otherwise Excluded.
- C.2: Optional IF MCS 23/2 "Pause", otherwise Excluded.

GMCS GATT requirements
======================

**Table 25: GATT Requirements**

Prerequisite: MCS 0b/2 "Generic Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_25_1    | x        | Write Without Response (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_25_2    | x        | Single Notification (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_25_3    | x        | Write Characteristic Descriptor (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_25_4    | x        | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_25_5    |          | GATT Server over BR/EDR (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_MCS_25_6    | x        | GATT Server over LE (C.2)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF MCS 21/1 "Service supported over BR/EDR", otherwise not
  defined.
- C.2: Mandatory IF MCS 21/2 "Service supported over LE", otherwise not
  defined.

GMCS SDP requirements
=====================

**Table 26: SDP Requirements**

Prerequisite: MCS 21/1 "Service supported over BR/EDR"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCS_26_1    |          | SDP record present for GMCS (M)              |
+------------------+----------+----------------------------------------------+

- M: Mandatory

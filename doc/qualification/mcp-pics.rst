.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

=====================
Media Control Profile
=====================
(TCRL pkg103, MCP.ICS.p4)

Roles
=====

**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_1_1     | x        | Media Control Server (C.1)                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_1_2     |          | Media Control Client (C.1)                   |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

Transports
==========

**Table 2: Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_2_1     |          | Profile supported over BR/EDR (C.1, C.3)     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_2_2     | x        | Profile supported over LE (C.2, C.3)         |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Profile IF CORE 41/2 "LE Core Configuration" OR CORE
  40/1 "Core-Controller".
- C.2: Excluded for this Profile IF CORE 41/1 "BR/EDR Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.3: Mandatory to support at least one.

Media Control Server role
=========================

**Table 3: X.Y Versions (Media Control Server)**

Prerequisite: MCP 1/1 "Media Control Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_3_1     | x        | MCP v1.0 (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 5: Service Requirements**

Prerequisite: MCP 1/1 "Media Control Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_5_1     |          | Media Control Service (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_5_2     | x        | Generic Media Control Service (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_5_3     |          | Object Transfer Service (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_5_4     | x        | LE Extended Advertising (M)                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 6: GAP Requirements (Media Control Server Role)**

Prerequisite: MCP 1/1 "Media Control Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_6_1     | x        | LE security mode 1 (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_2     | x        | Bondable mode (LE) (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_3     | x        | Bonding procedure (LE) (C.1)                 |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_4     | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (C.6)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_5     | x        | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (C.6)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_6     | x        | LE security mode 1 level 4 (C.6)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_7     | x        | Minimum 128 Bit entropy key (LE) (C.3)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_8     | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_9     |          | Security mode 4, level 2 (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_10    |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_11    |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_12    |          | BR/EDR Secure Connections (C.7)              |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_13    | x        | LE Secure Connections (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_14    |          | Out of Band (LE) (C.8)                       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_6_15    |          | Out-of-Band (BR/EDR) (C.7)                   |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF MCP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.2: Mandatory IF MCP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.3: Mandatory IF MCP 6/4 "Unauthenticated Pairing (LE security mode 1
  level 2) with LE Secure Connections Pairing only" OR MCP 6/5 "Authenticated
  Pairing (LE security mode 1 level 3) with LE Secure Connections Pairing
  only", otherwise not defined.
- C.6: Mandatory to support at least one IF MCP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.7: Mandatory to support at least one IF MCP 2/1 "Profile supported over
  BR/EDR", otherwise not defined.
- C.8: Mandatory to support at least one IF MCP 2/2 "Profile supported over
  LE", otherwise not defined.

**Table 8: OTP Requirements (Media Control Server)**

Prerequisite: MCP 5/3 "Object Transfer Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_8_1     |          | Object Server (M)                            |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 9: OTS Characteristics Requirements (Media Control Server)**

Prerequisite: MCP 5/3 "Object Transfer Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_9_1     |          | Object ID Characteristic (M)                 |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_9_2     |          | Object List Control Point (OLCP) (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_9_3     |          | Object Changed Characteristic (M)            |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 10: OTS Feature Requirements (Media Control Server)**

Prerequisite: MCP 5/3 "Object Transfer Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_10_1    |          | OACP Read Procedure (M)
+------------------+----------+----------------------------------------------+
| TSPC_MCP_10_2    |          | OLCP Go To Procedure (M)
+------------------+----------+----------------------------------------------+

- M: Mandatory

Media Control Client role
=========================

**Table 11: X.Y Versions (Media Control Client)**

Prerequisite: MCP 1/2 "Media Control Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_11_1    |          | MCP v1.0 (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 13: Media Control Service Support**

Prerequisite: MCP 1/2 "Media Control Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_13_1    |          | Discover Media Control Service (C.1)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_13_2    |          | Discover Generic Media Control Service (C.1) |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_13_3    |          | Discover Object Transfer Service (C.2)       |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.
- C.2: Mandatory IF MCP 14/20 "Search Results Object ID Characteristic" OR
  MCP 16/20 "Search Results Object ID Characteristic" OR MCP 14/10 "Current
  Track Segments Object ID Characteristic" OR MCP 16/10 "Current Track
  Segments Object ID Characteristic" OR MCP 14/11 "Current Track Object ID
  Characteristic" OR MCP 16/11 "Current Track Object ID Characteristic",
  otherwise Optional.

**Table 14: Media Control Service Characteristic Support Requirements**

Prerequisite: MCP 13/1 "Discover Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_14_1    |          | Media Player Name Characteristic (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_2    |          | Media Player Icon Object ID Characteristic   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_3    |          | Media Player Icon URL Characteristic (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_4    |          | Track Changed Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_5    |          | Track Title Characteristic (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_6    |          | Track Duration Characteristic (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_7    |          | Track Position Characteristic (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_8    |          | Playback Speed Characteristic (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_9    |          | Seeking Speed Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_10   |          | Current Track Segments Object ID             |
|                  |          | Characteristic (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_11   |          | Current Track Object ID Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_12   |          | Next Track Object ID Characteristic (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_13   |          | Parent Group Object ID Characteristic (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_14   |          | Current Group Object ID Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_15   |          | Playing Order Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_16   |          | Playing Order Supported Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_17   |          | Media State Characteristic (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_18   |          | Media Control Point Characteristic (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_19   |          | Media Control Point Opcodes Supported        |
|                  |          | Characteristic (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_20   |          | Search Results Object ID Characteristic (O)  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_21   |          | Search Control Point Characteristic (C.1)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_14_22   |          | Content Control ID Characteristic (O)        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF MCP 14/20 "Search Results Object ID Characteristic",
  otherwise Excluded.

**Table 15: Media Control Point Procedure Requirements**

Prerequisite: MCP 14/18 "Media Control Point Characteristic"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_15_1    |          | Play Current Track Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_2    |          | Pause Current Track Procedure (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_3    |          | Fast Forward Fast Rewind Procedure (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_4    |          | Stop Current Track Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_5    |          | Move Relative Procedure (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_6    |          | Move to Previous Segment Procedure (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_7    |          | Move to Next Segment Procedure (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_8    |          | Move to First Segment Procedure (O)          |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_9    |          | Move to Last Segment Procedure (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_10   |          | Move to Segment Number Procedure (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_11   |          | Move to Previous Track Procedure (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_12   |          | Move to Next Track Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_13   |          | Move to First Track Procedure (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_14   |          | Move to Last Track Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_15   |          | Move to Track Number Procedure (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_16   |          | Move to Previous Group Procedure (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_17   |          | Move to Next Group Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_18   |          | Move to First Group Procedure (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_19   |          | Move to Last Group Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_15_20   |          | Move to Group Number Procedure (O)           |
+------------------+----------+----------------------------------------------+

- O: Optional

**Table 16: Generic Media Control Service Characteristic Support Requirements**

Prerequisite: MCP 13/2 "Discover Generic Media Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_16_1    |          | Media Player Name Characteristic (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_2    |          | Media Player Icon Object ID Characteristic   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_3    |          | Media Player Icon URL Characteristic (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_4    |          | Track Changed Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_5    |          | Track Title Characteristic (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_6    |          | Track Duration Characteristic (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_7    |          | Track Position Characteristic (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_8    |          | Playback Speed Characteristic (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_9    |          | Seeking Speed Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_10   |          | Current Track Segments Object ID             |
|                  |          | Characteristic (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_11   |          | Current Track Object ID Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_12   |          | Next Track Object ID Characteristic (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_13   |          | Parent Group Object ID Characteristic (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_14   |          | Current Group Object ID Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_15   |          | Playing Order Characteristic (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_16   |          | Playing Order Supported Characteristic (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_17   |          | Media State Characteristic (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_18   |          | Media Control Point Characteristic (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_19   |          | Media Control Opcodes Supported              |
|                  |          | Characteristic (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_20   |          | Search Results Object ID Characteristic (O)  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_21   |          | Search Control Point Characteristic (C.1)    |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_16_22   |          | Content Control ID Characteristic (O)        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF MCP 16/20 "Search Results Object ID Characteristic",
  otherwise Excluded.

**Table 17: Media Control Point Procedure Requirements**

Prerequisite: MCP 16/18 "Media Control Point Characteristic"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_17_1    |          | Play Current Track Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_2    |          | Pause Current Track Procedure (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_3    |          | Fast Forward Fast Rewind Procedure (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_4    |          | Stop Current Track Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_5    |          | Move Relative Procedure (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_6    |          | Move to Previous Segment Procedure (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_7    |          | Move to Next Segment Procedure (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_8    |          | Move to First Segment Procedure (O)          |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_9    |          | Move to Last Segment Procedure (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_10   |          | Move to Segment Number Procedure (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_11   |          | Move to Previous Track Procedure (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_12   |          | Move to Next Track Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_13   |          | Move to First Track Procedure (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_14   |          | Move to Last Track Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_15   |          | Move to Track Number Procedure (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_16   |          | Move to Previous Group Procedure (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_17   |          | Move to Next Group Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_18   |          | Move to First Group Procedure (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_19   |          | Move to Last Group Procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_17_20   |          | Move to Group Number Procedure (O)           |
+------------------+----------+----------------------------------------------+

- O: Optional

**Table 18: GAP Requirements (Media Control Client)**

Prerequisite: MCP 1/2 "Media Control Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_18_2    |          | LE security mode 1 (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_3    |          | Bondable mode (LE) (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_4    |          | Bonding procedure (C.1)                      |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_5    |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_6    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_7    |          | LE security mode 1 level 4 (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_8    |          | Minimum 128 Bit entropy key (LE) (C.5)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_9    |          | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_10   |          | Security mode 4, level 2 (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_11   |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_12   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_13   |          | BR/EDR Secure Connections (C.7)              |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_14   |          | LE Secure Connections (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_15   |          | Out of Band (LE) (C.6)                       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18_16   |          | Out-of-Band (BR/EDR) (C.7)                   |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF MCP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.2: Mandatory IF MCP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.5: Mandatory IF MCP 18/5 "Unauthenticated Pairing (LE security mode 1
  level 2) with LE Secure Connections Pairing only" OR MCP 18/6 "Authenticated
  Pairing (LE security mode 1 level 3) with LE Secure Connections Pairing
  only", otherwise not defined.
- C.6: Mandatory to support at least one IF MCP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.7: Mandatory to support at least one IF MCP 2/1 "Profile supported over
  BR/EDR", otherwise not defined.

**Table 18a: GATT Requirements**

Prerequisite: MCP 1/2 "Media Control Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_18a_1   |          | GATT Client over BR/EDR (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_2   |          | GATT Client over LE (C.2)                    |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_3   |          | Discover All Primary Services (C.3)          |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_4   |          | Discover Primary Service by Service UUID     |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_5   |          | Find Included Services (O)                   |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_6   |          | Discover All Characteristics of a Service    |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_7   |          | Discover Characteristics by UUID (C.4)       |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_8   |          | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_9   |          | Single Notification (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_10  |          | Read Characteristic Value (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_11  |          | Write Characteristic Value (C.5)             |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_12  |          | Write Without Response (C.5)                 |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_13  |          | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_18a_14  |          | Write Characteristic Descriptor (M)          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF MCP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.2: Mandatory IF MCP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.3: Mandatory to support at least one.
- C.4: Mandatory to support at least one.
- C.5: Mandatory to support at least one.

**Table 20: OTP Requirements (Media Control Client)**

Prerequisite: MCP 13/3 "Discover Object Transfer Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_20_1    |          | Object Client (M)                            |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 21: OTP Procedure Requirements (Media Control Client)**

Prerequisite: MCP 13/3 "Discover Object Transfer Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MCP_21_1    |          | Object Discovery - Discover All Objects (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_21_2    |          | Select Object - Select by Object ID (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_MCP_21_3    |          | Read Object - Read Object Contents (M)       |
+------------------+----------+----------------------------------------------+

- M: Mandatory

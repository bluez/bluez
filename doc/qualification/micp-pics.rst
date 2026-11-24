.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

==========================
Microphone Control Profile
==========================
(TCRL pkg103, MICP.ICS.p4)

Roles
=====

**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_1_1    |          | Microphone Device (C.1)                      |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_1_2    | x        | Microphone Controller (C.1)                  |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

Transports
==========

**Table 2: Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_2_1    |          | Profile supported over BR/EDR (C.1, C.3)     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_2_2    | x        | Profile supported over LE (C.2, C.3)         |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Profile IF CORE 41/2 "LE Core Configuration" OR CORE
  40/1 "Core-Controller".
- C.2: Excluded for this Profile IF CORE 41/1 "BR/EDR Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.3: Mandatory to support at least one.

Microphone Device role
======================

**Table 3: X.Y Versions (Microphone Device)**

Prerequisite: MICP 1/1 "Microphone Device"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_3_1    |          | MICP v1.0 (M)                                |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 5: Service Requirements**

Prerequisite: MICP 1/1 "Microphone Device"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_5_1    |          | Microphone Control Service (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_5_2    |          | Audio Input Control Service (O)              |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 6: GAP Requirements (Microphone Device)**

Prerequisite: MICP 1/1 "Microphone Device"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_6_1    |          | LE security mode 1 (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_2    |          | Bondable mode (LE) (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_3    |          | Bondable mode (BR/EDR) (C.2)                 |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_4    |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (C.3)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_5    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (C.3)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_6    |          | LE security mode 1 level 4 (C.3)             |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_7    |          | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_8    |          | Minimum 128 Bit entropy key (LE) (C.6)       |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_9    |          | Security mode 4, level 2 (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_10   |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_11   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_12   |          | BR/EDR Secure Connections (C.8)              |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_13   |          | LE Secure Connections (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_14   |          | Out of Band (LE) (C.7)                       |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_6_15   |          | Out-of-Band (BR/EDR) (C.8)                   |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF MICP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.2: Optional IF MICP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.3: Mandatory to support at least one IF MICP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.6: Mandatory IF MICP 6/4 "Unauthenticated Pairing (LE security mode 1
  level 2) with LE Secure Connections Pairing only" OR MICP 6/5 "Authenticated
  Pairing (LE security mode 1 level 3) with LE Secure Connections Pairing
  only", otherwise not defined.
- C.7: Mandatory to support at least one IF MICP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.8: Mandatory to support at least one IF MICP 2/1 "Profile supported over
  BR/EDR", otherwise not defined.

Microphone Controller role
==========================

**Table 8: X.Y Versions (Microphone Controller)**

Prerequisite: MICP 1/2 "Microphone Controller"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_8_1    | x        | MICP v1.0 (M)                                |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 10: Service Requirements**

Prerequisite: MICP 1/2 "Microphone Controller"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_10_1   | x        | Discover Microphone Control Service (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_10_2   | x        | Discover Audio Input Control Service (O)     |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 11: Microphone Control Service Characteristic Discovery Requirements**

Prerequisite: MICP 10/1 "Discover Microphone Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_11_1   | x        | Mute (M)                                     |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 12: Microphone Control Service Procedures Support Requirements**

Prerequisite: MICP 10/1 "Discover Microphone Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_12_1   |          | Configure Mute Notifications (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_12_2   | x        | Read Mute (M)                                |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_12_3   | x        | Set Mute (O)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 13: Audio Input Control Service Characteristic Discovery Requirements**

Prerequisite: MICP 10/2 "Discover Audio Input Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_13_1   | x        | Audio Input State (C.1)                      |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_13_2   | x        | Gain Setting Propertie (C.1)                 |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_13_3   |          | Audio Input Type (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_13_4   |          | Audio Input Status (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_13_5   |          | Audio Input Control Point (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_13_6   |          | Audio Input Description (O)                  |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF MICP 14/7 "Set Gain Setting" OR MICP 14/8 "Mute" OR MICP
  14/9 "Unmute" OR MICP 14/10 "Set Manual Gain Mode" OR MICP 14/11 "Set
  Automatic Gain Mode", otherwise Optional.

**Table 14: Audio Input Control Service Procedures Requirements**

Prerequisite: MICP 10/2 "Discover Audio Input Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_14_1   | x        | Configure Input State Notifications (C.1)    |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_2   | x        | Read Audio Input State (C.1)                 |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_3   |          | Read Gain Setting Properties (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_4   |          | Read Audio Input Type (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_5   |          | Configure Audio Input Status Notifications   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_6   |          | Read Audio Input Status (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_7   | x        | Set Gain Setting (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_8   |          | Mute (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_9   |          | Unmute (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_10  |          | Set Manual Gain Mode (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_11  |          | Set Automatic Gain Mode (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_12  |          | Configure Audio Input Description            |
|                  |          | Notifications (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_13  |          | Read Audio Input Description (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_14_14  |          | Set Audio Input Description (O)              |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF MICP 14/7 "Set Gain Setting" OR MICP 14/8 "Mute" OR MICP
  14/9 "Unmute" OR MICP 14/10 "Set Manual Gain Mode" OR MICP 14/11 "Set
  Automatic Gain Mode", otherwise Optional.

**Table 15: Microphone Controller GATT Requirements**

Prerequisite: MICP 1/2 "Microphone Controller"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_15_1   | x        | Discover All Primary Services (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_2   | x        | Discover Primary Service by Service UUID     |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_3   | x        | Find Included Services (C.2)                 |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_4   | x        | Discover All Characteristics of a Service    |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_5   | x        | Discover Characteristics by UUID (C.3)       |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_6   | x        | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_7   | x        | Read Characteristic Value (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_8   | x        | Write Characteristic Value (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_9   | x        | Single Notification (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_10  | x        | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_11  | x        | Write Characteristic Descriptor (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_12  |          | GATT Client over BR/EDR (C.4)                |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_15_13  | x        | GATT Client over LE (C.5)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory to support at least one.
- C.2: Mandatory IF MICP 14/1 "Configure Input State Notifications" OR MICP
  14/2 "Read Audio Input State" OR MICP 14/3 "Read Gain Setting Properties"
  OR MICP 14/4 "Read Audio Input Type" OR MICP 14/5 "Configure Audio Input
  Status Notifications" OR MICP 14/6 "Read Audio Input Status" OR MICP 14/7
  "Set Gain Setting" OR MICP 14/8 "Mute" OR MICP 14/9 "Unmute" OR MICP 14/10
  "Set Manual Gain Mode" OR MICP 14/11 "Set Automatic Gain Mode" OR MICP
  14/12 "Configure Audio Input Description Notifications" OR MICP 14/13 "Read
  Audio Input Description" OR MICP 14/14 "Set Audio Input Description",
  otherwise Optional.
- C.3: Mandatory to support at least one.
- C.4: Mandatory IF MICP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.5: Mandatory IF MICP 2/2 "Profile supported over LE", otherwise not
  defined.

**Table 16: GAP Requirements (Microphone Controller)**

Prerequisite: MICP 1/2 "Microphone Controller"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_MICP_16_1   | x        | Bondable mode (LE) (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_2   |          | Bondable mode (BR/EDR) (C.2)                 |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_3   | x        | LE security mode 1 (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_4   |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_5   |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_6   |          | LE security mode 1 level 4 (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_7   |          | Minimum 128 Bit entropy key (LE) (C.3)       |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_8   | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_9   |          | Security mode 4, level 2 (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_10  |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_11  |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_12  |          | BR/EDR Secure Connections (C.7)              |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_13  | x        | LE Secure Connections (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_14  |          | Out of Band (LE) (C.6)                       |
+------------------+----------+----------------------------------------------+
| TSPC_MICP_16_15  |          | Out-of-Band (BR/EDR) (C.7)                   |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF MICP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.2: Optional IF MICP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.3: Mandatory IF MICP 16/4 "Unauthenticated Pairing (LE security mode 1
  level 2) with LE Secure Connections Pairing only" OR MICP 16/5
  "Authenticated Pairing (LE security mode 1 level 3) with LE Secure
  Connections Pairing only", otherwise not defined.
- C.6: Mandatory to support at least one IF MICP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.7: Mandatory to support at least one IF MICP 2/1 "Profile supported over
  BR/EDR", otherwise not defined.

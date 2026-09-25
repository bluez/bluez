.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

======================
Volume Control Profile
======================
(TCRL pkg103, VCP.ICS.p6)

Roles
=====

**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_1_1     |          | Volume Renderer (C.1)                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_1_2     | x        | Volume Controller (C.1)                      |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

Transports
==========

**Table 2: Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_2_1     |          | Profile supported over BR/EDR (C.1, C.3)     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_2_2     | x        | Profile supported over LE (C.2, C.3)         |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Profile IF CORE 41/2 "LE Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.2: Excluded for this Profile IF CORE 41/1 "BR/EDR Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.3: Mandatory to support at least one.

Volume Renderer role
====================

**Table 3: X.Y Versions (Volume Renderer)**

Prerequisite: VCP 1/1 "Volume Renderer"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_3_1     |          | VCP v1.0 (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 5: Service Requirements**

Prerequisite: VCP 1/1 "Volume Renderer"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_5_1     |          | Volume Control Service (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_5_2     |          | Volume Offset Control Service (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_5_3     |          | Audio Input Control Service (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_5_4     |          | LE Extended Advertising (M)                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 6: GAP Requirements (Volume Renderer)**

Prerequisite: VCP 1/1 "Volume Renderer"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_6_1     |          | LE security mode 1 (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_2     |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_3     |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (C.3)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_4     |          | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_5     |          | Security mode 4, level 2 (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_6     |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_7     |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_8     |          | Minimum 128 Bit entropy key (LE) (C.1)       |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_9     |          | BR/EDR Secure Connections (C.7)              |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_10    |          | LE Secure Connections (Peripheral) (C.6)     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_11    |          | Out of Band (Peripheral) (C.6)               |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_12    |          | Out-of-Band (BR/EDR) (C.7)                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_6_13    |          | Peripheral (C.1)                             |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF VCP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.2: Mandatory IF VCP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.3: Optional IF VCP 2/2 "Profile supported over LE", otherwise not defined.
- C.6: Mandatory to support at least one IF VCP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.7: Mandatory to support at least one IF VCP 2/1 "Profile supported over
  BR/EDR", otherwise not defined.

Volume Controller role
======================

**Table 8: X.Y Versions (Volume Controller)**

Prerequisite: VCP 1/2 "Volume Controller"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_8_1     | x        | VCP v1.0 (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 10: Volume Control Service Support**

Prerequisite: VCP 1/2 "Volume Controller"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_10_1    | x        | Discover Volume Control Service (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_10_2    |          | Discover Volume Offset Control Service (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_10_3    |          | Discover Audio Input Control Service (O)     |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 11: Volume Control Service Characteristic Support Requirements**

Prerequisite: VCP 10/1 "Discover Volume Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_11_1    | x        | Volume State (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_11_2    | x        | Volume Control Point (M)                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_11_3    |          | Volume Flags (O)                             |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 12: Volume Control Service Procedure Support Requirements**

Prerequisite: VCP 10/1 "Discover Volume Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_12_1    | x        | Configure Volume State Notifications (M)     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_2    | x        | Read Volume State (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_3    |          | Configure Volume Flags Notifications (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_4    |          | Read Volume Flags (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_5    |          | Set Initial Volume (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_6    | x        | Set Absolute Volume (C.2)                    |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_7    |          | Relative Volume Down (C.3)                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_8    |          | Relative Volume Up (C.3)                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_9    |          | Unmute/ Relative Volume Down (C.4)           |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_10   |          | Unmute/ Relative Volume Up (C.4)             |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_11   | x        | Mute (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_12_12   | x        | Unmute (O)                                   |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF VCP 12/4 "Read Volume Flags" OR VCP 12/6 "Set Absolute
  Volume", otherwise Excluded.
- C.2: Mandatory IF NOT VCP 12/7 "Relative Volume Down" AND NOT VCP 12/8
  "Relative Volume Up" AND NOT VCP 12/9 "Unmute/ Relative Volume Down" AND
  NOT VCP 12/10 "Unmute/ Relative Volume Up", otherwise Optional.
- C.3: Mandatory to support none or all.
- C.4: Mandatory to support none or all.

**Table 13: Volume Offset Control Service Characteristic Support Requirements**

Prerequisite: VCP 10/2 "Discover Volume Offset Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_13_1    |          | Volume Offset State (C.1)                    |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_13_2    |          | Audio Location (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_13_3    |          | Volume Offset Control Point (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_13_4    |          | Audio Output Description (O)                 |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF VCP 14/1 "Configure Offset State Notifications" OR VCP
  14/2 "Read Volume Offset State" OR VCP 14/3 "Configure Audio Location
  Notifications" OR VCP 14/4 "Read Audio Location" OR VCP 14/5 "Set Audio
  Location" OR VCP 14/6 "Set Volume Offset" OR VCP 14/7 "Configure Audio
  Output Description Notifications" OR VCP 14/8 "Read Audio Output
  Description" OR VCP 14/9 "Set Audio Output Description", otherwise Optional.

**Table 14: Volume Offset Control Service Procedure Support Requirements**

Prerequisite: VCP 10/2 "Discover Volume Offset Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_14_1    |          | Configure Offset State Notifications         |
|                  |          | (C.1, C.2)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_14_2    |          | Read Volume Offset State (C.1, C.2)          |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_14_3    |          | Configure Audio Location Notifications (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_14_4    |          | Read Audio Location (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_14_5    |          | Set Audio Location (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_14_6    |          | Set Volume Offset (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_14_7    |          | Configure Audio Output Description           |
|                  |          | Notifications (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_14_8    |          | Read Audio Output Description (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_14_9    |          | Set Audio Output Description (O)             |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF VCP 14/3 "Configure Audio Location Notifications" OR VCP
  14/4 "Read Audio Location" OR VCP 14/5 "Set Audio Location" OR VCP 14/6
  "Set Volume Offset" OR VCP 14/7 "Configure Audio Output Description
  Notifications" OR VCP 14/8 "Read Audio Output Description" OR VCP 14/9
  "Set Audio Output Description", otherwise Optional.
- C.2: Mandatory to support none or all.

**Table 15: Audio Input Control Service Characteristic Support Requirements**

Prerequisite: VCP 10/3 "Discover Audio Input Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_15_1    |          | Audio Input State (C.1)                      |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_15_2    |          | Gain Setting Properties (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_15_3    |          | Audio Input Type (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_15_4    |          | Audio Input Status (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_15_5    |          | Audio Input Control Point (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_15_6    |          | Audio Input Description (O)                  |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF VCP 16/1 "Configure Audio Input State Notifications" OR
  VCP 16/2 "Read Audio Input State" OR VCP 16/3 "Read Gain Setting Properties"
  OR VCP 16/4 "Read Audio Input Type" OR VCP 16/5 "Configure Audio Input
  Status Notifications" OR VCP 16/6 "Read Audio Input Status" OR VCP 16/7 "Set
  Gain Setting" OR VCP 16/8 "Mute" OR VCP 16/9 "Unmute" OR VCP 16/10 "Set
  Manual Gain Mode" OR VCP 16/11 "Set Automatic Gain Mode" OR VCP 16/12
  "Configure Audio Input Description Notifications" OR VCP 16/13 "Read Audio
  Input Description" OR VCP 16/14 "Set Audio Input Description", otherwise
  Optional.

**Table 16: Audio Input Control Service Procedure Support Requirements**

Prerequisite: VCP 10/3 "Discover Audio Input Control Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_16_1    |          | Configure Audio Input State Notifications    |
|                  |          | (C.1, C.2)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_2    |          | Read Audio Input State (C.1, C.2)            |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_3    |          | Read Gain Setting Properties (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_4    |          | Read Audio Input Type (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_5    |          | Configure Audio Input Status Notifications   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_6    |          | Read Audio Input Status (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_7    |          | Set Gain Setting (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_8    |          | Mute (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_9    |          | Unmute (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_10   |          | Set Manual Gain Mode (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_11   |          | Set Automatic Gain Mode (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_12   |          | Configure Audio Input Description            |
|                  |          | Notifications (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_13   |          | Read Audio Input Description (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_16_14   |          | Set Audio Input Description (O)              |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF VCP 16/3 "Read Gain Setting Properties" OR VCP 16/4 "Read
  Audio Input Type" OR VCP 16/5 "Configure Audio Input Status Notifications"
  OR VCP 16/6 "Read Audio Input Status" OR VCP 16/7 "Set Gain Setting" OR VCP
  16/8 "Mute" OR VCP 16/9 "Unmute" OR VCP 16/10 "Set Manual Gain Mode" OR VCP
  16/11 "Set Automatic Gain Mode" OR VCP 16/12 "Configure Audio Input
  Description Notifications" OR VCP 16/13 "Read Audio Input Description" OR
  VCP 16/14 "Set Audio Input Description", otherwise Optional.
- C.2: Mandatory to support none or all.

**Table 17: Volume Controller GATT Requirements**

Prerequisite: VCP 1/2 "Volume Controller"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_17_1    | x        | Discover All Primary Services (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_2    | x        | Discover Primary Service by Service UUID     |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_3    |          | Find Included Services (C.3)                 |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_4    | x        | Discover All Characteristics of a Service    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_5    | x        | Discover Characteristics by UUID (C.2)       |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_6    | x        | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_7    | x        | Read Characteristic Value (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_8    | x        | Write Characteristic Value (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_9    | x        | Single Notification (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_10   | x        | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_11   | x        | Write Characteristic Descriptor (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_12   |          | GATT Client over BR/EDR (C.4)                |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_17_13   | x        | GATT Client over LE (C.5)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory to support at least one.
- C.2: Mandatory to support at least one.
- C.3: Mandatory IF VCP 16/1 "Configure Audio Input State Notifications" OR
  VCP 14/1 "Configure Offset State Notifications" otherwise Optional.
- C.4: Mandatory IF VCP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.5: Mandatory IF VCP 2/2 "Profile supported over LE", otherwise not
  defined.

**Table 18: GAP Requirements (Volume Controller)**

Prerequisite: VCP 1/2 "Volume Controller"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_VCP_18_1    | x        | Central (C.2)                                |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_2    | x        | LE security mode 1 (C.2)                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_3    | x        | Bondable mode (LE) (C.2)                     |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_4    |          | Bonding procedure (C.3)                      |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_5    |          | Initiation of dedicated bonding (C.1)        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_6    | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (C.2)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_7    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (C.3)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_8    | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_9    |          | Security mode 4, level 2 (C.4)               |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_10   |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_11   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_12   | x        | Minimum 128 Bit entropy key (LE) (C.2)       |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_13   |          | BR/EDR Secure Connections (C.8)              |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_14   | x        | LE Secure Connections (Central) (C.7)        |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_15   |          | Out of Band (Central) (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_VCP_18_16   |          | Out-of-Band (BR/EDR) (C.8)                   |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF VCP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.2: Mandatory IF VCP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.3: Optional IF VCP 2/2 "Profile supported over LE", otherwise not defined.
- C.4: Mandatory IF VCP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.7: Mandatory to support at least one IF VCP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.8: Mandatory to support at least one IF VCP 2/1 "Profile supported over
  BR/EDR", otherwise not defined.

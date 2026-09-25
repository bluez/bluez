.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

======================================
Coordinated Set Identification Profile
======================================
(TCRL pkg103, CSIP.ICS.p7)

Roles
=====

**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_1_1    |          | Set Member (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_1_2    | x        | Set Coordinator (C.1)                        |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

Transports
==========

**Table 2: Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_2_1    |          | Profile supported over BR/EDR (C.1, C.3)     |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_2_2    | x        | Profile supported over LE (C.2, C.3)         |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Profile IF CORE 41/2 "LE Core Configuration" OR CORE
  40/1 "Core-Controller".
- C.2: Excluded for this Profile IF CORE 41/1 "BR/EDR Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.3: Mandatory to support at least one.

Set Member role
===============

**Table 3: Set Member, X.Y Versions**

Prerequisite: CSIP 1/1 "Set Member"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_3_1    |          | CSIP v1.0 (C.1, C.2)                         |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_3_2    |          | CSIP v1.1 (C.1)                              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support one and only one.
- C.2: Can only be supported with an active X.Y.Z version after Deprecation
  or Withdrawal.
  Deprecated 2025-02-01. Withdrawn 2027-02-01.

**Table 4: Set Member, X.Y.Z Versions**

Prerequisite: CSIP 1/1 "Set Member"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_4_2    |          | CSIP v1.0.1 (C.1)                            |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF CSIP 3/1 "CSIP v1.0", otherwise Excluded.

**Table 5: Services Requirements**

Prerequisite: CSIP 1/1 "Set Member"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_5_1    |          | Coordinated Set Identification Service (M)   |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_2    |          | PSRI AD Type field over LE (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_3    |          | PSRI AD Type over BR/EDR (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_4    |          | Encrypted SIRK (C.3)                         |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_5    |          | Plaintext SIRK (C.3)                         |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_6    |          | OOB SIRK Only (C.3)                          |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_7    |          | Coordinated Set Size Characteristic (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_8    |          | Notifiable Coordinated Set Size              |
|                  |          | Characteristic (C.7)                         |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_9    |          | Coordinated Set Name Characteristic (C.4)    |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_10   |          | Notifiable Coordinated Set Name              |
|                  |          | Characteristic (C.8)                         |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_11   |          | Coordinated Set Name AD Type field over LE   |
|                  |          | (C.5)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_5_12   |          | Coordinated Set Name AD Type over BR/EDR     |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF CSIP 2/2 "Profile supported over LE", otherwise Excluded.
- C.2: Mandatory IF CSIP 2/1 "Profile supported over BR/EDR", otherwise
  Excluded.
- C.3: Mandatory to support at least one.
- C.4: Excluded IF CSIP 3/1 "CSIP v1.0", otherwise Optional.
- C.5: Optional IF CSIP 5/9 "Coordinated Set Name Characteristic" AND CSIP
  2/2 "Profile supported over LE", otherwise Excluded.
- C.6: Optional IF CSIP 5/9 "Coordinated Set Name Characteristic" AND CSIP
  2/1 "Profile supported over BR/EDR", otherwise Excluded.
- C.7: Optional IF CSIP 5/7 "Coordinated Set Size Characteristic", otherwise
  not defined.
- C.8: Optional IF CSIP 5/9 "Coordinated Set Name Characteristic", otherwise
  not defined.


**Table 6: GAP Requirements (Set Member)**

Prerequisite: CSIP 1/1 "Set Member"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_6_1    |          | LE security mode 1 (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_2    |          | Peripheral (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_3    |          | Bondable mode (LE) (C.7)                     |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_4    |          | Privacy feature (C.7)                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_5    |          | Bondable mode (BR/EDR) (C.8)                 |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_6    |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (C.5)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_7    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (C.5)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_8    |          | LE security mode 1 level 4 (C.5)             |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_9    |          | Minimum 128 Bit entropy key (LE) (C.6)       |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_10   |          | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.9)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_11   |          | Security mode 4, level 2 (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_12   |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_13   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.10)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_14   |          | BR/EDR Secure Connections (C.10)             |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_15   |          | LE Secure Connections (Peripheral) (C.9)     |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_16   |          | Out of Band (Peripheral) (C.9)               |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_6_17   |          | Out-of-Band (BR/EDR) (C.10)                  |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF CSIP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.2: Mandatory IF CSIP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.5: Mandatory to support at least one IF CSIP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.6: Mandatory IF CSIP 6/6 "Unauthenticated Pairing (LE security mode 1
  level 2) with LE Secure Connections Pairing only" OR CSIP 6/7
  "Authenticated Pairing (LE security mode 1 level 3) with LE Secure
  Connections Pairing only", otherwise not defined.
- C.7: Optional IF CSIP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.8: Optional IF CSIP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.9: Mandatory to support at least one IF CSIP 2/2 "Profile supported over
  LE", otherwise not defined.
- C.10: Mandatory to support at least one IF CSIP 2/1 "Profile supported over
  BR/EDR", otherwise not defined.

Set Coordinator role
====================

**Table 8: Set Coordinator, X.Y Versions**

Prerequisite: CSIP 1/2 "Set Coordinator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_8_1    |          | CSIP v1.0 (C.1, C.2)                         |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_8_2    | x        | CSIP v1.1 (C.1)                              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support one and only one.
- C.2: Can only be supported with an active X.Y.Z version after Deprecation
  or Withdrawal.
  Deprecated 2025-02-01. Withdrawn 2027-02-01.

**Table 9: Set Coordinator, X.Y.Z Versions**

Prerequisite: CSIP 1/2 "Set Coordinator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_9_2    |          | CSIP v1.0.1 (C.1)
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF CSIP 8/1 "CSIP v1.0", otherwise Excluded.

**Table 10: Service Support**

Prerequisite: CSIP 1/2 "Set Coordinator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_10_1   | x        | Discover Coordinated Set Identification      |
|                  |          | Service (M)                                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 11: Characteristic Support Requirements**

Prerequisite: CSIP 10/1 "Discover Coordinated Set Identification Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_11_1   | x        | Set Identity Resolving Key Characteristic (M)|
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_11_2   | x        | Coordinated Set Size Characteristic (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_11_3   | x        | Set Member Lock Characteristic (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_11_4   | x        | Set Member Rank Characteristic (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_11_5   |          | Coordinated Set Name Characteristic (C.1)    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Excluded IF CSIP 8/1 "CSIP v1.0 ", otherwise Optional.

**Table 12: Procedure Support Requirements**

Prerequisite: CSIP 10/1 "Discover Coordinated Set Identification Service"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_12_1   | x        | Coordinated Set Discovery (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_12_2   | x        | Set Members Discovery (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_12_3   | x        | Lock Request (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_12_4   | x        | Lock Release (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_12_5   | x        | Ordered Access (M)                           |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 13: Set Coordinator GATT Requirements**

Prerequisite: CSIP 1/2 "Set Coordinator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_13_1   | x        | Discover All Primary Services (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_2   | x        | Discover Primary Service by Service UUID     |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_3   | x        | Find Included Services (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_4   | x        | Discover All Characteristics of a Service    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_5   | x        | Discover Characteristics by UUID (C.2)       |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_6   | x        | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_7   | x        | Read Characteristic Value (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_8   | x        | Write Characteristic Value (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_9   |          | Single Notification (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_10  | x        | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_11  |          | Write Characteristic Descriptor (C.3)        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_12  | x        | GATT Client over LE (C.4)                    |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_13  |          | GATT Client over BR/EDR (C.5)                |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_14  |          | Exchange MTU (C.6)                           |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_13_15  |          | Read Long Characteristic Value (C.6)         |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one.
- C.2: Mandatory to support at least one.
- C.3: Mandatory IF CSIP 13/9 "Single Notification", otherwise not defined.
- C.4: Mandatory IF CSIP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.5: Mandatory IF CSIP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.6: Mandatory IF CSIP 11/5 "Coordinated Set Name Characteristic",
  otherwise not defined.

**Table 14: GAP Requirements (Set Coordinator)**

Prerequisite: CSIP 1/2 "Set Coordinator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_CSIP_14_1   |          | Bondable mode (BR/EDR) (C.1)                 |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_2   | x        | Central (C.2)                                |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_3   | x        | LE security mode 1 (C.2)                     |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_4   |          | dable mode (LE) (C.4)                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_5   |          | Bonding procedure (C.4)                      |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_6   |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (C.4)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_7   |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (C.4)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_8   |          | LE security mode 1 level 4 (C.4)             |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_9   |          | Minimum 128 Bit entropy key (LE) (C.7)       |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_10  | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_11  |          | Security mode 4, level 2 (C.3)               |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_12  |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_13  |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.9)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_14  |          | BR/EDR Secure Connections (C.9)              |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_15  | x        | LE Secure Connections (Central) (C.8)        |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_16  |          | Out of Band (Central) (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_CSIP_14_17  |          | Out-of-Band (BR/EDR) (C.9)                   |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF CSIP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.2: Mandatory IF CSIP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.3: Mandatory IF CSIP 2/1 "Profile supported over BR/EDR", otherwise not
  defined.
- C.4: Optional IF CSIP 2/2 "Profile supported over LE", otherwise not
  defined.
- C.7: Mandatory IF CSIP 14/6 "Unauthenticated Pairing (LE security mode 1
  level 2) with LE Secure Connections Pairing only" OR CSIP 14/7
  "Authenticated Pairing (LE security mode 1 level 3) with LE Secure
  Connections Pairing only", otherwise not defined.
- C.8: Mandatory to support at least one IF CSIP 2/2 "Profile supported
  over LE", otherwise not defined.
- C.9: Mandatory to support at least one IF CSIP 2/1 "Profile supported
  over BR/EDR", otherwise not defined.

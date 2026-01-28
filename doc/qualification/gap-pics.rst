.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

======================
Generic Access Profile
======================
(TCRL 2023-1, GAP.ICS.p40)

Device and version configuration
================================
**Table 0: Device Configuration**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_0_1     |          | BR/EDR (C.1)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_0_2     |          | LE (C.2)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_0_3     | x        | BR/EDR/LE (C.3)                              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF SUM ICS 32/3 "Generic Access Profile (BR/EDR)" AND
  NOT SUM ICS 34/2 "Generic Access Profile (LE)", otherwise Excluded.
- C.2: Mandatory IF SUM ICS 34/2 "Generic Access Profile (LE)" AND
  NOT SUM ICS 32/3 "Generic Access Profile (BR/EDR)", otherwise Excluded.
- C.3: Mandatory IF SUM ICS 32/3 "Generic Access Profile (BR/EDR)" AND
  SUM ICS 34/2 "Generic Access Profile (LE)", otherwise Excluded.

BR/EDR Capability Statement
===========================
**Table 1: Modes**

Prerequisite: GAP 0/1 "BR/EDR" OR GAP 0/3 "BR/EDR/LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_1_1     | x        | Non-discoverable mode (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_1_2     | x        | Limited discoverable mode (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_1_3     | x        | General discoverable mode (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_1_4     | x        | Non-connectable mode (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_1_5     | x        | Connectable mode (M)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_1_6     |          | Non-bondable mode (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_1_7     | x        | Bondable mode (C.2)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_1_8     |          | Non-synchronizable mode (C.3)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_1_9     |          | Synchronizable mode (C.3)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF GAP 1/2 "Limited discoverable mode", otherwise Optional.
- C.2: Mandatory IF GAP 3/5 "Initiation of general bonding", otherwise
  Optional.
- C.3: Optional IF BB 3a/1 "Connectionless Peripheral Broadcast Transmitter",
  otherwise Excluded.

BR/EDR Capability Statement
===========================
**Table 2: Security Aspects**

Prerequisite: GAP 0/1 "BR/EDR" OR GAP 0/3 "BR/EDR/LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_2_1     |          | Authentication procedure (C.1)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_2     | x        | Support of LMP-Authentication (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_3     | x        | Initiate LMP-Authentication (C.5)            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_4     |          | Security mode 1 (C.7)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_5     |          | Security mode 2 (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_6     |          | Security mode 3 (C.7)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_7     | x        | Security mode 4 (M)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_7a    |          | Security mode 4, level 4 (C.9)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_7b    |          | Security mode 4, level 3 (C.9)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_7c    |          | Security mode 4, level 2 (C.9)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_7d    |          | Security mode 4, level 1 (C.9)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_8     | x        | Authenticated link key (C.6)                 |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_9     | x        | Unauthenticated link key (C.6)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_10    | x        | Security Optional (C.6)                      |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_11    | x        | Secure Connections Only Mode (C.8)           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_12    |          | 56-bit minimum encryption key size (C.10)    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_2_13    |          | 128-bit encryption key size capable (C.11)   |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF GAP 2/5 "Security mode 2" OR GAP 2/6 "Security mode 3",
  otherwise Optional.
- C.5: Mandatory IF GAP 2/5 "Security mode 2" OR GAP 2/6 "Security mode 3" OR
  GAP 2/7 "Security mode 4", otherwise Optional.
- C.6: Mandatory to support at least one IF GAP 2/7 "Security mode 4",
  otherwise Excluded.
- C.7: Excluded. Note 2: A Core 2.1 or later is required to support security
  mode 4. Security mode 2 is used only for backward compatibility purposes
  with Core 2.0 and earlier devices. Security mode 1 and security mode 3 are
  excluded for Core 2.1 or later devices
- C.8: Mandatory IF GAP 25/10 "Secure Connections Only mode" OR
  GAP 35/10 "Secure Connections Only mode", otherwise Optional IF LMP 2/26
  "Secure Connections (Controller Support)" AND GAP 2/7a "Security mode 4,
  level 4", otherwise Excluded.
- C.9: Optional IF GAP 2/7 "Security mode 4", otherwise Excluded.
- C.10: Optional IF GAP 2/7d "Security mode 4, level 1" OR
  GAP 2/7c "Security mode 4, level 2" OR GAP 2/7b "Security mode 4, level 3",
  otherwise Excluded.
- C.11: Mandatory IF GAP 2/7a "Security mode 4, level 4", otherwise Optional
  IF GAP 2/7d "Security mode 4, level 1" OR GAP 2/7c "Security mode 4, level
  2" OR GAP 2/7b "Security mode 4, level 3", otherwise Excluded.

BR/EDR Capability Statement
===========================
**Table 3: Idle Mode Procedures**

Prerequisite: GAP 0/1 "BR/EDR" OR GAP 0/3 "BR/EDR/LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_3_1     | x        | Initiation of general inquiry (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_3_2     | x        | Initiation of limited inquiry (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_3_3     | x        | Initiation of name discovery (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_3_4     | x        | Initiation of device discovery (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_3_5     | x        | Initiation of general bonding (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_3_6     | x        | Initiation of dedicated bonding (O)          |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory to support at least one IF GAP 3/5 "Initiation of general
  bonding", otherwise Optional.

BR/EDR Capability Statement
===========================
**Table 4: Establishment Procedures**

Prerequisite: GAP 0/1 "BR/EDR" OR GAP 0/3 "BR/EDR/LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_4_1     | x        | Link Establishment as initiator (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_4_2     | x        | Link Establishment as acceptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_4_3     | x        | Channel Establishment as initiator (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_4_4     | x        | Channel Establishment as acceptor (M)        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_4_5     | x        | Connection Establishment as initiator (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_4_6     | x        | Connection Establishment as acceptor (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_4_7     |          | Synchronization Establishment as receiver    |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF BB 3a/2 "Connectionless Peripheral Broadcast Receiver",
  otherwise Excluded.

LE Capability Statement
=======================
**Table 5: LE Roles**

Prerequisite: GAP 0/2 "LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_5_1     |          | Broadcaster (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_5_2     |          | Observer (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_5_3     |          | Peripheral (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_5_4     |          | Central (C.1)                                |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

LE Capability Statement
=======================
**Table 6: Broadcaster Physical Layer**

Prerequisite: GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_6_1     | x        | Transmitter (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_6_2     | x        | Receiver (O)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

LE Capability Statement
=======================
**Table 7: Broadcaster Link Layer States**

Prerequisite: GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_7_1     | x        | Standby state (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_7_2     | x        | Advertising state (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_7_3     |          | Isochronous Broadcasting State (C.1)         |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1",
  otherwise Optional.

LE Capability Statement
=======================
**Table 8: Broadcaster Link Layer Advertising Event Types**

Prerequisite: GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_8_1     | x        | Non-connectable and non-scannable undirected |
|                  |          | event (M)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8_2     | x        | Scannable undirected event (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8_3     |          | Non-connectable and non-scannable directed   |
|                  |          | event (C.1)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8_4     |          | Scannable directed event (C.1)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS",
  otherwise Optional.

LE Capability Statement
=======================
**Table 8a: Broadcaster Link Layer Advertising Data Types**

Prerequisite: GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_8a_1    | x        | Service UUID (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_2    | x        | Local Name (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_3    | x        | Flags (O)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_4    | x        | Manufacturer Specific Data (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_5    | x        | TX Power Level (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_6    |          | Security Manager OOB (C.1)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_7    |          | Security Manager TK Value (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_8    |          | Peripheral Connection Interval Range (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_9    |          | Service Solicitation (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_10   |          | Service Data (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_11   | x        | Appearance (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_12   |          | Public Target Address (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_13   |          | Random Target Address (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_14   |          | Advertising Interval (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_14a  |          | Advertising Interval - Long (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_15   |          | LE Bluetooth Device Address (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_16   |          | LE Role (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_17   |          | Uniform Resource Identifier (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_18   |          | LE Supported features (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_19   |          | Encrypted Data (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_8a_20   |          | Periodic Advertising Response Timing (O)     |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF SM 2/4 "OOB supported", otherwise Excluded.

LE Capability Statement
=======================
**Table 9: Broadcaster Connection Modes and Procedures**

Prerequisite: GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_9_1     | x        | Non-connectable mode (M)                     |
+------------------+----------+----------------------------------------------+

- M: Mandatory

LE Capability Statement
=======================
**Table 10: Broadcaster Broadcasting and Observing Features**

Prerequisite: GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_10_1    | x        | Broadcast mode (M)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_10_2    |          | Broadcast Isochronous Synchronizability mode |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_10_3    |          | Broadcast Isochronous Broadcasting mode (C.2)|
+------------------+----------+----------------------------------------------+
| TSPC_GAP_10_4    |          | Broadcast Isochronous Terminate procedure    |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_10_5    |          | Broadcast Isochronous Channel Map Update     |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF GAP 10/3 "Broadcast Isochronous Broadcasting mode",
  otherwise Excluded.
- C.2: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1",
  otherwise Optional.

LE Capability Statement
=======================
**Table 11: Broadcaster Privacy Feature**

Prerequisite: GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_11_1    |          | Privacy feature (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11_2    | x        | Resolvable private address generation        |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11_3    | x        | Non-resolvable private address generation    |
|                  |          | procedure (C.2)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11_4    |          | Resolvable private address resolution        |
|                  |          | procedure (O)                                |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF GAP 11/1 "Privacy feature" AND NOT GAP 11/3
  "Non-resolvable private address generation procedure", otherwise Optional.
- C.2: Mandatory IF GAP 11/1 "Privacy feature" AND NOT GAP 11/2
  "Resolvable private address generation procedure", otherwise Optional.

LE Capability Statement
=======================
**Table 11a: Periodic Advertising Modes and Procedures**

Prerequisite: (GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster
(BR/EDR/LE)") AND NOT (SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18
"Core v4.2+HS")

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_11a/1   |          | Periodic Advertising Synchronizability mode  |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11a/2   |          | Periodic Advertising mode (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11a/3   |          | Periodic Advertising with Responses (C.3)    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11a/4   |          | Periodic Advertising Connection (C.4)        |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF LL 3/10 "Periodic Advertising", otherwise Excluded.
- C.2: Mandatory IF GAP 11a/1 "Periodic Advertising Synchronizability mode",
  otherwise Excluded.
- C.3: Mandatory IF LL 3/10a "Periodic Advertising with Responses",
  otherwise Excluded.
- C.4: Optional IF GAP 11a/3 "Periodic Advertising with Responses",
  otherwise Excluded.

LE Capability Statement
=======================
**Table 11b: Broadcaster Security Aspects Features**

Prerequisite: GAP 5/1 "Broadcaster (LE)" OR GAP 38/1 "Broadcaster (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_11b_1   |          | LE security mode 3 (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11b_2   |          | LE security mode 3 level 1 (C.2)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11b_3   |          | LE security mode 3 level 2 (C.2)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_11b_4   |          | LE security mode 3 level 3 (C.2)             |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF GAP 10/2 "Broadcast Isochronous Synchronizability mode",
  otherwise Excluded.
- C.2: Mandatory to support at least one IF GAP 11b/1 "LE security mode 3",
  otherwise Excluded.

LE Capability Statement
=======================
**Table 12: Observer Physical Layer**

Prerequisite: GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_12_1    | x        | Receiver (M)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_12_2    | x        | Transmitter (O)                              |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

LE Capability Statement
=======================
**Table 13: Observer Link Layer States**

Prerequisite: GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_13_1    | x        | Standby state (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_13_2    | x        | Scanning state (M)                           |
+------------------+----------+----------------------------------------------+

- M: Mandatory

LE Capability Statement
=======================
**Table 14: Observer Link Layer Scanning Types**

Prerequisite: GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_14_1    | x        | Passive scanning (M)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14_2    | x        | Active scanning (O)                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

LE Capability Statement
=======================
**Table 14a: Observer Link Layer Scanning Data Types**

Prerequisite: GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_14a_1   |          | Service UUID (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_2   |          | Local Name (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_3   |          | Flags (O)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_4   |          | Manufacturer Specific Data (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_5   |          | TX Power Level (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_6   |          | Security Manager OOB (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_7   |          | Security Manager TK Value (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_8   |          | Peripheral Connection Interval Range (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_9   |          | Service Solicitation (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_10  |          | Service Data (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_11  |          | Appearance (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_12  |          | Public Target Address (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_13  |          | Random Target Address (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_14  |          | Advertising Interval (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_14a |          | Advertising Interval - Long (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_15  |          | LE Bluetooth Device Address (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_16  |          | LE Role (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_17  |          | Uniform Resource Identifier (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_18  |          | LE Supported features (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_19  |          | Encrypted Data (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_14a_20  |          | Periodic Advertising Response Timing (O)     |
+------------------+----------+----------------------------------------------+

- O: Optional

LE Capability Statement
=======================
**Table 15: Observer Connection Modes and Procedures**

Prerequisite: GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_15_1    | x        | Non-connectable mode (M)                     |
+------------------+----------+----------------------------------------------+

- M: Mandatory

LE Capability Statement
=======================
**Table 16: Observer Broadcasting and Observing Features**

Prerequisite: GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_16_1    | x        | Observation procedure (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_16_2    |          | Broadcast Isochronous Synchronization        |
|                  |          | Establishment procedure (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_16_3    |          | Broadcast Isochronous Termination procedure  |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_16_4    |          | Broadcast Isochronous Channel Map Update     |
|                  |          | procedure (C.2)                              |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1",
  otherwise Optional.
- C.2: Mandatory IF GAP 16/2 "Broadcast Isochronous Synchronization
  Establishment procedure", otherwise Excluded.

LE Capability Statement
=======================
**Table 17: Observer Privacy Feature**

Prerequisite: GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_17_1    |          | Privacy feature (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_17_2    | x        | Non-resolvable private address generation    |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_17_3    | x        | Resolvable private address resolution        |
|                  |          | procedure (O)                                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_17_4    | x        | Resolvable private address generation        |
|                  |          | procedure (C.2)                              |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF GAP 17/1 "Privacy feature" AND GAP 14/2 "Active scanning"
  AND NOT GAP 17/4 "Resolvable private address generation procedure",
  otherwise Optional.
- C.2: Mandatory IF GAP 17/1 "Privacy feature" AND GAP 14/2 "Active scanning"
  AND NOT GAP 17/2 "Non-resolvable private address generation procedure",
  otherwise Optional.

LE Capability Statement
=======================
**Table 17a: Periodic Advertising Modes and Procedures**

Prerequisite: (GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)") AND
NOT (SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS")

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_17a_1   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure without listening for|
|                  |          | periodic advertising (C.2)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_17a_2   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure with listening for   |
|                  |          | periodic advertising (C.1)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_17a_3   |          | Periodic Advertising Connection (C.3)        |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF LL 4/8 "Scanning for Periodic Advertising", otherwise
  Excluded.
- C.2: Optional IF LL 11/1 "Synchronizing to Periodic Advertising", otherwise
  Excluded.
- C.3: Optional IF LL 4/8a "Scanning for Periodic Advertising with Responses",
  otherwise Excluded.

LE Capability Statement
=======================
**Table 17b: Observer Security Aspects Features**

Prerequisite: GAP 5/2 "Observer (LE)" OR GAP 38/2 "Observer (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_17b_1   |          | LE security mode 3 (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_17b_2   |          | LE security mode 3 level 1 (C.2)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_17b_3   |          | LE security mode 3 level 2 (C.2)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_17b_4   |          | LE security mode 3 level 3 (C.2)             |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF GAP 16/2 "Broadcast Isochronous Synchronization
  Establishment procedure", otherwise Excluded.
- C.2: Mandatory to support at least one IF GAP 17b/1 "LE security mode 3",
  otherwise Excluded.

LE Capability Statement
=======================
**Table 18: Peripheral Physical Layer**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_18_1    | x        | Transmitter (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_18_2    | x        | Receiver (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory

LE Capability Statement
=======================
**Table 19: Peripheral Link Layer States**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_19_1    | x        | Standby state (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_19_2    | x        | Advertising state (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_19_3    | x        | Connection state, Peripheral role (M)        |
+------------------+----------+----------------------------------------------+

- M: Mandatory

LE Capability Statement
=======================
**Table 20: Peripheral Link Layer Advertising Event Types**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_20_1    | x        | Connectable and scannable undirected event   |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20_2    | x        | Connectable directed event (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20_3    | x        | Non-connectable and non-scannable undirected |
|                  |          | event (O)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20_4    | x        | Scannable undirected event (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20_5    | x        | Connectable undirected event (C.1)           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20_6    |          | Non-connectable and non-scannable directed   |
|                  |          | event (C.1)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20_7    |          | Scannable directed event (C.1)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS",
  otherwise Optional.

LE Capability Statement
=======================
**Table 20A: Peripheral Link Layer Advertising Data Types**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_20A_1   |          | Service UUID (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_2   | x        | Local Name (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_3   | x        | Flags (C.2)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_4   | x        | Manufacturer Specific Data (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_5   | x        | TX Power Level (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_6   |          | Security Manager OOB (C.3)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_7   |          | Security Manager TK Value (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_8   |          | Peripheral Connection Interval Range (C.1)   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_9   |          | Service Solicitation (C.1)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_10  |          | Service Data (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_11  | x        | Appearance (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_12  |          | Public Target Address (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_13  |          | Random Target Address (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_14  |          | Advertising Interval (C.1)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_14a |          | Advertising Interval - Long (C.1)            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_15  |          | LE Bluetooth Device Address (C.1)            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_16  |          | LE Role (C.1)                                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_17  |          | Uniform Resource Identifier (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_18  |          | LE Supported features (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_19  |          | Encrypted Data (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_20A_20  |          | Periodic Advertising Response Timing (C.4)   |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF GAP 20/1 "Connectable and scannable undirected event" OR
  GAP 20/3 "Non-connectable and non-scannable undirected event" OR GAP 20/4
  "Scannable undirected event", otherwise Excluded.
- C.2: Mandatory IF GAP 22/2 "Limited discoverable mode" OR GAP 22/3 "General
  discoverable mode", otherwise Optional.
- C.3: Optional IF (GAP 20/1 "Connectable and scannable undirected event" OR
  GAP 20/3 "Non-connectable and non-scannable undirected event" OR GAP 20/4
  "Scannable undirected event") AND SM 2/4 "OOB supported", otherwise
  Excluded.
- C.4: Mandatory IF LL 3/10a "Periodic Advertising with Responses",
  otherwise Excluded.

LE Capability Statement
=======================
**Table 21: Peripheral Link Layer Control Procedures**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_21_1    | x        | Connection Update procedure (M)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_2    | x        | Channel Map Update procedure (M)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_3    | x        | Encryption procedure (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_4    | x        | Central-initiated Feature Exchange procedure |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_5    | x        | Version Exchange procedure (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_6    | x        | Termination procedure (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_7    |          | LE Ping procedure (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_8    | x        | Peripheral-initiated Feature Exchange        |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_9    | x        | Connection Parameter Request procedure (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_10   |          | Data Length Update procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_11   |          | PHY Update procedure (C.2)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_21_12   |          | Minimum Number Of Used Channels procedure    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF GAP 21/9 "Connection Parameter Request procedure",
  otherwise Optional.
- C.2: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS",
  otherwise Optional.

LE Capability Statement
=======================
**Table 22: Peripheral Discovery Modes and Procedures**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_22_1    | x        | Non-discoverable mode (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_22_2    | x        | Limited discoverable mode (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_22_3    | x        | General discoverable mode (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_22_4    | x        | Name discovery procedure (O)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF NOT GAP 22/2 "Limited discoverable mode", otherwise
  Optional.

LE Capability Statement
=======================
**Table 23: Peripheral Connection Modes and Procedures**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_23_1    | x        | Non-connectable mode (M)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_23_2    |          | Directed connectable mode (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_23_3    | x        | Undirected connectable mode (M)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_23_4    |          | Connection parameter update procedure (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_23_5    | x        | Terminate connection procedure (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_23_6    |          | Connected Isochronous Stream Peripheral      |
|                  |          | Establishment procedure (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_23_7    |          | Connected Isochronous Stream Terminate       |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_23_8    |          | Connection Subrate procedure (C.2)           |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF LL 9/32 "Connected Isochronous Stream Peripheral",
  otherwise Excluded.
- C.2: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1" OR SUM ICS 31/21
  "Core v5.2", otherwise Optional.

LE Capability Statement
=======================
**Table 24: Peripheral Bonding Modes and Procedures**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_24_1    | x        | Non-bondable mode (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_24_2    | x        | Bondable mode (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_24_3    | x        | Bonding procedure (C.2)                      |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_24_4    | x        | Multiple Bonds (C.1)                         |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF GAP 24/2 "Bondable mode", otherwise Excluded.
- C.2: Mandatory IF GAP 24/2 "Bondable mode", otherwise Excluded.

LE Capability Statement
=======================
**Table 25: Peripheral Security Aspects Features**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_25_1    | x        | LE security mode 1 (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_2    | x        | LE security mode 2 (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_3    | x        | Authentication procedure (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_4    | x        | Authorization procedure (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_5    | x        | Connection data signing procedure (C.6)      |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_6    | x        | Authenticate signed data procedure (C.6)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_7    | x        | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_8    | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_9    | x        | LE security mode 1 level 4 (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_10   | x        | Secure Connections Only mode (C.4)           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_11   |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_12   |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_13   | x        | Minimum 128 Bit entropy key (C.5)            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_25_14   | x        | Client security checks for GATT indications  |
|                  |          | and notifications (C.7)                      |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF GAP 25/1 "LE security mode 1", otherwise Excluded.
- C.4: Mandatory IF GAP 2/11 "Secure Connections Only Mode" OR GAP 35/10
  "Secure Connections Only mode", otherwise Optional IF GAP 25/9 "LE security
  mode 1 level 4", otherwise Excluded.
- C.5: Mandatory IF GAP 25/9 "LE security mode 1 level 4", otherwise Optional
  IF GAP 25/11 "Unauthenticated Pairing (LE security mode 1 level 2) with LE
  Secure Connections Pairing only" OR GAP 25/12 "Authenticated Pairing (LE
  security mode 1 level 3) with LE Secure Connections Pairing only",
  otherwise Excluded.
- C.6: Mandatory to support at least one IF GAP 25/2 "LE security mode 2",
  otherwise Optional.
- C.7: Optional IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1" OR SUM ICS 31/21
  "Core v5.2", otherwise Mandatory.

LE Capability Statement
=======================
**Table 26: Peripheral Privacy Feature**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_26_1    |          | Privacy feature (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_26_2    | x        | Non-resolvable private address generation    |
|                  |          | procedure (O)                                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_26_3    | x        | Resolvable private address generation        |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_26_4    | x        | Resolvable private address resolution        |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF GAP 26/1 "Privacy feature", otherwise Optional.

LE Capability Statement
=======================
**Table 27: Peripheral GAP Characteristics**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_27_1    | x        | Device Name (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27_2    | x        | Appearance (M)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27_5    |          | Peripheral Preferred Connection Parameters   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27_6    |          | Writable Device Name (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27_7    |          | Writable Appearance (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27_9    |          | Central Address Resolution (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27_10   |          | Encrypted Data Key Material (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27_11   |          | LE GATT Security Levels (O)                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF LL 2/5 "Resolution of private addresses", otherwise
  Excluded.

LE Capability Statement
=======================
**Table 27a: Periodic Advertising Modes and Procedures**

Prerequisite: (GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)")
AND NOT (SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS" OR SUM ICS
31/19 "Core v5.0")

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_27a_1   |          | Periodic Advertising Synchronization Transfer|
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27a_2   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | without listening for periodic advertising   |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27a_3   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | with listening for periodic advertising      |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF LL 9/26 "Periodic Advertising Sync Transfer: Sender",
  otherwise Excluded.
- C.2: Optional IF LL 9/27 "Periodic Advertising Sync Transfer: Recipient",
  otherwise Excluded.
- C.3: Optional IF LL 11/1 "Synchronizing to Periodic Advertising" AND LL 9/27
  "Periodic Advertising Sync Transfer: Recipient", otherwise Excluded.

LE Capability Statement
=======================
**Table 27b: SM Requirements**

Prerequisite: GAP 5/3 "Peripheral (LE)" OR GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_27b_1   | x        | Peripheral Role (Responder) (M)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27b_2   | x        | Authenticated MITM protection (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27b_3   | x        | Unauthenticated no MITM protection (C.2)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27b_4   |          | No security requirements (C.3)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27b_5   | x        | LE Secure Connections (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27b_6   | x        | Encryption Key (C.5)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27b_7   | x        | Identity Key (C.6)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_27b_8   | x        | Signing Key (C.7)                            |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF GAP 25/7 "Authenticated Pairing (LE security mode 1 level
  3)" OR GAP 25/12 "Authenticated Pairing (LE security mode 1 level 3) with LE
  Secure Connections Pairing only" OR (GAP 25/2 "LE security mode 2" AND GAP
  25/3 "Authentication procedure"), otherwise not defined.
- C.2: Mandatory IF GAP 25/8 "Unauthenticated Pairing (LE security mode 1
  level 2)" OR GAP 25/11 "Unauthenticated Pairing (LE security mode 1 level 2)
  with LE Secure Connections Pairing only" OR (GAP 25/2 "LE security mode 2"
  AND NOT GAP 25/3 "Authentication procedure"), otherwise not defined.
- C.3: Mandatory IF GAP 25/1 "LE security mode 1" AND NOT GAP 25/8
  "Unauthenticated Pairing (LE security mode 1 level 2)" AND NOT GAP 25/7
  "Authenticated Pairing (LE security mode 1 level 3)", otherwise not defined.
- C.4: Mandatory IF GAP 25/9 "LE security mode 1 level 4" OR GAP 25/11
  "Unauthenticated Pairing (LE security mode 1 level 2) with LE Secure
  Connections Pairing only" OR GAP 25/12 "Authenticated Pairing (LE security
  mode 1 level 3) with LE Secure Connections Pairing only", otherwise not
  defined.
- C.5: Mandatory IF GAP 24/2 "Bondable mode", otherwise not defined.
- C.6: Mandatory IF GAP 26/3 "Resolvable private address generation
  procedure", otherwise not defined.
- C.7: Mandatory IF GAP 25/6 "Authenticate signed data procedure", otherwise
  not defined.

LE Capability Statement
=======================
**Table 28: Central Physical Layer**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_28_1    | x        | Transmitter (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_28_2    | x        | Receiver (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory

LE Capability Statement
=======================
**Table 29: Central Link Layer States**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_29_1    | x        | Standby state (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_29_2    | x        | Scanning state (M)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_29_3    | x        | Initiating state (M)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_29_4    | x        | Connection state, Central role (M)           |
+------------------+----------+----------------------------------------------+

- M: Mandatory

LE Capability Statement
=======================
**Table 30: Central Link Layer Scanning Types**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_30_1    | x        | Passive scanning (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30_2    | x        | Active scanning (C.1)                        |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF NOT GAP 30/1 "Passive scanning", otherwise Optional.

LE Capability Statement
=======================
**Table 30a: Central Link Layer Scanning Data Types**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_30a_1   |          | Service UUID (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_2   |          | Local Name (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_3   |          | Flags (O)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_4   |          | Manufacturer Specific Data (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_5   |          | TX Power Level (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_6   |          | Security Manager OOB (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_7   |          | Security Manager TK Value (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_8   |          | Peripheral Connection Interval Range (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_9   |          | Service Solicitation (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_10  |          | Service Data (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_11  |          | Appearance (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_12  |          | Public Target Address (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_13  |          | Random Target Address (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_14  |          | Advertising Interval (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_14a |          | Advertising Interval - Long (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_15  |          | LE Bluetooth Device Address (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_16  |          | LE Role (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_17  |          | Uniform Resource Identifier (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_18  |          | LE Supported features (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_19  |          | Encrypted Data (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_30a_20  |          | Periodic Advertising Response Timing (O)     |
+------------------+----------+----------------------------------------------+

- O: Optional

LE Capability Statement
=======================
**Table 31: Central Link Layer Control Procedures**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_31_1    | x        | Connection Update procedure (M)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_2    | x        | Channel Map Update procedure (M)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_3    | x        | Encryption procedure (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_4    | x        | Central-initiated Feature Exchange procedure |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_5    | x        | Version Exchange procedure (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_6    | x        | Termination procedure (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_7    |          | LE Ping procedure (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_8    | x        | Peripheral-initiated Feature Exchange        |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_9    | x        | Connection Parameter Request procedure (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_10   |          | Data Length Update procedure (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_11   |          | PHY Update procedure (C.2)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_31_12   |          | Minimum Number Of Used Channels procedure    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF GAP 31/9 "Connection Parameter Request procedure",
  otherwise Optional.
- C.2: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS",
  otherwise Optional.

LE Capability Statement
=======================
**Table 32: Central Discovery Modes and Procedures**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_32_1    | x        | Limited Discovery procedure (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_32_2    | x        | General Discovery procedure (M)              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_32_3    | x        | Name Discovery procedure (O)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

LE Capability Statement
=======================
**Table 33: Central Connection Modes and Procedures**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_33_1    | x        | Auto connection establishment procedure (O)  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_33_2    | x        | General connection establishment procedure   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_33_3    | x        | Selective connection establishment procedure |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_33_4    | x        | Direct connection establishment procedure (M)|
+------------------+----------+----------------------------------------------+
| TSPC_GAP_33_5    | x        | Connection parameter update procedure (M)    |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_33_6    | x        | Terminate connection procedure (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_33_7    |          | Connected Isochronous Stream Central         |
|                  |          | Establishment procedure (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_33_8    |          | Connected Isochronous Stream Terminate       |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_33_9    |          | Connection Subrate procedure (C.2)           |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF LL 9/31 "Connected Isochronous Stream Central",
  otherwise Excluded.
- C.2: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1" OR SUM ICS 31/21
  "Core v5.2", otherwise Optional.

LE Capability Statement
=======================
**Table 34: Central Bonding Modes and Procedures**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_34_1    | x        | Non-bondable mode (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_34_2    | x        | Bondable mode (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_34_3    | x        | Bonding procedure (C.1)                      |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF GAP 34/2 "Bondable mode", otherwise Excluded.

LE Capability Statement
=======================
**Table 35: Central Security Features**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_35_1    | x        | LE security mode 1 (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_2    | x        | LE security mode 2 (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_3    | x        | Authentication procedure (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_4    |          | Authorization procedure (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_5    |          | Connection data signing procedure (O)        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_6    |          | Authenticate signed data procedure (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_7    | x        | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_8    | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_9    | x        | LE security mode 1 level 4 (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_10   | x        | Secure Connections Only mode (C.3)           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_11   |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_12   |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_13   | x        | Minimum 128 Bit entropy key (C.4)            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_14   |          | Encrypted Advertising Data Procedure (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_35_15   | x        | Client security checks for GATT indications  |
|                  |          | and notifications (C.5)                      |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF GAP 35/1 "LE security mode 1", otherwise Excluded.
- C.3: Mandatory IF GAP 2/11 "Secure Connections Only Mode" OR GAP 25/10
  "Secure Connections Only mode", otherwise Optional IF GAP 35/9 "LE security
  mode 1 level 4", otherwise Excluded.
- C.4: Mandatory IF GAP 35/9 "LE security mode 1 level 4", otherwise Optional
  IF GAP 35/11 "Unauthenticated Pairing (LE security mode 1 level 2) with LE
  Secure Connections Pairing only" OR GAP 35/12 "Authenticated Pairing (LE
  security mode 1 level 3) with LE Secure Connections Pairing only", otherwise
  Excluded.
- C.5: Optional IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1" OR SUM ICS 31/21
  "Core v5.2", otherwise Mandatory.

LE Capability Statement
=======================
**Table 36: Central Privacy Feature**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_36_1    |          | Privacy feature (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_36_2    | x        | Non-resolvable private address generation    |
|                  |          | procedure (O)                                |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_36_3    | x        | Resolvable private address resolution        |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_36_5    | x        | Resolvable private address generation        |
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF GAP 36/1 "Privacy feature", otherwise Optional.

LE Capability Statement
=======================
**Table 37: Central GAP Characteristics**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_37_1    | x        | Device Name (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37_2    | x        | Appearance (M)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37_3    |          | Central Address Resolution (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37_4    |          | LE GATT Security Levels (O)                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF LL 2/5 "Resolution of private addresses", otherwise
  Excluded.

LE Capability Statement
=======================
**Table 37a: Periodic Advertising Modes and Procedures**

Prerequisite: (GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)") AND
NOT (SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS" OR SUM ICS
31/19 "Core v5.0")

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_37a_1   |          | Periodic Advertising Synchronization Transfer|
|                  |          | procedure (C.1)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37a_2   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | without listening for periodic advertising   |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37a_3   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | with listening for periodic advertising (C.3)|
+------------------+----------+----------------------------------------------+

- C.1: Optional IF LL 9/26 "Periodic Advertising Sync Transfer: Sender",
  otherwise Excluded.
- C.2: Optional IF LL 9/27 "Periodic Advertising Sync Transfer: Recipient",
  otherwise Excluded.
- C.3: Optional IF LL 11/1 "Synchronizing to Periodic Advertising" AND LL 9/27
  "Periodic Advertising Sync Transfer: Recipient", otherwise Excluded.

LE Capability Statement
=======================
**Table 37b: SM Requirements**

Prerequisite: GAP 5/4 "Central (LE)" OR GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_37b_1   | x        | Central Role (Initiator) (M)                 |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37b_2   | x        | Authenticated MITM protection (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37b_3   | x        | Unauthenticated no MITM protection (C.2)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37b_4   |          | No security requirements (C.3)               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37b_5   | x        | LE Secure Connections (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37b_6   | x        | Encryption Key (C.5)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37b_7   | x        | Identity Key (C.6)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_37b_8   |          | Signing Key (C.7)                            |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF GAP 35/7 "Authenticated Pairing (LE security mode 1 level
  3)" OR GAP 35/12 "Authenticated Pairing (LE security mode 1 level 3) with
  LE Secure Connections Pairing only" OR (GAP 35/2 "LE security mode 2" AND
  GAP 35/3 "Authentication procedure"), otherwise not defined.
- C.2: Mandatory IF GAP 35/8 "Unauthenticated Pairing (LE security mode 1
  level 2)" OR GAP 35/11 "Unauthenticated Pairing (LE security mode 1 level
  2) with LE Secure Connections Pairing only" OR (GAP 35/2 "LE security mode
  2" AND NOT GAP 35/3 "Authentication procedure"), otherwise not defined.
- C.3: Mandatory IF GAP 35/1 "LE security mode 1" AND NOT GAP 35/8
  "Unauthenticated Pairing (LE security mode 1 level 2)" AND NOT GAP 35/7
  "Authenticated Pairing (LE security mode 1 level 3)", otherwise not defined.
- C.4: Mandatory IF GAP 35/9 "LE security mode 1 level 4" OR GAP 35/11
  "Unauthenticated Pairing (LE security mode 1 level 2) with LE Secure
  Connections Pairing only" OR GAP 35/12 "Authenticated Pairing (LE security
  mode 1 level 3) with LE Secure Connections Pairing only", otherwise not
  defined.
- C.5: Mandatory IF GAP 34/2 "Bondable mode", otherwise not defined.
- C.6: Mandatory IF GAP 36/5 "Resolvable private address generation
  procedure", otherwise not defined.
- C.7: Mandatory IF GAP 35/6 "Authenticate signed data procedure", otherwise
  not defined.

BR/EDR/LE Capability Statement
==============================
**Table 38: BR/EDR/LE Roles**

Prerequisite: GAP 0/3 "BR/EDR/LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_38_1    | x        | Broadcaster (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_38_2    | x        | Observer (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_38_3    | x        | Peripheral (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_38_4    | x        | Central (C.1)                                |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

BR/EDR/LE Capability Statement
==============================
**Table 41: Central BR/EDR/LE Security Aspects**

Prerequisite: GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_41_1    | x        | Security aspects (M)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_41_2a   |          | Derivation of BR/EDR Link Key from LE LTK (O)|
+------------------+----------+----------------------------------------------+
| TSPC_GAP_41_2b   |          | Derivation of LE LTK from BR/EDR Link Key (O)|
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

BR/EDR/LE Capability Statement
==============================
**Table 44: Central Simultaneous BR/EDR and LE Transports**

Prerequisite: GAP 38/4 "Central (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_44_1    | x        | Simultaneous BR/EDR and LE Transports -      |
|                  |          | BR/EDR Peripheral to the same device (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_44_2    | x        | Simultaneous BR/EDR and LE Transports -      |
|                  |          | BR/EDR Central to the same device (O)        |
+------------------+----------+----------------------------------------------+

- O: Optional

BR/EDR/LE Capability Statement
==============================
**Table 43: Peripheral BR/EDR/LE Security Aspects**

Prerequisite: GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_43_1    | x        | Security aspects (M)                         |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_43_2a   |          | Derivation of BR/EDR Link Key from LE LTK (O)|
+------------------+----------+----------------------------------------------+
| TSPC_GAP_43_2b   |          | Derivation of LE LTK from BR/EDR Link Key (O)|
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

BR/EDR/LE Capability Statement
==============================
**Table 45: Peripheral Simultaneous BR/EDR and LE Transports**

Prerequisite: GAP 38/3 "Peripheral (BR/EDR/LE)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GAP_45_1    | x        | Simultaneous BR/EDR and LE Transports -      |
|                  |          | BR/EDR Peripheral to the same device (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GAP_45_2    | x        | Simultaneous BR/EDR and LE Transports -      |
|                  |          | BR/EDR Central to the same device (O)        |
+------------------+----------+----------------------------------------------+

- O: Optional

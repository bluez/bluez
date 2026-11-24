.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

===========================================
Audio/Video Distribution Transport Protocol
===========================================
(TCRL 2023-1, AVDTP.ICS.1.3.4ed3)

Version and Role Declarations
=============================
**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_1_1   | x        | Source (C.1)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_1_2   | x        | Sink (C.1)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_1_3   | x        | Initiator (C.2)                              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_1_4   | x        | Acceptor (C.2)                               |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one of AVDTP 1/1 "Source" OR AVDTP 1/2
  "Sink".
- C.2: Mandatory to support at least one of AVDTP 1/3 "Initiator" OR AVDTP 1/4
  "Acceptor". Note: It is within the scope of profiles using the AVDTP
  specification to mandate Initiator/Acceptor capabilities.

Source Capabilities
===================
**Table 14a: AVDTP Source - Major Versions (X.Y)**

Prerequisite: AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_14a_1 |          | AVDTP 1.0 Withdrawn (C.1, C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_14a_2 |          | AVDTP 1.2 Withdrawn (C.1, C.3)               |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_14a_3 | x        | AVDTP 1.3 (C.1)                              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support one and only one of AVDTP 14a/1 "AVDTP 1.0" OR
  AVDTP 14a/2 "AVDTP 1.2" OR AVDTP 14a/3 "AVDTP 1.3".
- C.2: Excluded after the date of deprecation. Deprecated 2022-02-01.
  Withdrawn 2023-02-01.
- C.3: Excluded after the date of deprecation. Deprecated 2023-02-01.
  Withdrawn 2024-02-01.

Source Capabilities
===================
**Table 14: Source Capabilities**

Prerequisite: AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_14_1  | x        | Basic transport service support (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_14_2  |          | Reporting service support (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_14_3  |          | Recovery service support (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_14_4  |          | Multiplexing service support (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_14_5  |          | Robust header compression service support (O)|
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_14_6  |          | Delay Reporting (C.1)                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF AVDTP 14a/3 "AVDTP 1.3" is supported, otherwise Excluded.

Source Capabilities
===================
**Table 2: Signaling Message Format (Initiator, Source)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_2_1   | x        | Transaction Label (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_2_2   | x        | Packet type (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_2_3   | x        | Message type (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_2_4   | x        | Signal identifier (M)                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Source Capabilities
===================
**Table 3: Signaling Channel Establishment/Disconnection (Initiator, Source)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_3_1   | x        | Establish signaling channel (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_3_2   | x        | Disconnect signaling channel (O)             |
+------------------+----------+----------------------------------------------+

- O: Optional

Source Capabilities
===================
**Table 4: Stream Discovery and Configuration (Initiator, Source)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_4_1   | x        | Stream discover command (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4_2   | x        | Stream get capabilities command (C.2)        |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4_3   | x        | Set configuration command (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4_4   | x        | Get configuration command (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4_5   |          | Reconfigure command (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4_6   | x        | Stream get all capabilities command (C.1)    |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF AVDTP 14a/3 "AVDTP 1.3" is supported, otherwise Excluded.
- C.2: Mandatory IF AVDTP 4/6 "Stream get all capabilities command" is
  supported, otherwise Optional.

Source Capabilities
===================
**Table 5: Stream Establishment, Suspension and Release (Initiator, Source)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_5_1   | x        | Open stream command (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_5_2   | x        | Start stream command (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_5_3   | x        | Close stream command (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_5_4   | x        | Suspend command (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_5_5   | x        | Abort stream command (O)                     |
+------------------+----------+----------------------------------------------+

- O: Optional

Source Capabilities
===================
**Table 6: Security Signaling (Initiator, Source)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_6_1   |          | Content security control command (O)         |
+------------------+----------+----------------------------------------------+

- O: Optional

Source Capabilities
===================
**Table 7: Message Fragmentation (Initiator, Source)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_7_1   | x        | Signaling message fragmentation (M)          |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Source Capabilities
===================
**Table 8: Signaling Message Format (Acceptor, Source)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_8_1   | x        | Transaction Label (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_8_2   | x        | Packet type (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_8_3   | x        | Message type (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_8_4   | x        | Signal identifier (M)                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Source Capabilities
===================
**Table 9: Signaling Channel Establishment/Disconnection (Acceptor, Source)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_9_1   | x        | Establish signaling channel (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_9_2   | x        | Disconnect signaling channel (O)             |
+------------------+----------+----------------------------------------------+

- O: Optional

Source Capabilities
===================
**Table 10: Stream Discovery and Configuration (Acceptor, Source)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_10_1  | x        | Stream discover response (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10_2  | x        | Stream get capabilities response (C.2)       |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10_3  | x        | Set configuration response (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10_4  | x        | Get configuration response (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10_5  |          | Reconfigure response (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10_6  | x        | Stream get all capabilities response (C.1)   |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF AVDTP 14a/3 "AVDTP 1.3" is supported, otherwise Excluded.
- C.2: Mandatory IF AVDTP 10/6 "Stream get all capabilities response" is
  supported, otherwise Optional.

Source Capabilities
===================
**Table 11: Stream Establishment, Suspension and Release (Acceptor, Source)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_11_1  | x        | Open stream response (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11_2  | x        | Start stream response (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11_3  | x        | Close stream response (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11_4  | x        | Suspend response (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11_5  | x        | Abort stream response (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11_6  | x        | General reject message (O)                   |
+------------------+----------+----------------------------------------------+

- O: Optional

Source Capabilities
===================
**Table 12: Security Signaling (Acceptor, Source)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_12_1  |          | Content security control response (O)        |
+------------------+----------+----------------------------------------------+

- O: Optional

Source Capabilities
===================
**Table 13: Message Fragmentation (Acceptor, Source)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/1 "Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_13_1  | x        | Signaling message fragmentation (M)          |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Sink Capabilities
=================
**Table 15a: AVDTP Sink - Major Versions (X.Y)**

Prerequisite: AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_15a_1 |          | AVDTP 1.0 Withdrawn (C.1, C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_15a_2 |          | AVDTP 1.2 Withdrawn (C.1, C.3)               |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_15a_3 | x        | AVDTP 1.3 (C.1)                              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support one and only one of AVDTP 15a/1 "AVDTP 1.0" OR
  AVDTP 15a/2 "AVDTP 1.2" OR AVDTP 15a/3 "AVDTP 1.3".
- C.2: Excluded after the date of deprecation. Deprecated 2022-02-01.
  Withdrawn 2023-02-01.
- C.3: Excluded after the date of deprecation. Deprecated 2023-02-01.
  Withdrawn 2024-02-01.

Sink Capabilities
=================
**Table 15: Sink Capabilities**

Prerequisite: AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_15_1  | x        | Basic transport service support (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_15_2  |          | Reporting service support (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_15_3  |          | Recovery service support (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_15_4  |          | Multiplexing service support (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_15_5  |          | Robust header compression service support (O)|
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_15_6  |          | Delay Reporting (C.1)                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF AVDTP 15a/3 "AVDTP 1.3" is supported, otherwise Excluded.

Sink Capabilities
=================
**Table 2b: Signaling Message Format (Initiator, Sink)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_2b_1  | x        | Transaction Label (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_2b_2  | x        | Packet type (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_2b_3  | x        | Message type (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_2b_4  | x        | Signal identifier (M)                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Sink Capabilities
=================
**Table 3b: Signaling Channel Establishment/Disconnection (Initiator, Sink)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_3b_1  |          | Establish signaling channel (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_3b_2  |          | Disconnect signaling channel (O)             |
+------------------+----------+----------------------------------------------+

- O: Optional

Sink Capabilities
=================
**Table 4b: Stream Discovery and Configuration (Initiator, Sink)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_4b_1  | x        | Stream discover command (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4b_2  | x        | Stream get capabilities command (C.2)        |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4b_3  | x        | Set configuration command (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4b_4  |          | Get configuration command (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4b_5  |          | Reconfigure command (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_4b_6  | x        | Stream get all capabilities command (C.1)    |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF AVDTP 15a/3 "AVDTP 1.3" is supported, otherwise Excluded.
- C.2: Mandatory IF AVDTP 4b/6 "Stream get all capabilities command" is
  supported, otherwise Optional.

Sink Capabilities
=================
**Table 5b: Stream Establishment, Suspension and Release (Initiator, Sink)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_5b_1  | x        | Open stream command (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_5b_2  | x        | Start stream command (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_5b_3  | x        | Close stream command (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_5b_4  |          | Suspend command (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_5b_5  | x        | Abort stream command (O)                     |
+------------------+----------+----------------------------------------------+

- O: Optional

Sink Capabilities
=================
**Table 6b: Security Signaling (Initiator, Sink)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_6b_1  |          | Content security control command (O)         |
+------------------+----------+----------------------------------------------+

- O: Optional

Sink Capabilities
=================
**Table 7b: Message Fragmentation (Initiator, Sink)**

Prerequisite: AVDTP 1/3 "Initiator" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_7b_1  | x        | Signaling message fragmentation (M)          |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Sink Capabilities
=================
**Table 8b: Signaling Message Format (Acceptor, Sink)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_8b_1  | x        | Transaction Label (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_8b_2  | x        | Packet type (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_8b_3  | x        | Message type (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_8b_4  | x        | Signal identifier (M)                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Sink Capabilities
=================
**Table 9b: Signaling Channel Establishment/Disconnection (Acceptor, Sink)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_9b_1  |          | Establish signaling channel (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_9b_2  |          | Disconnect signaling channel (O)             |
+------------------+----------+----------------------------------------------+

- O: Optional

Sink Capabilities
=================
**Table 10b: Stream Discovery and Configuration (Acceptor, Sink)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_10b_1 | x        | Stream discover response (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10b_2 | x        | Stream get capabilities response (C.2)       |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10b_3 | x        | Set configuration response (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10b_4 |          | Get configuration response (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10b_5 |          | Reconfigure response (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_10b_6 | x        | Stream get all capabilities response (C.1)   |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF AVDTP 15a/3 "AVDTP 1.3" is supported, otherwise Excluded.
- C.2: Mandatory IF AVDTP 10b/6 "Stream get all capabilities response" is
  supported, otherwise Optional.

Sink Capabilities
=================
**Table 11b: Stream Establishment, Suspension and Release (Acceptor, Sink)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_11b_1 | x        | Open stream response (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11b_2 | x        | Start stream response (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11b_3 | x        | Close stream response (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11b_4 |          | Suspend response (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11b_5 | x        | Abort stream response (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_11b_6 | x        | General reject message (O)                   |
+------------------+----------+----------------------------------------------+

- O: Optional

Sink Capabilities
=================
**Table 12b: Security Signaling (Acceptor, Sink)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_12b_1 |          | Content security control response (O)        |
+------------------+----------+----------------------------------------------+

- O: Optional

Sink Capabilities
=================
**Table 13b: Message Fragmentation (Acceptor, Sink)**

Prerequisite: AVDTP 1/4 "Acceptor" AND AVDTP 1/2 "Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_13b_1 | x        | Signaling message fragmentation (M)          |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Message Error Handling Capabilities
===================================
**Table 16: Message Error Handling Capabilities**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_16_1  | x        | Reporting Capability Error (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_16_2  |          | Reject Corrupted Messages (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_16_3  | x        | General Reject Response Includes Signal ID   |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF AVDTP 14a/2 "AVDTP 1.2" OR AVDTP 15a/2 "AVDTP 1.2" OR
  AVDTP 14a/3 "AVDTP 1.3" OR AVDTP 15a/3 "AVDTP 1.3" is supported, otherwise
  Optional.
- C.2: Excluded IF AVDTP 16/3 "General Reject Response Includes Signal ID" is
  supported, otherwise Optional.
- C.3: Mandatory IF AVDTP 14a/3 "AVDTP 1.3" OR AVDTP 15a/3 "AVDTP 1.3" is
  supported, otherwise Optional.

Upper Tester Interface
======================
**Table 17: Upper Test Interface**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_17_1  |          | Upper Tester Interface provided (O)          |
+------------------+----------+----------------------------------------------+

- O: Optional

L2CAP Capabilities
==================
**Table 18: L2CAP Capabilities**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_AVDTP_18_1  |          | Enhanced Retransmission Mode preferred for   |
|                  |          | signaling channel (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_18_2  |          | Streaming Mode preferred for Media Transport |
|                  |          | channel (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_AVDTP_18_3  |          | FCS Option (C.1)                             |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF AVDTP 18/1 "Enhanced Retransmission Mode preferred for
  signaling channel" is supported, otherwise Optional.

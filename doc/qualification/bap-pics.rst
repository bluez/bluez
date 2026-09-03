.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

===================
Basic Audio Profile
===================
(TCRL pkg102, BAP.ICS.p11)

Roles
=====
**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_1_1     | x        | Unicast Server (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_1_2     | x        | Unicast Client (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_1_3     | x        | Broadcast Source (C.1)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_1_4     | x        | Broadcast Sink (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_1_5     | x        | Scan Delegator (C.1, C.2)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_1_6     | x        | Broadcast Assistant (C.1)                    |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.
- C.2: Mandatory IF BAP 1/4 "Broadcast Sink", otherwise Excluded.

Transports
==========

**Table 2: Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_2_1     | x        | Profile supported over LE (C.1, C.3)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_2_2     |          | Profile supported over BR/EDR (C.2, C.4)     |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Profile IF CORE 41/1 "BR/EDR Core Configuration" OR
  CORE 40/1 "Core-Controller".
- C.2: Excluded for this Profile IF CORE 41/2 "LE Core Configuration" OR CORE
  40/1 "Core-Controller".
- C.3: Mandatory for this Profile.
- C.4: Optional for this Profile IF BAP 3/2 "GAP BR/EDR Host", otherwise
  Excluded.

Host Configurations
===================

**Table 3: GAP Host Configuration**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_3_1     | x        | GAP LE Host (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_3_2     |          | GAP BR/EDR Host (O)                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

Note: A GAP BR/EDR/LE Host will need to select BAP 3/1 and BAP 3/2.

LC3 Configurations
==================

**Table 93: LC3 Decoder Features**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_93_1    |          | Narrow Band (8 kHz) (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_93_2    | x        | Wideband (16 kHz) (C.1)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_93_3    | x        | Semi-Superwideband (24 kHz) (C.1)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_93_4    | x        | Superwideband (32 kHz) (O)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_93_5    |          | Full Band (44.1 kHz) (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_93_6    | x        | Full Band (48 kHz) (O)                       |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF (BAP 1/1 "Unicast Server" AND BAP 8/1 "Audio Sink") OR
  (BAP 1/2 "Unicast Client" AND BAP 29/1 "Audio Sink") OR BAP 1/4 "Broadcast
  Sink", otherwise Optional.

**Table 94: LC3 Decoder Frame Interval**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_94_1    | x        | 7.5 ms (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_94_2    | x        | 10 ms (C.1)                                  |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF (BAP 1/1 "Unicast Server" AND BAP 8/1 "Audio Sink") OR
  (BAP 1/2 "Unicast Client" AND BAP 29/1 "Audio Sink") OR BAP 1/4 "Broadcast
  Sink", otherwise Optional.

**Table 95: LC3 Encoder Features**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_95_1    |          | Narrow Band (8 kHz) (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_95_2    | x        | Wideband (16 kHz) (C.1)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_95_3    |          | Semi-Superwideband (24 kHz) (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_95_4    | x        | Superwideband (32 kHz) (O)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_95_5    |          | Full Band (44.1 kHz) (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_95_6    | x        | Full Band (48 kHz) (O)                       |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF (BAP 1/1 "Unicast Server" AND BAP 8/2 "Audio Source") OR
  (BAP 1/2 "Unicast Client" AND BAP 29/2 "Audio Source") OR BAP 1/3 "Broadcast
  Source" , otherwise Optional.

**Table 96: LC3 Encoder Frame Interval**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_96_1    | x        | 7.5 ms (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_96_2    | x        | 10 ms (C.1)                                  |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF (BAP 1/1 "Unicast Server" AND BAP 8/2 "Audio Source") OR
  (BAP 1/2 "Unicast Client" AND BAP 29/2 "Audio Source") OR BAP 1/3 "Broadcast
  Source" , otherwise Optional.

Unicast Server requirements
===========================

**Table 4: Unicast Server, X.Y Versions**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_4_1     | x        | BAP v1.0 (C.1, C.2)                          |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory.
- C.2: Can only be supported with an active X.Y.Z version after Deprecation
  or Withdrawal.
  Deprecated 2025-02-01. Withdrawn 2027-02-01.

**Table 5: Unicast Server, X.Y.Z Versions**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_5_1     |          | BAP v1.0.1 (C.4)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_5_2     |          | No longer used                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_5_3     |          | Erratum 19096 (C.3)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_5_4     | x        | BAP v1.0.2 (C.4)                             |
+------------------+----------+----------------------------------------------+

- C.1-C.2: No longer used.
- C.3: Mandatory IF BAP 5/1 "BAP v1.0.1", otherwise Excluded.
- C.4: Mandatory to support one and only one.

**Table 6: Unicast Server: Services Included**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_6_1     |          | ASCS supported over BR/EDR (C.1, C.3)        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_6_2     | x        | ASCS supported over LE (C.1)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_6_3     |          | PACS supported over BR/EDR (C.2, C.3)        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_6_4     | x        | PACS supported over LE (C.2)                 |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.
- C.2: Mandatory to support at least one.
- C.3: Optional IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.

**Table 7: Unicast Server: Feature Support**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_7_1     | x        | ASCS UUID in AD (M)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_2     |          | Two Sink Audio Channels (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_3     |          | Two Source Audio Channels (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_4     |          | Autonomous Config Codec (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_5     |          | Autonomous Receiver Start Ready (C.1)        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_6     |          | Autonomous Disable (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_7     |          | Autonomous Update Metadata (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_8     |          | Autonomous Release (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_9     | x        | General Announcement (C.2)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_7_10    | x        | Targeted Announcement (C.2)                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF BAP 8/1 "Audio Sink", otherwise not defined.
- C.2: Mandatory to support at least one.

**Table 8: Audio Role Requirements: Unicast Server**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_8_1     | x        | Audio Sink (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_8_2     | x        | Audio Source (C.1)                           |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

**Table 9: Published Audio Capabilities Service Characteristic Support Requirements**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_9_1     | x        | Sink PAC characteristic (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9_2     | x        | Sink Audio Locations characteristic (C.3)    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9_3     | x        | Source PAC characteristic (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9_4     |          | Source Audio Locations characteristic (C.4)  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9_5     | x        | Available Audio Contexts characteristic (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9_6     | x        | Supported Audio Contexts characteristic (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9_7     |          | Multiple Sink Audio Locations (C.3)          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9_8     |          | Multiple Source Audio Locations (C.4)        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF BAP 8/1 "Audio Sink", otherwise Excluded.
- C.2: Mandatory IF BAP 8/2 "Audio Source", otherwise Excluded.
- C.3: Optional IF BAP 8/1 "Audio Sink", otherwise Excluded.
- C.4: Optional IF BAP 8/2 "Audio Source", otherwise Excluded.

**Table 9a: CIS Establishment Requirements: Unicast Server**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_9a_1    | x        | Sink ASE - Enabling, Source ASE - Enabling   |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9a_2    | x        | Sink ASE - Enabling, Source ASE - QoS        |
|                  |          | Configured (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9a_3    | x        | Sink ASE - Enabling, Source ASE - Not Bound  |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9a_4    | x        | Sink ASE - QoS Configured, Source ASE -      |
|                  |          | Enabling (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9a_5    |          | Sink ASE - QoS Configured, Source ASE - QoS  |
|                  |          | Configured (C.3)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9a_6    |          | Sink ASE - QoS Configured, Source ASE - Not  |
|                  |          | Bound (C.4)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9a_7    | x        | Sink ASE - Not bound, Source ASE - Enabling  |
|                  |          | (C.5)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_9a_8    |          | Sink ASE - Not bound, Source ASE - QoS       |
|                  |          | Configured (C.6)                             |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 8/1 "Audio Sink" AND BAP 8/2 "Audio Source", otherwise
  Excluded.
- C.2: Mandatory IF BAP 8/1 "Audio Sink", otherwise Excluded.
- C.3: Optional IF BAP 8/1 "Audio Sink" AND BAP 8/2 "Audio Source", otherwise
  Excluded.
- C.4: Optional IF BAP 8/1 "Audio Sink", otherwise Excluded.
- C.5: Mandatory IF BAP 8/2 "Audio Source", otherwise Excluded.
- C.6: Optional IF BAP 8/2 "Audio Source", otherwise Excluded.

Audio Capability Support requirements
-------------------------------------

**Table 10: Codec Specific Capabilities LTV Structures: Unicast Server**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_10_1    | x        | Supported Sampling Frequencies (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_10_2    | x        | Supported Frame Durations (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_10_3    | x        | Supported Octets per Codec Frame (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_10_4    |          | Supported Audio Channel Counts (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_10_5    |          | Supported Max Codec Frames Per SDU (O)       |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 11: Metadata LTV Structures: Unicast Server**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_11_1    |          | Preferred_Audio_Contexts (O)
+------------------+----------+----------------------------------------------+
| TSPC_BAP_11_2    | x        | Streaming_Audio_Contexts (M)
+------------------+----------+----------------------------------------------+
| TSPC_BAP_11_3    |          | Vendor-specific Metadata (O)
+------------------+----------+----------------------------------------------+

**Table 12: Audio Capability Support Settings: Unicast Server is Audio Sink**

Prerequisite: BAP 8/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_12_1    |          | 8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms    |
|                  |          | Frame Duration, 26 Octets (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_2    |          | 8_2 LC3: 8 kHz Sampling Frequency, 10 ms     |
|                  |          | Frame Duration, 30 Octets (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_3    | x        | 16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms  |
|                  |          |  FrameDuration, 30 Octets (C.3)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_4    | x        | 16_2 LC3: 16 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 40 Octets (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_5    |          | 24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 45 Octets (C.4)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_6    | x        | 24_2 LC3: 24 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 60 Octets (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_7    | x        | 32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 60 Octets (C.5)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_8    | x        | 32_2 LC3: 32 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 80 Octets (C.6)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_9    |          | 441_1 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 8.163 ms Frame Duration, 97 Octets (C.7)     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_10   |          | 441_2 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 10.884 ms Frame Duration, 130 Octets (C.8)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_11   | x        | 48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 75 Octets (C.9)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_12   | x        | 48_2 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 100 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_13   | x        | 48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 90 Octets (C.9)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_14   | x        | 48_4 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 120 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_15   | x        | 48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 117 Octets (C.9)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_16   | x        | 48_6 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 155 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_12_17   |          | Vendor-specific Codec Capability Setting (O) |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF BAP 93/1 "Narrow Band (8 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.2: Optional IF BAP 93/1 "Narrow Band (8 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.3: Optional IF BAP 93/2 "Wideband (16 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.4: Optional IF BAP 93/3 "Semi-Superwideband (24 kHz)" AND BAP 94/1 "7.5
  ms", otherwise Excluded.
- C.5: Optional IF BAP 93/4 "Superwideband (32 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.6: Optional IF BAP 93/4 "Superwideband (32 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.7: Optional IF BAP 93/5 "Full Band (44.1 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.8: Optional IF BAP 93/5 "Full Band (44.1 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.9: Optional IF BAP 93/6 "Full Band (48 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.10: Optional IF BAP 93/6 "Full Band (48 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.

**Table 13: Audio Capability Support Settings: Unicast Server is Audio Source**

Prerequisite: BAP 8/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_13_1    |          | 8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms    |
|                  |          | Frame Duration, 26 Octets (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_2    |          | 8_2 LC3: 8 kHz Sampling Frequency, 10 ms     |
|                  |          | Frame Duration, 30 Octets (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_3    | x        | 16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 30 Octets (C.3)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_4    | x        | 16_2 LC3: 16 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 40 Octets (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_5    |          | 24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 45 Octets (C.4)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_6    |          | 24_2 LC3: 24 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 60 Octets (C.5)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_7    | x        | 32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 60 Octets (C.6)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_8    | x        | 32_2 LC3: 32 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 80 Octets (C.7)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_9    |          | 441_1 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 8.163 ms Frame Duration, 97 Octets (C.8)     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_10   |          | 441_2 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 10.884 ms Frame Duration, 130 Octets (C.9)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_11   |          | 48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 75 Octets (C.10)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_12   |          | 48_2 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 100 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_13   |          | 48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 90 Octets (C.10)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_14   |          | 48_4 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 120 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_15   |          | 48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 117 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_16   |          | 48_6 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 155 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_13_17   |          | Vendor-specific Codec Capability Setting (O) |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1:Optional IF BAP 95/1 "Narrow Band (8 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.2:Optional IF BAP 95/1 "Narrow Band (8 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.3:Optional IF BAP 95/2 "Wideband (16 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.4: Optional IF BAP 95/3 "Semi-Superwideband (24 kHz)" AND BAP 96/1 "7.5
  ms", otherwise Excluded.
- C.5: Optional IF BAP 95/3 "Semi-Superwideband (24 kHz)" AND BAP 96/2 "10
  ms", otherwise Excluded.
- C.6: Optional IF BAP 95/4 "Superwideband (32 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.7: Optional IF BAP 95/4 "Superwideband (32 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.8: Optional IF BAP 95/5 "Full Band (44.1 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.9: Optional IF BAP 95/5 "Full Band (44.1 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.10: Optional IF BAP 95/6 "Full Band (48 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.11: Optional IF BAP 95/6 "Full Band (48 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.

QoS Configuration requirements
------------------------------

**Table 14: QoS Configuration: LC3 Low Latency: Unicast Server is Audio Sink**

Prerequisite: BAP 8/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_14_1    |          | 8_1_1 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_2    |          | 8_2_1 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_3    | x        | 16_1_1 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_4    | x        | 16_2_1 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_5    |          | 24_1_1 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_6    |          | 24_2_1 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.5)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_7    | x        | 32_1_1 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_8    | x        | 32_2_1 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_9    |          | 441_1_1 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 5 RTN, 24 Max_Transport_Latency|
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_10   |          | 441_2_1 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 5 RTN, 31 Max_Transport_Latency|
|                  |          | (C.9)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_11   | x        | 48_1_1 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.10)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_12   | x        | 48_2_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 100 Max SDU Size, 5 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_13   | x        | 48_3_1 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.12)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_14   | x        | 48_4_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 120 Max SDU Size, 5 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_15   | x        | 48_5_1 LC3: 7500 SDU Interval, unframed,     |
|                  |          | 117 Max SDU Size, 5 RTN, 15                  |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_14_16   | x        | 48_6_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 155 Max SDU Size, 5 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.15)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Optional IF BAP 12/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 12/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 12/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4 Mandatory IF BAP 12/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 12/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 12/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.7: Optional IF BAP 12/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.8: Optional IF BAP 12/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.9: Optional IF BAP 12/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884 ms
  Frame Duration, 130 Octets", otherwise Excluded.
- C.10: Optional IF BAP 12/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.11: Optional IF BAP 12/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 100 Octets", otherwise Excluded.
- C.12: Optional IF BAP 12/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.13: Optional IF BAP 12/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 120 Octets", otherwise Excluded.
- C.14:Optional IF BAP 12/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 117 Octets", otherwise Excluded.
- C.15: Optional IF BAP 12/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 155 Octets", otherwise Excluded.

**Table 15: QoS Configuration: LC3 Low Latency: Unicast Server is Audio Source**

Prerequisite: BAP 8/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_15_1    |          | 8_1_1 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_2    |          | 8_2_1 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_3    | x        | 16_1_1 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_4    | x        | 16_2_1 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_5    |          | 24_1_1 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_6    |          | 24_2_1 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.5)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_7    | x        | 32_1_1 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_8    | x        | 32_2_1 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_9    |          | 441_1_1 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 5 RTN, 24 Max_Transport_Latency|
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_10   |          | 441_2_1 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 5 RTN, 31 Max_Transport_Latency|
|                  |          | (C.9)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_11   |          | 48_1_1 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.10)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_12   |          | 48_2_1 LC3: 10000 SDU Interval, unframed, 100|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.11)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_13   |          | 48_3_1 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.12)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_14   |          | 48_4_1 LC3: 10000 SDU Interval, unframed, 120|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.13)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_15   |          | 48_5_1 LC3: 7500 SDU Interval, unframed, 117 |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.14)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_15_16   |          | 48_6_1 LC3: 10000 SDU Interval, unframed, 155|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.15)                                       |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Optional IF BAP 13/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 13/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 13/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Mandatory IF BAP 13/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 13/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 13/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.7: Optional IF BAP 13/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.8: Optional IF BAP 13/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.9: Optional IF BAP 13/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884 ms
  Frame Duration, 130 Octets", otherwise Excluded.
- C.10: Optional IF BAP 13/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.11: Optional IF BAP 13/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 100 Octets", otherwise Excluded.
- C.12: Optional IF BAP 13/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.13: Optional IF BAP 13/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 120 Octets", otherwise Excluded.
- C.14: Optional IF BAP 13/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.15: Optional IF BAP 13/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 155 Octets", otherwise Excluded.

**Table 16: QoS Configuration: LC3 High Reliability: Unicast Server is Audio Sink**

Prerequisite: BAP 8/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_16_1    |          | 8_1_2 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_2    |          | 8_2_2 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_3    |          | 16_1_2 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.3)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_4    | x        | 16_2_2 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_5    |          | 24_1_2 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_6    | x        | 24_2_2 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_7    |          | 32_1_2 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.5)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_8    |          | 32_2_2 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_9    |          | 441_1_2 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 13 RTN, 80                     |
|                  |          | Max_Transport_Latency (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_10   |          | 441_2_2 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 13 RTN, 85                     |
|                  |          | Max_Transport_Latency (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_11   | x        | 48_1_2 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_12   | x        | 48_2_2 LC3: 10000 SDU Interval, unframed, 100|
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_13   | x        | 48_3_2 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_14   | x        | 48_4_2 LC3: 10000 SDU Interval, unframed, 120|
|                  |          | Max SDU Size, 13 RTN, 100                    |
|                  |          | Max_Transport_Latency (C.12)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_15   | x        | 48_5_2 LC3: 7500 SDU Interval, unframed, 117 |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_16_16   | x        | 48_6_2 LC3: 10000 SDU Interval, unframed, 155|
|                  |          | Max SDU Size, 13 RTN, 100                    |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Optional IF BAP 12/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 12/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 12/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Optional IF BAP 12/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 12/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 12/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.7: Optional IF BAP 12/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.8: Optional IF BAP 12/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884 ms
  Frame Duration, 130 Octets", otherwise Excluded.
- C.9: Optional IF BAP 12/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms Fram
  Duration, 75 Octets", otherwise Excluded.
- C.10: Optional IF BAP 12/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 100 Octets", otherwise Excluded.
- C.11: Optional IF BAP 12/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.12: Optional IF BAP 12/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 120 Octets", otherwise Excluded.
- C.13: Optional IF BAP 12/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.14: Optional IF BAP 12/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 155 Octets", otherwise Excluded.

**Table 17: QoS Configuration: LC3 High Reliability: Unicast Server is Audio Source**

Prerequisite: BAP 8/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_17_1    |          | 8_1_2 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_2    |          | 8_2_2 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_3    |          | 16_1_2 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.3)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_4    |          | 16_2_2 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_5    |          | 24_1_2 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.5)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_6    |          | 24_2_2 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_7    |          | 32_1_2 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_8    |          | 32_2_2 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_9    |          | 441_1_2 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 13 RTN, 80                     |
|                  |          | Max_Transport_Latency (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_10   |          | 441_2_2 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 13 RTN, 85                     |
|                  |          | Max_Transport_Latency (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_11   |          | 48_1_2 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_12   |          | 48_2_2 LC3: 10000 SDU Interval, unframed, 100|
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.12)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_13   |          | 48_3_2 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_14   |          | 48_4_2 LC3: 10000 SDU Interval, unframed, 120|
|                  |          | Max SDU Size, 13 RTN, 100                    |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_15   |          | 48_5_2 LC3: 7500 SDU Interval, unframed, 117 |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.15)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_17_16   |          | 48_6_2 LC3: 10000 SDU Interval, unframed, 155|
|                  |          | Max SDU Size, 13 RTN, 100                    |
|                  |          | Max_Transport_Latency (C.16)                 |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF BAP 13/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 13/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 13/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Optional IF BAP 13/4 "16_2 LC3: 16 kHz Sampling Frequency, 10 ms Frame
  Duration, 40 Octets", otherwise Excluded.
- C.5: Optional IF BAP 13/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.6: Optional IF BAP 13/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.7: Optional IF BAP 13/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.8: Optional IF BAP 13/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.9: Optional IF BAP 13/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.10: Optional IF BAP 13/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884
  ms Frame Duration, 130 Octets", otherwise Excluded.
- C.11: Optional IF BAP 13/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.12: Optional IF BAP 13/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 100 Octets", otherwise Excluded.
- C.13: Optional IF BAP 13/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.14: Optional IF BAP 13/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 120 Octets", otherwise Excluded.
- C.15: Optional IF BAP 13/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.16: Optional IF BAP 13/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 155 Octets", otherwise Excluded.

**Table 18: QoS Configuration: Vendor-Specific Codec: Unicast Server is Audio Sink**

Prerequisite: BAP 8/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_18_1    |          | Vendor-specific QoS Config Setting: Unicast  |
|                  |          | Server is Audio Sink (C.1)                   |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 12/17 "Vendor-specific Codec Capability Setting",
  otherwise Excluded.

**Table 19: QoS Configuration: Vendor-Specific Codec: Unicast Server is Audio Source**

Prerequisite: BAP 8/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_19_1    |          | Vendor-specific QoS Config Setting: Unicast  |
|                  |          | Server is Audio Source (C.1)                 |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 13/17 "Vendor-specific Codec Capability Setting",
  otherwise Excluded.

**Table 20: LC3 Audio Configuration: Unicast Server**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_20_1    | x        | AC 1: 1 Server, 1 Sink ASE, 1 Channel/Sink,  |
|                  |          | 1 CIS, 1 Audio Stream (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_2    | x        | AC 2: 1 Server, 1 Source ASE,                |
|                  |          | 1 Channel/Source, 1 CIS, 1 Audio Stream (C.2)|
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_3    | x        | AC 3: 1 Server, 1 Sink ASE, 1 Channel/Sink,  |
|                  |          | 1 CIS, 2 Audio Streams (C.3)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_4    |          | AC 4: 1 Server, 1 Sink ASE, 2 Channels/Sink, |
|                  |          | 1 CIS, 1 Audio Stream (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_5    |          | AC 5: 1 Server, 1 Sink ASE, 1 Source ASE, 2  |
|                  |          | Channels/Sink, 1 Channel/Source, 1, CIS, 2   |
|                  |          | Audio Streams (C.8)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_6    |          | AC 6i: 1 Server, 2 Sink ASEs, 1 Channel/Sink,|
|                  |          | 2 CISes, 2 Audio Streams (C.6)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_7    | x        | AC 7i: 1 Server, 1 Sink ASE, 1 Source ASE, 1 |
|                  |          | Channel/Sink, 1 Channel/Source, 2 CISes, 2   |
|                  |          | Audio Streams (C.3)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_8    |          | AC 8i: 1 Server, 2 Sink ASEs, 1 Source ASE, 1|
|                  |          | Channel/Sink, 1 Channel/Source, 2 CISes, 3   |
|                  |          | Audio Streams (C.5)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_9    |          | AC 9i: 1 Server, 2 Source ASEs, 1            |
|                  |          | Channel/Source, 2 CISes, 2 Audio Streams     |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_10   |          | AC 10: 1 Server, 1 Source ASE, 2             |
|                  |          | Channels/Source, 1 CIS, 1 Audio Stream (C.9) |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_20_11   |          | AC 11i: 1 Server, 2 Sink ASEs, 2 Source ASEs,|
|                  |          | 1 Channel/Sink, 1 Channel/Source, 2 CISes,   |
|                  |          | 4 Audio Streams (C.5)                        |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 8/1 "Audio Sink", otherwise Excluded.
- C.2: Mandatory IF BAP 8/2 "Audio Source", otherwise Excluded.
- C.3: Mandatory IF BAP 8/1 "Audio Sink" AND BAP 8/2 "Audio Source", otherwise
  Excluded.
- C.4:  Mandatory IF BAP 8/1 "Audio Sink" AND BAP 9/7 "Multiple Sink Audio
  Locations" AND BAP 7/2 "Two Sink Audio Channels", otherwise Excluded.
- C.5: Optional IF BAP 8/1 "Audio Sink" AND BAP 8/2 "Audio Source", otherwise
  Excluded.
- C.6: Mandatory IF BAP 8/1 "Audio Sink" AND BAP 9/7 "Multiple Sink Audio
  Locations", otherwise Excluded.
- C.7: Mandatory IF BAP 8/2 "Audio Source" AND BAP 9/8 "Multiple Source Audio
  Locations", otherwise Excluded.
- C.8: Optional IF BAP 8/1 "Audio Sink" AND BAP 8/2 "Audio Source" AND BAP 7/2
  "Two Sink Audio Channels", otherwise Excluded.
- C.9: Mandatory IF BAP 9/2 "Sink Audio Locations characteristic" AND BAP 7/3
  "Two Source Audio Channels", otherwise Excluded.

Context Type requirements
-------------------------

**Table 21: Supported Sink Context Requirements: Unicast Server**

Prerequisite: BAP 8/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_21_1    | x        | Unspecified (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_2    | x        | Conversational (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_3    | x        | Media (O)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_4    |          | Game (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_5    |          | Instructional (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_6    |          | Voice assistants (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_7    |          | Live (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_8    |          | Sound effects (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_9    |          | Notifications (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_10   |          | Ringtone (O)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_11   |          | Alerts (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_21_12   |          | Emergency Alarm (O)                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 22: Supported Source Context Requirements: Unicast Server**

Prerequisite: BAP 8/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_22_1    | x        | Unspecified (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_2    | x        | Conversational (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_3    |          | Media (O)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_4    |          | Game (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_5    |          | Instructional (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_6    |          | Voice assistants (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_7    |          | Live (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_8    |          | Sound effects (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_9    |          | Notifications (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_10   |          | Ringtone (O)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_11   |          | Alerts (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_22_12   |          | Emergency Alarm (O)                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

GAP requirements
----------------

**Table 23: GAP Requirements: Unicast Server**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_23_1    | x        | Peripheral (M)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_2    | x        | Bondable mode (LE) (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_3    |          | Bondable mode (BR/EDR) (C.2)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_4    | x        | Bonding procedure (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_5    | x        | LE security mode 1 (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_6    | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (M)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_7    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_8    |          | Security mode 4, level 2 (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_9    |          | 128-bit encryption key size capable (BR/EDR) |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_10   | x        | Minimum 128 Bit entropy key (LE) (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_11   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_12   | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_13   |          | CoD Major Service Class bit 14 (C.2)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_14   |          | Limited discoverable mode (C.6)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_15   |          | General discoverable mode (BR/EDR) (C.6)     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_16   |          | Initiation of general bonding (C.2)          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_17   |          | BR/EDR Secure Connections (C.8)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_18   | x        | LE Secure Connections (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_19   | x        | Out of Band (Peripheral) (C.7)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_20   |          | Out-of-Band (BR/EDR) (C.8)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_23_21   |          | LE security mode 1 level 4 (O)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: No longer used.
- C.2: Mandatory IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.
- C.3-C.5: No longer used.
- C.6: Mandatory to support at least one IF BAP 3/2 "GAP BR/EDR Host",
  otherwise not defined.
- C.7: Mandatory to support at least one.
- C.8: Mandatory to support at least one IF BAP 3/2 "GAP BR/EDR Host",
  otherwise not defined.

**Table 24: No longer used**

LL requirements
---------------

**Table 25: LL Requirements: Unicast Server**

Prerequisite: BAP 1/1 "Unicast Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_25_1    | x        | LE Encryption (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_25_2    | x        | LE Extended Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_25_3    | x        | Connected Isochronous Stream - Peripheral (M)|
+------------------+----------+----------------------------------------------+

- M: Mandatory

Unicast Client requirements
===========================

**Table 26: Unicast Client, X.Y Versions**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_26_1    | x        | BAP v1.0 (C.1, C.2)                          |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory.
- C.2: Can only be supported with an active X.Y.Z version after Deprecation
  or Withdrawal.
  Deprecated 2025-02-01. Withdrawn 2027-02-01.

**Table 27: Unicast Client, X.Y.Z Versions**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_27_1    |          | No longer used                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_27_2    |          | BAP v1.0.1 (C.3)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_27_3    |          | No longer used                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_27_4    |          | Erratum 19096 (C.2)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_27_5    | x        | BAP v1.0.2 (C.3)                             |
+------------------+----------+----------------------------------------------+

- C.1: No longer used.
- C.2: Mandatory IF BAP 27/2 "BAP v1.0.1", otherwise Excluded.
- C.3: Mandatory to support one and only one.

**Table 28: Unicast Client: Client Services Support**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_28_1    |          | Discover ASCS over BR/EDR (C.1, C.3)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_28_2    | x        | Discover ASCS over LE (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_28_3    |          | Discover PACS over BR/EDR (C.2, C.3)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_28_4    | x        | Discover PACS over LE (C.2)                  |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.
- C.2: Mandatory to support at least one.
- C.3: Optional IF BAP 3/2 "GAP BR/EDR Host", otherwise Excluded.

**Table 29: Audio Role Requirements: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_29_1    | x        | Audio Sink (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_29_2    | x        | Audio Source (C.1)                           |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

**Table 30: Feature Support: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_30_1    |          | Multiple Server Support (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_30_2    |          | Multiple Audio Locations (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_30_3    | x        | Two Audio Channels (O)                       |
+------------------+----------+----------------------------------------------+

- O: Optional

**Table 31: Audio Stream Control Service Characteristic Support Requirements**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_31_1    | x        | Sink ASE Characteristic discovery (C.2)      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_31_2    | x        | Source ASE Characteristic discovery (C.1)    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_31_3    | x        | ASE Control Point Characteristic discovery   |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_31_4    | x        | Audio Stream Control Service Discovery (M)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_31_5    | x        | Audio Stream Control Service Characteristic  |
|                  |          | Discovery (M)                                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_31_6    | x        | Sink ASE_ID Discovery (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_31_7    | x        | Source ASE_ID Discovery (C.1)                |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF BAP 29/1 "Audio Sink", otherwise Excluded.
- C.2: Mandatory IF BAP 29/2 "Audio Source", otherwise Excluded.

**Table 32: Published Audio Capabilities Service Characteristic Support Requirements**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_32_1    | x        | Sink PAC characteristic (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_2    | x        | Sink Audio Locations characteristic (C.1)    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_3    | x        | Source PAC characteristic (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_4    | x        | Source Audio Locations characteristic (C.2)  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_5    | x        | Available Audio Contexts characteristic (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_6    | x        | Supported Audio Contexts characteristic (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_7    | x        | Published Audio Capabilities Service         |
|                  |          | Discovery (M)                                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_8    | x        | Published Audio Capabilities Service         |
|                  |          | Characteristic Discovery (M)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_9    |          | Supported Audio Contexts discovery (O)       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_32_10   | x        | Available Audio Contexts discovery (M)       |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF BAP 29/2 "Audio Source", otherwise Excluded.
- C.2: Mandatory IF BAP 29/1 "Audio Sink", otherwise Excluded.

**Table 33: ASE Control Operations Requirements: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_33_1    | x        | Codec configuration (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33_2    | x        | QoS configuration (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33_3    | x        | Enabling an ASE (M)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33_4    | x        | Receiver Start Ready (C.1)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33_5    |          | Update Metadata (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33_6    | x        | Disabling an ASE (M)                         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33_7    | x        | Receiver Stop Ready (C.1)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33_8    | x        | Releasing an ASE (M)                         |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF BAP 29/1 "Audio Sink", otherwise Excluded.

**Table 33a: CIS Establishment Requirements: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_33a_1   | x        | Sink ASE - Enabling, Source ASE - Enabling   |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33a_2   | x        | Sink ASE - Enabling, Source ASE - QoS        |
|                  |          | Configured (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33a_3   | x        | Sink ASE - Enabling, Source ASE - Not Bound  |
|                  |          | (C.5)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33a_4   | x        | Sink ASE - QoS Configured, Source ASE -      |
|                  |          | Enabling (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33a_5   |          | Sink ASE - QoS Configured, Source ASE - QoS  |
|                  |          | Configured (C.3)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33a_6   |          | Sink ASE - QoS Configured, Source ASE - Not  |
|                  |          | Bound (C.6)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33a_7   | x        | Sink ASE - Not bound, Source ASE - Enabling  |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_33a_8   |          | Sink ASE -Not bound, Source ASE - QoS        |
|                  |          | Configured (C.4)                             |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one IF BAP 29/1 "Audio Sink" AND BAP 29/2
  "Audio Source", otherwise Excluded.
- C.2: Mandatory IF BAP 29/1 "Audio Sink", otherwise Excluded.
- C.3: Optional IF BAP 29/1 "Audio Sink" AND BAP 29/2 "Audio Source", otherwise
  Excluded.
- C.4: Optional IF BAP 29/1 "Audio Sink", otherwise Excluded.
- C.5: Mandatory IF BAP 29/2 "Audio Source", otherwise Excluded.
- C.6: Optional IF BAP 29/2 "Audio Source", otherwise Excluded.

Audio Capability Support requirements
-------------------------------------

**Table 34: Codec Specific Configuration LTV Structures: Unicast Client**

Prerequisite: BAP 29/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_34_1    | x        | Sampling_Frequency (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_34_2    | x        | Frame_Duration (M)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_34_3    |          | Audio_Channel_Allocation (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_34_4    | x        | Octets_Per_Codec_Frame (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_34_5    |          | Codec_Frame_Blocks_Per_SDU (O)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 35: Metadata LTV Structures: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_35_1    | x        | Streaming_Audio_Contexts (M)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_35_2    |          | Vendor-specific Metadata (O)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 36: Audio Capability Configuration Support Settings: Unicast Client is Audio Sink**

Prerequisite: BAP 29/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_36_1    |          | 8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms    |
|                  |          | Frame Duration, 26 Octets (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_2    |          | 8_2 LC3: 8 kHz Sampling Frequency, 10 ms     |
|                  |          | Frame Duration, 30 Octets (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_3    | x        | 16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 30 Octets (C.3)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_4    | x        | 16_2 LC3: 16 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 40 Octets (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_5    |          | 24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 45 Octets (C.4)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_6    |          | 24_2 LC3: 24 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 60 Octets (C.11)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_7    | x        | 32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 60 Octets (C.5)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_8    | x        | 32_2 LC3: 32 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 80 Octets (C.6)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_9    |          | 441_1 LC3: 44.1 kHz Sampling Frequency, 8.163|
|                  |          | ms Frame Duration, 97 Octets (C.7)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_10   |          | 441_2 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 10.884 ms Frame Duration, 130 Octets (C.8)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_11   | x        | 48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 75 Octets (C.9)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_12   | x        | 48_2 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 100 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_13   |          | 48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 90 Octets (C.9)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_14   |          | 48_4 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 120 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_15   |          | 48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 117 Octets (C.9)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_16   |          | 48_6 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 155 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_36_17   |          | Vendor-specific Codec Config Setting (O)     |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF BAP 93/1 "Narrow Band (8 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.2: Optional IF BAP 93/1 "Narrow Band (8 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.3: Optional IF BAP 93/2 "Wideband (16 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.4: Optional IF BAP 93/3 "Semi-Superwideband (24 kHz)" AND BAP 94/1
  "7.5 ms", otherwise Excluded.
- C.5: Optional IF BAP 93/4 "Superwideband (32 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.6: Optional IF BAP 93/4 "Superwideband (32 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.7: Optional IF BAP 93/5 "Full Band (44.1 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.8: Optional IF BAP 93/5 "Full Band (44.1 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.9: Optional IF BAP 93/6 "Full Band (48 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.10: Optional IF BAP 93/6 "Full Band (48 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.11: Optional IF BAP 93/3 "Semi-Superwideband (24 kHz)" AND BAP 94/2
  "10 ms", otherwise Excluded.

**Table 37: Audio Capability Configuration Support Settings: Unicast Client is Audio Source**

Prerequisite: BAP 29/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_37_1    |          | 8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms    |
|                  |          | Frame Duration, 26 Octets (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_2    |          | 8_2 LC3: 8 kHz Sampling Frequency, 10 ms     |
|                  |          | Frame Duration, 30 Octets (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_3    |          | 16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 30 Octets (C.3)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_4    | x        | 16_2 LC3: 16 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 40 Octets (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_5    |          | 24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 45 Octets (C.4)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_6    |          | 24_2 LC3: 24 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 60 Octets (C.5)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_7    | x        | 32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 60 Octets (C.6)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_8    | x        | 32_2 LC3: 32 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 80 Octets (C.7)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_9    |          | 441_1 LC3: 44.1 kHz Sampling Frequency, 8.163|
|                  |          | ms Frame Duration, 97 Octets (C.8)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_10   |          | 441_2 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 10.884 ms Frame Duration, 130 Octets (C.9)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_11   | x        | 48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 75 Octets (C.10)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_12   | x        | 48_2 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 100 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_13   |          | 48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 90 Octets (C.10)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_14   | x        | 48_4 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 120 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_15   |          | 48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 117 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_16   |          | 48_6 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 155 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_37_17   |          | Vendor-specific Codec Config Setting: Unicast|
|                  |          | Client is Audio Source (O)                   |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF BAP 95/1 "Narrow Band (8 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.2: Optional IF BAP 95/1 "Narrow Band (8 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.3: Optional IF BAP 95/2 "Wideband (16 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.4: Optional IF BAP 95/3 "Semi-Superwideband (24 kHz)" AND BAP 96/1
  "7.5 ms", otherwise Excluded.
- C.5: Optional IF BAP 95/3 "Semi-Superwideband (24 kHz)" AND BAP 96/2
  "10 ms", otherwise Excluded.
- C.6: Optional IF BAP 95/4 "Superwideband (32 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.7: Optional IF BAP 95/4 "Superwideband (32 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.8: Optional IF BAP 95/5 "Full Band (44.1 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.9: Optional IF BAP 95/5 "Full Band (44.1 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.10: Optional IF BAP 95/6 "Full Band (48 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.11: Optional IF BAP 95/6 "Full Band (48 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.

**Table 38: QoS Configuration: LC3 Low Latency: Unicast Client is Audio Sink**

Prerequisite: BAP 29/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_38_1    |          | 8_1_1 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_2    |          | 8_2_1 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_3    |          | 16_1_1 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_4    | x        | 16_2_1 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_5    |          | 24_1_1 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_6    |          | 24_2_1 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.5)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_7    |          | 32_1_1 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_8    | x        | 32_2_1 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_9    |          | 441_1_1 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 5 RTN, 24 Max_Transport_Latency|
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_10   |          | 441_2_1 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 5 RTN, 31 Max_Transport_Latency|
|                  |          | (C.9)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_11   |          | 48_1_1 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.10)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_12   |          | 48_2_1 LC3: 10000 SDU Interval, unframed, 100|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.11)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_13   |          | 48_3_1 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.12)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_14   |          | 48_4_1 LC3: 10000 SDU Interval, unframed, 120|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.13)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_15   |          | 48_5_1 LC3: 7500 SDU Interval, unframed, 117 |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.14)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_38_16   |          | 48_6_1 LC3: 10000 SDU Interval, unframed, 155|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.15)                                       |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Optional IF BAP 36/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 36/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 36/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Mandatory IF BAP 36/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 36/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 36/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.7: Optional IF BAP 36/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.8: Optional IF BAP 36/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.9: Optional IF BAP 36/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884
  ms Frame Duration, 130 Octets", otherwise Excluded.
- C.10: Optional IF BAP 36/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.11: Optional IF BAP 36/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 100 Octets", otherwise Excluded.
- C.12: Optional IF BAP 36/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.13: Optional IF BAP 36/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 120 Octets", otherwise Excluded.
- C.14: Optional IF BAP 36/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.15: Optional IF BAP 36/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 155 Octets", otherwise Excluded.

**Table 39: QoS Configuration: LC3 Low Latency: Unicast Client is Audio Source**

Prerequisite: BAP 29/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_39_1    |          | 8_1_1 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_2    |          | 8_2_1 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_3    |          | 16_1_1 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_4    | x        | 16_2_1 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_5    |          | 24_1_1 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_6    |          | 24_2_1 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.5)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_7    |          | 32_1_1 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_8    | x        | 32_2_1 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 2 RTN, 10 Max_Transport_Latency|
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_9    |          | 441_1_1 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 5 RTN, 24 Max_Transport_Latency|
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_10   |          | 441_2_1 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 5 RTN, 31 Max_Transport_Latency|
|                  |          | (C.9)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_11   |          | 48_1_1 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.10)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_12   | x        | 48_2_1 LC3: 10000 SDU Interval, unframed, 100|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.11)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_13   |          | 48_3_1 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.12)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_14   | x        | 48_4_1 LC3: 10000 SDU Interval, unframed, 120|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.13)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_15   |          | 48_5_1 LC3: 7500 SDU Interval, unframed, 117 |
|                  |          | Max SDU Size, 5 RTN, 15 Max_Transport_Latency|
|                  |          | (C.14)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_39_16   |          | 48_6_1 LC3: 10000 SDU Interval, unframed, 155|
|                  |          | Max SDU Size, 5 RTN, 20 Max_Transport_Latency|
|                  |          | (C.15)                                       |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Optional IF BAP 37/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 37/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 37/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Mandatory IF BAP 37/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 37/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 37/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.7: Optional IF BAP 37/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.8: Optional IF BAP 37/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.9: Optional IF BAP 37/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884
  ms Frame Duration, 130 Octets", otherwise Excluded.
- C.10: Optional IF BAP 37/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.11: Optional IF BAP 37/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 100 Octets", otherwise Excluded.
- C.12: Optional IF BAP 37/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.13: Optional IF BAP 37/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 120 Octets", otherwise Excluded.
- C.14: Optional IF BAP 37/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.15: Optional IF BAP 37/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 155 Octets", otherwise Excluded.

**Table 40: QoS Configuration: LC3 High Reliability: Unicast Client is Audio Sink**

Prerequisite: BAP 29/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_40_1    |          | 8_1_2 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_2    |          | 8_2_2 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_3    |          | 16_1_2 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.3)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_4    |          | 16_2_2 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.16)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_5    |          | 24_1_2 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_6    |          | 24_2_2 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.5)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_7    |          | 32_1_2 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_8    |          | 32_2_2 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_9    |          | 441_1_2 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 13 RTN, 80                     |
|                  |          | Max_Transport_Latency (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_10   |          | 441_2_2 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 13 RTN, 85                     |
|                  |          | Max_Transport_Latency (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_11   | x        | 48_1_2 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_12   | x        | 48_2_2 LC3: 10000 SDU Interval, unframed, 100|
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_13   |          | 48_3_2 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.12)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_14   |          | 48_4_2 LC3: 10000 SDU Interval, unframed, 120|
|                  |          | Max SDU Size, 13 RTN, 100                    |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_15   |          | 48_5_2 LC3: 7500 SDU Interval, unframed, 117 |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_40_16   |          | 48_6_2 LC3: 10000 SDU Interval, unframed, 155|
|                  |          | Max SDU Size, 13 RTN, 100                    |
|                  |          | Max_Transport_Latency (C.15)                 |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF BAP 36/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 36/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 36/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Optional IF BAP 36/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 36/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 36/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.7: Optional IF BAP 36/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.8: Mandatory IF BAP 36/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.9: Mandatory IF BAP 36/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884
  ms Frame Duration, 130 Octets", otherwise Excluded.
- C.10: Mandatory IF BAP 36/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.11: Mandatory IF BAP 36/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 100 Octets", otherwise Excluded.
- C.12: Mandatory IF BAP 36/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.13: Mandatory IF BAP 36/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 120 Octets", otherwise Excluded.
- C.14: Mandatory IF BAP 36/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.15: Mandatory IF BAP 36/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 155 Octets", otherwise Excluded.
- C.16: Optional IF BAP 36/4 "16_2 LC3: 16 kHz Sampling Frequency, 10 ms
  Frame Duration, 40 Octets", otherwise Excluded.

**Table 41: QoS Configuration: LC3 High Reliability: Unicast Client is Audio Source**

Prerequisite: BAP 29/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_41_1    |          | 8_1_2 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_2    |          | 8_2_2 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_3    |          | 16_1_2 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.3)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_4    |          | 16_2_2 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.15)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_5    |          | 24_1_2 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_6    |          | 24_2_2 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.16)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_7    |          | 32_1_2 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.5)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_8    |          | 32_2_2 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_9    |          | 441_1_2 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 13 RTN, 80                     |
|                  |          | Max_Transport_Latency (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_10   |          | 441_2_2 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 13 RTN, 85                     |
|                  |          | Max_Transport_Latency (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_11   | x        | 48_1_2 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_12   | x        | 48_2_2 LC3: 10000 SDU Interval, unframed, 100|
|                  |          | Max SDU Size, 13 RTN, 95                     |
|                  |          | Max_Transport_Latency (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_13   |          | 48_3_2 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_14   | x        | 48_4_2 LC3: 10000 SDU Interval, unframed, 120|
|                  |          | Max SDU Size, 13 RTN, 100                    |
|                  |          | Max_Transport_Latency (C.12)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_15   |          | 48_5_2 LC3: 7500 SDU Interval, unframed, 117 |
|                  |          | Max SDU Size, 13 RTN, 75                     |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_41_16   |          | 48_6_2 LC3: 10000 SDU Interval, unframed, 155|
|                  |          | Max SDU Size, 13 RTN, 100                    |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF BAP 37/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 37/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 37/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Optional IF BAP 37/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 37/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 37/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.7: Mandatory IF BAP 37/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.8: Mandatory IF BAP 37/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884
  ms Frame Duration, 130 Octets", otherwise Excluded.
- C.9: Mandatory IF BAP 37/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.10: Mandatory IF BAP 37/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 100 Octets", otherwise Excluded.
- C.11: Mandatory IF BAP 37/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.12: Mandatory IF BAP 37/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 120 Octets", otherwise Excluded.
- C.13: Mandatory IF BAP 37/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.14: Mandatory IF BAP 37/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 155 Octets", otherwise Excluded.
- C.15: Optional IF BAP 37/4 "16_2 LC3: 16 kHz Sampling Frequency, 10 ms Frame
  Duration, 40 Octets", otherwise Excluded.
- C.16: Optional IF BAP 37/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.

**Table 42: QoS Configuration: Vendor-Specific Codec: Unicast Client is Audio Sink**

Prerequisite: BAP 29/1 "Audio Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_42_1    |          | Vendor-specific QoS Config Setting: Unicast  |
|                  |          | Client is Audio Sink (C.1)                   |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 36/17 "Vendor-specific Codec Config Setting",
  otherwise Excluded.

**Table 43: QoS Configuration: Vendor-Specific Codec: Unicast Client is Audio Source**

Prerequisite: BAP 29/2 "Audio Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_43_1    |          | Vendor-specific QoS Config Setting: Unicast  |
|                  |          | Client is Audio Source (C.1)                 |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 37/17 "Vendor-specific Codec Config Setting: Unicast
  Client is Audio Source", otherwise Excluded.

**Table 44: LC3 Audio Configuration: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_44_1    | x        | AC 1: 1 Server, 1 Sink ASE, 1 Channel/Sink,  |
|                  |          | 1 CIS, 1 Audio Stream (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_2    | x        | AC 2: 1 Server, 1 Source ASE,                |
|                  |          | 1 Channel/Source, 1 CIS, 1 Audio Stream (C.2)|
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_3    | x        | AC 3: 1 Server, 1 Sink ASE, 1 Channel/Sink,  |
|                  |          | 1 CIS, 2 Audio Streams (C.3)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_4    | x        | AC 4: 1 Server, 1 Sink ASE, 2 Channels/Sink, |
|                  |          | 1 CIS, 1 Audio Stream (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_5    |          | AC 5: 1 Server, 1 Sink ASE, 1 Source ASE, 2  |
|                  |          | Channels/Sink, 1 Channel/Source, 1, CIS, 2   |
|                  |          | Audio Streams (C.7)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_6    | x        | AC 6i: 1 Server, 2 Sink ASEs, 1 Channel/Sink,|
|                  |          | 2 CISes, 2 Audio Streams (C.1)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_7    | x        | AC 6ii: 2 Servers, 2 Sink ASEs, 1            |
|                  |          | Channel/Sink, 2 CISes, 2 Audio Streams (C.1) |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_8    |          | AC 7i: 1 Server, 1 Sink ASE, 1 Source ASE, 1 |
|                  |          | Channel/Sink, 1 Channel/Source, 2 CISes, 2   |
|                  |          | Audio Streams (C.5)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_9    | x        | AC 7ii: 2 Servers, 1 Sink ASE, 1 Source ASE, |
|                  |          | 1 Channel/Sink, 1 Channel/Source, 2 CISes, 2 |
|                  |          | Audio Streams (C.3)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_10   |          | AC 8i: 1 Server, 2 Sink ASEs, 1 Source ASE, 1|
|                  |          | Channel/Sink, 1 Channel/Source, 2 CISes, 3   |
|                  |          | Audio Streams (C.5, C.8)                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_11   |          | AC 8ii: 2 Servers, 2 Sink ASEs, 1 Source ASE,|
|                  |          | 1 Channel/Sink, 1 Channel/Source, 2 CISes, 3 |
|                  |          | Audio Streams (C.5, C.9)                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_12   | x        | AC 9i: 1 Server, 2 Source ASEs, 1            |
|                  |          | Channel/Source, 2 CISes, 2 Audio Streams     |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_13   | x        | AC 9ii: 2 Servers, 2 Source ASEs, 1          |
|                  |          | Channel/Source, 2 CISes, 2 Audio Streams     |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_14   |          | AC 10: 1 Server, 1 Source ASE, 2             |
|                  |          | Channels/Source, 1 CIS, 1 Audio Stream (C.6) |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_15   |          | AC 11i: 1 Server, 2 Sink ASEs, 2 Source ASEs,|
|                  |          | 1 Channel/Sink, 1 Channel/Source, 2 CISes,   |
|                  |          | 4 Audio Streams (C.5, C.10)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_44_16   |          | AC 11ii: 2 Servers, 2 Sink ASEs, 2 Source    |
|                  |          | ASEs, 1 Channel/Sink, 1 Channel/Source, 2    |
|                  |          | CISes, 4 Audio Streams (C.5, C.11)           |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 29/2 "Audio Source", otherwise Excluded.
- C.2: Mandatory IF BAP 29/1 "Audio Sink", otherwise Excluded.
- C.3: Mandatory IF BAP 29/1 "Audio Sink" AND BAP 29/2 "Audio Source",
  otherwise Excluded.
- C.4: Optional IF BAP 29/2 "Audio Source" AND BAP 30/3 "Two Audio Channels",
  otherwise Excluded.
- C.5: Optional IF BAP 29/1 "Audio Sink" AND BAP 29/2 "Audio Source",
  otherwise Excluded.
- C.6: Optional IF BAP 29/1 "Audio Sink" AND BAP 30/3 "Two Audio Channels",
  otherwise Excluded.
- C.7: Optional IF BAP 29/1 "Audio Sink" AND BAP 29/2 "Audio Source" AND BAP
  30/3 "Two Audio Channels", otherwise Excluded.
- C.8: Mandatory IF BAP 44/11 "AC 8ii: 2 Servers, 2 Sink ASEs, 1 Source ASE,
  1 Channel/Sink, 1 Channel/Source, 2 CISes, 3 Audio Streams", otherwise
  Excluded.
- C.9: Mandatory IF BAP 44/10 "AC 8i: 1 Server, 2 Sink ASEs, 1 Source ASE, 1
  Channel/Sink, 1 Channel/Source, 2 CISes, 3 Audio Streams", otherwise
  Excluded.
- C.10: Mandatory IF BAP 44/16 "AC 11ii: 2 Servers, 2 Sink ASEs, 2 Source
  ASEs, 1 Channel/Sink, 1 Channel/Source, 2 CISes, 4 Audio Streams",
  otherwise Excluded.
- C.11: Mandatory IF BAP 44/15 "AC 11i: 1 Server, 2 Sink ASEs, 2 Source ASEs,
  1 Channel/Sink, 1 Channel/Source, 2 CISes, 4 Audio Streams", otherwise
  Excluded.

GATT requirements
-----------------

**Table 45: GATT Requirements: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_45_1    | x        | Discover All Primary Services (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_2    | x        | Discover Primary Service by Service UUID     |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_3    |          | Find Included Services (O)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_4    | x        | Discover All Characteristics of a Service    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_5    | x        | Discover Characteristics by UUID (C.2)       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_6    | x        | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_7    | x        | Read Characteristic Value (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_8    | x        | Write Without Response (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_9    | x        | Write Characteristic Value (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_10   | x        | Write Long Characteristic Value (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_11   | x        | Single Notification (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_12   | x        | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_13   | x        | Write Characteristic Descriptor (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_14   | x        | Exchange MTU (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_15   |          | GATT Client over BR/EDR (C.3)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_45_16   | x        | GATT Client over LE (M)                      |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one.
- C.2: Mandatory to support at least one.
- C.3: Mandatory IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.

GAP requirements
----------------

**Table 46: GAP Requirements: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_46_1    | x        | Central (M)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_2    | x        | Bondable mode (LE) (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_3    | x        | Bonding procedure (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_4    | x        | LE security mode 1 (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_5    | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (M)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_6    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_7    |          | Security mode 4, level 2 (C.3)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_8    |          | 128-bit encryption key size capable          |
|                  |          | (BR/EDR) (C.3)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_9    | x        | Minimum 128 Bit entropy key (LE) (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_10   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_11   | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_12   |          | CoD Major Service Class bit 14 (C.3)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_13   |          | BR/EDR Secure Connections (C.7)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_14   | x        | LE Secure Connections (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_15   | x        | Out of Band (Central) (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_16   |          | Out-of-Band (BR/EDR) (C.7)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_46_17   |          | LE security mode 1 level 4 (O)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1-C.2: No longer used.
- C.3: Mandatory IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.
- C.4-C.5: No longer used.
- C.6: Mandatory to support at least one.
- C.7: Mandatory to support at least one IF BAP 3/2 "GAP BR/EDR Host",
  otherwise not defined.

**Table 47: No longer used**

LL requirements
---------------

**Table 48: LL Requirements: Unicast Client**

Prerequisite: BAP 1/2 "Unicast Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_48_1    | x        | LE Encryption (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_48_2    | x        | LE Extended Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_48_3    | x        | Connected Isochronous Stream - Central (M)   |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Broadcast Source requirements
=============================

**Table 49: Broadcast Source, X.Y Versions**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_49_1    | x        | BAP v1.0 (C.1, C.2)                          |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory.
- C.2: Can only be supported with an active X.Y.Z version after Deprecation
  or Withdrawal.
  Deprecated 2025-02-01. Withdrawn 2027-02-01.

**Table 50: Broadcast Source, X.Y.Z Versions**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_50_1    |          | BAP v1.0.1 (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_50_2    | x        | BAP v1.0.2 (C.1)                             |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support one and only one.

**Table 51: Broadcast Source: Service Support Requirements**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_51_1    |          | Broadcast Audio Stream Metadata Update (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_51_2    |          | Broadcast Audio Stream Reconfiguration (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_51_3    | x        | Broadcast Audio Stream Establishment (M)     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_51_4    | x        | Broadcast Audio Stream Disable (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_51_5    | x        | Broadcast Audio Stream Release (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_51_6    | x        | Broadcast Audio Announcement Service UUID (M)|
+------------------+----------+----------------------------------------------+
| TSPC_BAP_51_7    |          | Multiple BIG Support (O)                     |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

Audio Capability Support requirements
-------------------------------------

**Table 52: Codec Specific Configuration LTV Structures: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_52_1    | x        | Sampling_Frequency (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_52_2    | x        | Frame_Duration (M)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_52_3    |          | Audio_Channel_Allocation (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_52_4    | x        | Octets_Per_Codec_Frame (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_52_5    |          | Codec_Frame_Blocks_Per_SDU (O)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 53: Metadata LTV Structures: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_53_1    | x        | Streaming_Audio_Contexts (M)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_53_2    |          | Vendor-specific Metadata (O)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 54: Audio Capability Configuration Support Settings: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_54_1    |          | 8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms    |
|                  |          | Frame Duration, 26 Octets (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_2    |          | 8_2 LC3: 8 kHz Sampling Frequency, 10 ms     |
|                  |          | Frame Duration, 30 Octets (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_3    |          | 16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 30 Octets (C.3)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_4    | x        | 16_2 LC3: 16 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 40 Octets (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_5    |          | 24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 45 Octets (C.4)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_6    |          | 24_2 LC3: 24 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 60 Octets (C.5)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_7    |          | 32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 60 Octets (C.6)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_8    |          | 32_2 LC3: 32 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 80 Octets (C.7)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_9    |          | 441_1 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 8.163 ms Frame Duration, 97 Octets (C.8)     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_10   |          | 441_2 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 10.884 ms Frame Duration, 130 Octets (C.9)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_11   | x        | 48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 75 Octets (C.10)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_12   | x        | 48_2 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 100 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_13   | x        | 48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 90 Octets (C.10)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_14   | x        | 48_4 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 120 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_15   |          | 48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 117 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_16   |          | 48_6 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 155 Octets (C.11)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_54_17   |          | Vendor-specific Codec Configuration Setting  |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF BAP 95/1 "Narrow Band (8 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.2: Optional IF BAP 95/1 "Narrow Band (8 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.3: Optional IF BAP 95/2 "Wideband (16 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.4: Optional IF BAP 95/3 "Semi-Superwideband (24 kHz)" AND BAP 96/1
  "7.5 ms", otherwise Excluded.
- C.5: Optional IF BAP 95/3 "Semi-Superwideband (24 kHz)" AND BAP 96/2
  "10 ms", otherwise Excluded.
- C.6: Optional IF BAP 95/4 "Superwideband (32 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.7: Optional IF BAP 95/4 "Superwideband (32 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.8: Optional IF BAP 95/5 "Full Band (44.1 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.9: Optional IF BAP 95/5 "Full Band (44.1 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.
- C.10: Optional IF BAP 95/6 "Full Band (48 kHz)" AND BAP 96/1 "7.5 ms",
  otherwise Excluded.
- C.11: Optional IF BAP 95/6 "Full Band (48 kHz)" AND BAP 96/2 "10 ms",
  otherwise Excluded.

**Table 55: QoS Requirements: LC3 Low Latency: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_55_1    |          | 8_1_1 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_2    |          | 8_2_1 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 10                      |
|                  |          | Max_Transport_Latency (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_3    |          | 16_1_1 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.3)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_4    | x        | 16_2_1 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 2 RTN, 10                      |
|                  |          | Max_Transport_Latency (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_5    |          | 24_1_1 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_6    |          | 24_2_1 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 2 RTN, 10                      |
|                  |          | Max_Transport_Latency (C.5)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_7    |          | 32_1_1 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 2 RTN, 8 Max_Transport_Latency |
|                  |          | (C.6)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_8    |          | 32_2_1 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 2 RTN, 10                      |
|                  |          | Max_Transport_Latency (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_9    |          | 441_1_1 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 4 RTN, 24                      |
|                  |          | Max_Transport_Latency (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_10   |          | 441_2_1 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 4 RTN, 31                      |
|                  |          | Max_Transport_Latency (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_11   | x        | 48_1_1 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 4 RTN, 15                      |
|                  |          | Max_Transport_Latency (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_12   | x        | 48_2_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 100 Max SDU Size, 4 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_13   | x        | 48_3_1 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 4 RTN, 15                      |
|                  |          | Max_Transport_Latency (C.12)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_14   | x        | 48_4_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 120 Max SDU Size, 4 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_15   |          | 48_5_1 LC3: 7500 SDU Interval, unframed,     |
|                  |          | 117 Max SDU Size, 4 RTN, 15                  |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_55_16   |          | 48_6_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 155 Max SDU Size, 4 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.15)                 |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF BAP 54/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 54/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 54/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Optional IF BAP 54/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.5: Mandatory IF BAP 54/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 54/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.7: Optional IF BAP 54/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.8: Optional IF BAP 54/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.9: Optional IF BAP 54/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884
  ms Frame Duration, 130 Octets", otherwise Excluded.
- C.10: Optional IF BAP 54/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.11: Optional IF BAP 54/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 100 Octets", otherwise Excluded.
- C.12: Optional IF BAP 54/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.13: Optional IF BAP 54/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 120 Octets", otherwise Excluded.
- C.14: Optional IF BAP 54/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.15: Optional IF BAP 54/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 155 Octets", otherwise Excluded.

**Table 56: QoS Configuration: LC3 High Reliability: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_56_1    |          | 8_1_2 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 4 RTN, 45                      |
|                  |          | Max_Transport_Latency (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_2    |          | 8_2_2 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_3    |          | 16_1_2 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 4 RTN, 45                      |
|                  |          | Max_Transport_Latency (C.3)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_4    | x        | 16_2_2 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_5    |          | 24_1_2 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 4 RTN, 45                      |
|                  |          | Max_Transport_Latency (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_6    |          | 24_2_2 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (C.15)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_7    |          | 32_1_2 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 4 RTN, 45                      |
|                  |          | Max_Transport_Latency (C.5)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_8    |          | 32_2_2 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_9    |          | 441_1_2 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 4 RTN, 54                      |
|                  |          | Max_Transport_Latency (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_10   |          | 441_2_2 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_11   | x        | 48_1_2 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 4 RTN, 50                      |
|                  |          | Max_Transport_Latency (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_12   | x        | 48_2_2 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 100 Max SDU Size, 4 RTN, 65                  |
|                  |          | Max_Transport_Latency (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_13   | x        | 48_3_2 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 4 RTN, 50                      |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_14   | x        | 48_4_2 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 120 Max SDU Size, 4 RTN, 65                  |
|                  |          | Max_Transport_Latency (C.12)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_15   |          | 48_5_2 LC3: 7500 SDU Interval, unframed,     |
|                  |          | 117 Max SDU Size, 4 RTN, 50                  |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_56_16   |          | 48_6_2 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 155 Max SDU Size, 4 RTN, 65                  |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF BAP 54/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 54/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 54/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Optional IF BAP 54/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 54/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 54/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.7: Optional IF BAP 54/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.8: Optional IF BAP 54/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884 ms
  Frame Duration, 130 Octets", otherwise Excluded.
- C.9: Optional IF BAP 54/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 75 Octets", otherwise Excluded.
- C.10: Optional IF BAP 54/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 100 Octets", otherwise Excluded.
- C.11: Optional IF BAP 54/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 90 Octets", otherwise Excluded.
- C.12: Optional IF BAP 54/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 120 Octets", otherwise Excluded.
- C.13: Optional IF BAP 54/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 117 Octets", otherwise Excluded.
- C.14: Optional IF BAP 54/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 155 Octets", otherwise Excluded.
- C.15: Mandatory IF BAP 54/6 "24_2 LC3: 24 kHz Sampling Frequency, 10 ms Frame
  Duration, 60 Octets", otherwise Excluded.

**Table 57: QoS Configuration: Vendor-Specific Codec: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_57_1    |          | Vendor-specific QoS Config Setting:          |
|                  |          | Broadcast Source (C.1)                       |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 54/17 "Vendor-specific Codec Configuration Setting",
  otherwise Excluded.

**Table 58: LC3 Audio Configuration: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_58_1    | x        | AC12: 1 BIS, Single Audio Channel/BIS, 1     |
|                  |          | Audio Stream (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_58_2    | x        | AC13: 2 BISes, Single Audio Channel/BIS, 2   |
|                  |          | Audio Streams (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_58_3    |          | AC14: 1 BIS, Multiple Audio Channels/BIS, 1  |
|                  |          | Audio Stream (O)                             |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

Context Type requirements
-------------------------

**Table 59: Supported Sink Context Requirements: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_59_1    | x        | Unspecified (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_2    |          | Conversational (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_3    |          | Media (O)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_4    |          | Game (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_5    |          | Instructional (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_6    |          | Voice assistants (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_7    |          | Live (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_8    |          | Sound effects (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_9    |          | Notifications (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_10   |          | Ringtone (O)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_11   |          | Alerts (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_59_12   |          | Emergency Alarm (O)                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

GAP requirements
----------------

**Table 60: GAP Requirements: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_60_1    | x        | Broadcaster (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_60_2    | x        | LE security mode 3 level 1 (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_60_3    | x        | LE security mode 3 level 2 (C.1)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_60_4    |          | LE security mode 3 level 3 (C.2)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_60_5    |          | CoD Major Service Class bit 14 (C.3)         |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF BAP 61/6 "Encrypted Broadcast Isochronous Stream",
  otherwise not defined.
- C.2: Optional IF BAP 61/6 "Encrypted Broadcast Isochronous Stream",
  otherwise not defined.
- C.3: Mandatory IF BAP 3/2 "GAP BR/EDR Host", otherwise Excluded.

**Table 61: Link Layer Requirements: Broadcast Source**

Prerequisite: BAP 1/3 "Broadcast Source"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_61_1    | x        | LE Encryption (C.1)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_61_2    | x        | LE Extended Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_61_3    | x        | LE Periodic Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_61_4    | x        | Isochronous Broadcaster (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_61_5    | x        | Unencrypted Broadcast Isochronous Stream     |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_61_6    | x        | Encrypted Broadcast Isochronous Stream       |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF BAP 61/6 "Encrypted Broadcast Isochronous Stream",
  otherwise not defined.
- C.2: Mandatory to support at least one.


Broadcast Sink requirements
===========================

**Table 62: Broadcast Sink, X.Y Versions**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_62_1    | x        | BAP v1.0 (C.1, C.2)                          |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory.
- C.2: Can only be supported with an active X.Y.Z version after Deprecation
  or Withdrawal.
  Deprecated 2025-02-01. Withdrawn 2027-02-01.

**Table 63: Broadcast Sink, X.Y.Z Versions**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_63_1    |          | BAP v1.0.1 (C.3)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_63_2    |          | No longer used                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_63_3    | x        | BAP v1.0.2 (C.3)                             |
+------------------+----------+----------------------------------------------+

- C.1-C.2: No longer used.
- C.3: Mandatory to support one and only one.

**Table 64: Broadcast Sink: Support Requirements**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_64_1    |          | PACS supported over BR/EDR (C.1, C.2)        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_64_2    | x        | PACS supported over LE (C.1)                 |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.
- C.2: Optional IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.

Audio Capability Support requirements
-------------------------------------

**Table 65: Codec Specific Capabilities LTV Structures: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_65_1    | x        | Supported Sampling Frequencies (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_65_2    | x        | Supported Frame Durations (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_65_3    | x        | Supported Octets per Codec Frame (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_65_4    | x        | Supported Audio Channel Counts (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_65_5    | x        | Supported Max Codec Frames Per SDU (M)       |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 66: Codec Specific Audio Capability Support: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_66_1    |          | Multiple Audio Locations (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_66_2    |          | Two Audio Channels (O)                       |
+------------------+----------+----------------------------------------------+

- O: Optional

**Table 67: Metadata LTV Structures: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_67_1    |          | Preferred_Audio_Contexts (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_67_2    | x        | Streaming_Audio_Contexts (M)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_67_3    |          | Vendor-specific Metadata (O)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

**Table 68: Audio Capability Support Settings: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_68_1    |          | 8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms    |
|                  |          | Frame Duration, 26 Octets (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_2    |          | 8_2 LC3: 8 kHz Sampling Frequency, 10 ms     |
|                  |          | Frame Duration, 30 Octets (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_3    |          | 16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 30 Octets (C.3)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_4    | x        | 16_2 LC3: 16 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 40 Octets (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_5    |          | 24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 45 Octets (C.4)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_6    | x        | 24_2 LC3: 24 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 60 Octets (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_7    |          | 32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 60 Octets (C.5)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_8    |          | 32_2 LC3: 32 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 80 Octets (C.6)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_9    |          | 441_1 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 8.163 ms Frame Duration, 97 Octets (C.7)     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_10   |          | 441_2 LC3: 44.1 kHz Sampling Frequency,      |
|                  |          | 10.884 ms Frame Duration, 130 Octets (C.8)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_11   | x        | 48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 75 Octets (C.9)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_12   | x        | 48_2 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 100 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_13   | x        | 48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 90 Octets (C.9)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_14   | x        | 48_4 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 120 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_15   | x        | 48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms  |
|                  |          | Frame Duration, 117 Octets (C.9)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_16   | x        | 48_6 LC3: 48 kHz Sampling Frequency, 10 ms   |
|                  |          | Frame Duration, 155 Octets (C.10)            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_68_17   |          | Vendor-specific Codec Capability Setting:    |
|                  |          | Broadcast Sink (O)                           |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Optional IF BAP 93/1 "Narrow Band (8 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.2: Optional IF BAP 93/1 "Narrow Band (8 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.3: Optional IF BAP 93/2 "Wideband (16 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.4: Optional IF BAP 93/3 "Semi-Superwideband (24 kHz)" AND BAP 94/1
  "7.5 ms", otherwise Excluded.
- C.5: Optional IF BAP 93/4 "Superwideband (32 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.6: Optional IF BAP 93/4 "Superwideband (32 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.7: Optional IF BAP 93/5 "Full Band (44.1 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.8: Optional IF BAP 93/5 "Full Band (44.1 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.
- C.9: Optional IF BAP 93/6 "Full Band (48 kHz)" AND BAP 94/1 "7.5 ms",
  otherwise Excluded.
- C.10: Optional IF BAP 93/6 "Full Band (48 kHz)" AND BAP 94/2 "10 ms",
  otherwise Excluded.

**Table 69: QoS Requirements: LC3 Low Latency: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_69_1    |          | 8_1_1 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 2 RTN, 8                       |
|                  |          | Max_Transport_Latency (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_2    |          | 8_2_1 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 10                      |
|                  |          | Max_Transport_Latency (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_3    |          | 16_1_1 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 2 RTN, 8                       |
|                  |          | Max_Transport_Latency (C.3)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_4    | x        | 16_2_1 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 2 RTN, 10                      |
|                  |          | Max_Transport_Latency (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_5    |          | 24_1_1 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 2 RTN, 8                       |
|                  |          | Max_Transport_Latency (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_6    | x        | 24_2_1 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 2 RTN, 10                      |
|                  |          | Max_Transport_Latency (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_7    |          | 32_1_1 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 2 RTN, 8                       |
|                  |          | Max_Transport_Latency (C.5)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_8    |          | 32_2_1 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 2 RTN, 10                      |
|                  |          | Max_Transport_Latency (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_9    |          | 441_1_1 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 4 RTN, 24                      |
|                  |          | Max_Transport_Latency (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_10   |          | 441_2_1 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 4 RTN, 31                      |
|                  |          | Max_Transport_Latency (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_11   | x        | 48_1_1 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 4 RTN, 15                      |
|                  |          | Max_Transport_Latency (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_12   | x        | 48_2_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 100 Max SDU Size, 4 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_13   | x        | 48_3_1 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 4 RTN, 15                      |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_14   | x        | 48_4_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 120 Max SDU Size, 4 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.12)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_15   | x        | 48_5_1 LC3: 7500 SDU Interval, unframed,     |
|                  |          | 117 Max SDU Size, 4 RTN, 15                  |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_69_16   | x        | 48_6_1 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 155 Max SDU Size, 4 RTN, 20                  |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Optional IF BAP 68/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 68/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 68/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Mandatory IF BAP 68/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 68/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 68/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.7: Optional IF BAP 68/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.8: Optional IF BAP 68/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884
  ms Frame Duration, 130 Octets", otherwise Excluded.
- C.9: Optional IF BAP 68/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 75 Octets", otherwise Excluded.
- C.10: Optional IF BAP 68/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 100 Octets", otherwise Excluded.
- C.11: Optional IF BAP 68/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 90 Octets", otherwise Excluded.
- C.12: Optional IF BAP 68/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 120 Octets", otherwise Excluded.
- C.13: Optional IF BAP 68/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms
  Frame Duration, 117 Octets", otherwise Excluded.
- C.14: Optional IF BAP 68/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms
  Frame Duration, 155 Octets", otherwise Excluded.

**Table 70: QoS Configuration: LC3 High Reliability: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_70_1    |          | 8_1_2 LC3: 7500 SDU Interval, unframed, 26   |
|                  |          | Max SDU Size, 4 RTN, 45                      |
|                  |          | Max_Transport_Latency (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_2    |          | 8_2_2 LC3: 10000 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (C.2)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_3    |          | 16_1_2 LC3: 7500 SDU Interval, unframed, 30  |
|                  |          | Max SDU Size, 4 RTN, 45                      |
|                  |          | Max_Transport_Latency (C.3)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_4    | x        | 16_2_2 LC3: 10000 SDU Interval, unframed, 40 |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_5    |          | 24_1_2 LC3: 7500 SDU Interval, unframed, 45  |
|                  |          | Max SDU Size, 4 RTN, 45                      |
|                  |          | Max_Transport_Latency (C.4)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_6    | x        | 24_2_2 LC3: 10000 SDU Interval, unframed, 60 |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_7    |          | 32_1_2 LC3: 7500 SDU Interval, unframed, 60  |
|                  |          | Max SDU Size, 4 RTN, 45                      |
|                  |          | Max_Transport_Latency (C.5)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_8    |          | 32_2_2 LC3: 10000 SDU Interval, unframed, 80 |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (C.6)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_9    |          | 441_1_2 LC3: 8163 SDU Interval, framed, 97   |
|                  |          | Max SDU Size, 4 RTN, 54                      |
|                  |          | Max_Transport_Latency (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_10   |          | 441_2_2 LC3: 10884 SDU Interval, framed, 130 |
|                  |          | Max SDU Size, 4 RTN, 60                      |
|                  |          | Max_Transport_Latency (C.8)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_11   | x        | 48_1_2 LC3: 7500 SDU Interval, unframed, 75  |
|                  |          | Max SDU Size, 4 RTN, 50                      |
|                  |          | Max_Transport_Latency (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_12   | x        | 48_2_2 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 100 Max SDU Size, 4 RTN, 65                  |
|                  |          | Max_Transport_Latency (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_13   | x        | 48_3_2 LC3: 7500 SDU Interval, unframed, 90  |
|                  |          | Max SDU Size, 4 RTN, 50                      |
|                  |          | Max_Transport_Latency (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_14   | x        | 48_4_2 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 120 Max SDU Size, 4 RTN, 65                  |
|                  |          | Max_Transport_Latency (C.12)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_15   | x        | 48_5_2 LC3: 7500 SDU Interval, unframed,     |
|                  |          | 117 Max SDU Size, 4 RTN, 50                  |
|                  |          | Max_Transport_Latency (C.13)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_70_16   | x        | 48_6_2 LC3: 10000 SDU Interval, unframed,    |
|                  |          | 155 Max SDU Size, 4 RTN, 65                  |
|                  |          | Max_Transport_Latency (C.14)                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Optional IF BAP 68/1 "8_1 LC3: 8 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 26 Octets", otherwise Excluded.
- C.2: Optional IF BAP 68/2 "8_2 LC3: 8 kHz Sampling Frequency, 10 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.3: Optional IF BAP 68/3 "16_1 LC3: 16 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 30 Octets", otherwise Excluded.
- C.4: Optional IF BAP 68/5 "24_1 LC3: 24 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 45 Octets", otherwise Excluded.
- C.5: Optional IF BAP 68/7 "32_1 LC3: 32 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 60 Octets", otherwise Excluded.
- C.6: Optional IF BAP 68/8 "32_2 LC3: 32 kHz Sampling Frequency, 10 ms Frame
  Duration, 80 Octets", otherwise Excluded.
- C.7: Optional IF BAP 68/9 "441_1 LC3: 44.1 kHz Sampling Frequency, 8.163 ms
  Frame Duration, 97 Octets", otherwise Excluded.
- C.8: Optional IF BAP 68/10 "441_2 LC3: 44.1 kHz Sampling Frequency, 10.884 ms
  Frame Duration, 130 Octets", otherwise Excluded.
- C.9: Optional IF BAP 68/11 "48_1 LC3: 48 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 75 Octets", otherwise Excluded.
- C.10: Optional IF BAP 68/12 "48_2 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 100 Octets", otherwise Excluded.
- C.11: Optional IF BAP 68/13 "48_3 LC3: 48 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 90 Octets", otherwise Excluded.
- C.12: Optional IF BAP 68/14 "48_4 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 120 Octets", otherwise Excluded.
- C.13: Optional IF BAP 68/15 "48_5 LC3: 48 kHz Sampling Frequency, 7.5 ms Frame
  Duration, 117 Octets", otherwise Excluded.
- C.14: Optional IF BAP 68/16 "48_6 LC3: 48 kHz Sampling Frequency, 10 ms Frame
  Duration, 155 Octets", otherwise Excluded.

**Table 71: QoS Configuration: Vendor-Specific Codec: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_71_1    |          | Vendor-specific QoS Config Setting:          |
|                  |          | Broadcast Sink (C.1)                         |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF BAP 68/17 "Vendor-specific Codec Capability Setting:
  Broadcast Sink", otherwise Excluded.

**Table 72: LC3 Audio Configuration: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_72_1    | x        | AC12: 1 BIS, Single Audio Channel/BIS, 1     |
|                  |          | Audio Stream (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_72_2    |          | AC13: 2 BISes, Single Audio Channel/BIS, 2   |
|                  |          | Audio Streams (C.1)                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_72_3    |          | AC14: 1 BIS, Multiple Audio Channels/BIS, 1  |
|                  |          | Audio Stream (C.2)                           |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Mandatory IF BAP 66/1 "Multiple Audio Locations", otherwise Excluded.
- C.2: Mandatory IF BAP 66/1 "Multiple Audio Locations" AND BAP 66/2
  "Two Audio Channels", otherwise Excluded.

Context Type requirements
-------------------------

**Table 73: Supported Sink Context Requirements: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_73_1    | x        | Unspecified (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_2    |          | Conversational (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_3    | x        | Media (O)                                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_4    |          | Game (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_5    |          | Instructional (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_6    |          | Voice assistants (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_7    |          | Live (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_8    |          | Sound effects (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_9    |          | Notifications (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_10   |          | Ringtone (O)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_11   |          | Alerts (O)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_73_12   |          | Emergency Alarm (O)                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

GAP requirements
----------------

**Table 74: GAP Requirements: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_74_1    | x        | Observer (M)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_2    |          | Central (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_3    | x        | Peripheral (M)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_4    | x        | Bondable mode (LE) (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_5    |          | Bondable mode (BR/EDR) (C.6)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_6    | x        | Bonding procedure (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_7    | x        | LE security mode 1 (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_8    | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (M)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_9    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_10   | x        | LE security mode 3 level 1 (C.4)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_11   | x        | LE security mode 3 level 2 (C.4)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_12   |          | LE security mode 3 level 3 (C.5)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_13   |          | Security mode 4, level 2 (C.6)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_14   |          | 128-bit encryption key size capable          |
|                  |          | (BR/EDR) (C.6)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_15   | x        | Minimum 128 Bit entropy key (LE) (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_16   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.11)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_17   | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.10)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_18   |          | CoD Major Service Class bit 14 (C.6)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_19   |          | Limited discoverable mode (C.9)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_20   |          | General discoverable mode (BR/EDR) (C.9)     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_21   |          | BR/EDR Secure Connections (C.11)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_22   | x        | LE Secure Connections (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_23   | x        | Out of Band (LE) (C.10)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_24   |          | Out-of-Band (BR/EDR) (C.11)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_74_25   |          | LE security mode 1 level 4 (O)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1-C.3: No longer used.
- C.4: Mandatory IF BAP 74/1 "Observer", otherwise not defined.
- C.5: Optional IF BAP 74/1 "Observer", otherwise not defined.
- C.6: Mandatory IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.
- C.7-C.8: No longer used.
- C.9: Mandatory to support at least one IF BAP 3/2 "GAP BR/EDR Host",
  otherwise not defined.
- C.10: Mandatory to support at least one.
- C.11: Mandatory to support at least one IF BAP 3/2 "GAP BR/EDR Host",
  otherwise not defined.

**Table 75: No longer used**

LL requirements
---------------

**Table 76: LL Requirements: Broadcast Sink**

Prerequisite: BAP 1/4 "Broadcast Sink"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_76_1    | x        | LE Encryption (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_76_2    | x        | LE Extended Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_76_3    | x        | LE Periodic Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_76_4    | x        | Synchronized Receiver (M)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Scan Delegator requirements
===========================

**Table 77: Scan Delegator, X.Y Versions**

Prerequisite: BAP 1/5 "Scan Delegator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_77_1    | x        | BAP v1.0 (C.1, C.2)                          |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory.
- C.2: Can only be supported with an active X.Y.Z version after Deprecation
  or Withdrawal. Deprecated 2025-02-01. Withdrawn 2027-02-01.

**Table 78: Scan Delegator, X.Y.Z Versions**

Prerequisite: BAP 1/5 "Scan Delegator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_78_1    |          | BAP v1.0.1 (C.3)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_78_2    |          | No longer used                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_78_3    | x        | BAP v1.0.2 (C.3)                             |
+------------------+----------+----------------------------------------------+

- C.1-C.2: No longer used.
- C.3: Mandatory to support one and only one.

**Table 79: Scan Delegator: Support Requirements**

Prerequisite: BAP 1/5 "Scan Delegator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_79_1    |          | BASS supported over BR/EDR (C.1, C.2)        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_79_2    | x        | BASS supported over LE (C.1)                 |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.
- C.2: Optional IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.

GAP requirements
----------------

**Table 80: GAP Requirements: Scan Delegator**

Prerequisite: BAP 1/5 "Scan Delegator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_80_1    | x        | Peripheral (M)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_2    |          | Central (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_3    | x        | Bondable mode (LE) (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_4    |          | Bondable mode (BR/EDR) (C.2)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_5    | x        | LE security mode 1 (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_6    | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (M)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_7    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_8    |          | Security mode 4, level 2 (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_9    |          | 128-bit encryption key size capable          |
|                  |          | (BR/EDR) (C.2)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_10   | x        | Minimum 128 Bit entropy key (LE) (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_11   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.11)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_12   | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.10)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_13   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | without listening for periodic advertising   |
|                  |          | (Peripheral) (C.6)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_14   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | with listening for periodic advertising      |
|                  |          | (Peripheral) (C.6)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_15   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | without listening for periodic advertising   |
|                  |          | (Central) (C.7)                              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_16   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | with listening for periodic advertising      |
|                  |          | (Central) (C.7)                              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_17   |          | Periodic Advertising Synchronization Transfer|
|                  |          | procedure (Peripheral) (C.8)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_18   |          | Periodic Advertising Synchronization Transfer|
|                  |          | procedure (Central) (C.9)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_19   |          | CoD Major Service Class bit 14 (C.2)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_20   |          | BR/EDR Secure Connections (C.11)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_21   | x        | LE Secure Connections (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_22   | x        | Out of Band (LE) (C.10)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_23   |          | Out-of-Band (BR/EDR) (C.11)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_80_24   |          | LE security mode 1 level 4 (O)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: No longer used.
- C.2: Mandatory IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.
- C.3-C.5: No longer used.
- C.6: Mandatory IF BAP 82/4 "Periodic Advertising Sync Transfer - Recipient"
  AND BAP 80/1 "Peripheral", otherwise not defined.
- C.7: Mandatory IF BAP 82/4 "Periodic Advertising Sync Transfer - Recipient"
  AND BAP 80/2 "Central", otherwise not defined.
- C.8: Mandatory IF BAP 82/4 "Periodic Advertising Sync Transfer - Recipient"
  AND BAP 80/1 "Peripheral" AND NOT BAP 80/2 "Central", otherwise Optional IF
  BAP 82/4 "Periodic Advertising Sync Transfer - Recipient" AND BAP 80/1
  "Peripheral", otherwise not defined.
- C.9: Mandatory IF BAP 82/4 "Periodic Advertising Sync Transfer - Recipient"
  AND BAP 80/2 "Central" AND NOT BAP 80/1 "Peripheral", otherwise Optional IF
  BAP 82/4 "Periodic Advertising Sync Transfer - Recipient" AND BAP 80/2
  "Central", otherwise not defined.
- C.10: Mandatory to support at least one.
- C.11: Mandatory to support at least one IF BAP 3/2 "GAP BR/EDR Host",
  otherwise not defined.

**Table 81: No longer used**

**Table 82: LL Requirements: Scan Delegator Role**

Prerequisite: BAP 1/5 "Scan Delegator"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_82_1    | x        | LE Encryption (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_82_2    | x        | LE Extended Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_82_3    | x        | LE Periodic Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_82_4    |          | Periodic Advertising Sync Transfer -         |
|                  |          | Recipient (O)                                |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

Broadcast Assistant requirements
================================

**Table 83: Broadcast Assistant, X.Y Versions**

Prerequisite: BAP 1/6 "Broadcast Assistant"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_83_1    | x        | BAP v1.0 (C.1, C.2)                          |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory.
- C.2: Can only be supported with an active X.Y.Z version after Deprecation
  or Withdrawal.
  Deprecated 2025-02-01. Withdrawn 2027-02-01.

**Table 84: Broadcast Assistant, X.Y.Z Versions**

Prerequisite: BAP 1/6 "Broadcast Assistant"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_84_1    |          | BAP v1.0.1 (C.3)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_84_2    |          | No longer used                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_84_3    | x        | BAP v1.0.2 (C.3)                             |
+------------------+----------+----------------------------------------------+

- C.1-C.2: No longer used.
- C.3: Mandatory to support one and only one.

**Table 85: Broadcast Assistant: Client Services Support Requirements**

Prerequisite: BAP 1/6 "Broadcast Assistant"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_85_1    |          | Discover BASS over BR/EDR (C.1, C.2)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_85_2    | x        | Discover BASS over LE (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_85_3    |          | Discover PACS over BR/EDR (C.2)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_85_4    |          | Discover PACS over LE (O)                    |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory to support at least one.
- C.2: Optional IF BAP 3/2 "GAP BR/EDR Host", otherwise Excluded.

**Table 86: Broadcast Audio Scan Service Characteristic Support Requirements**

Prerequisite: BAP 1/6 "Broadcast Assistant"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_86_1    | x        | Broadcast Audio Scan Control Point           |
|                  |          | characteristic (M)                           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_86_2    | x        | Broadcast Receive State characteristic (M)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_86_3    | x        | Broadcast Audio Scan Service discovery (M)   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_86_4    | x        | Broadcast Audio Scan Service characteristic  |
|                  |          | discovery (M)                                |
+------------------+----------+----------------------------------------------+

- M: Mandatory

**Table 87: Published Audio Capabilities Service Characteristic Support Requirements**

Prerequisite: BAP 85/3 "Discover PACS over BR/EDR" OR BAP 85/4 "Discover PACS over LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_87_1    |          | Sink PAC characteristic (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_87_2    |          | Sink Audio Locations characteristic (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_87_3    |          | Published Audio Capabilities Service         |
|                  |          | discovery (O)                                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_87_4    |          | Published Audio Capabilities Service         |
|                  |          | characteristic discovery (O)                 |
+------------------+----------+----------------------------------------------+

- O: Optional

**Table 88: Broadcast Audio Scan Service Operation Support Requirements**

Prerequisite: BAP 1/6 "Broadcast Assistant"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_88_1    |          | Remote Scan Start operation (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_88_2    |          | Remote Scan Stop operation (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_88_3    | x        | Add Source operation (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_88_4    |          | Modify Source operation (O)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_88_5    |          | SyncInfo Transfer (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_88_6    | x        | Set Broadcast Code operation (M)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_88_7    | x        | Remove Source operation (O)                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

GATT requirements
-----------------

**Table 89: GATT Requirements: Broadcast Assistant**

Prerequisite: BAP 1/6 "Broadcast Assistant"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_89_1    | x        | Discover All Primary Services (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_2    | x        | Discover Primary Service by Service UUID     |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_3    |          | Find Included Services (O)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_4    | x        | Discover All Characteristics of a Service    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_5    | x        | Discover Characteristics by UUID (C.2)       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_6    | x        | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_7    | x        | Read Characteristic Value (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_8    | x        | Write Characteristic Value (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_9    | x        | Write Without Response (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_10   | x        | Single Notification (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_11   | x        | Read Characteristic Descriptor (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_12   | x        | Write Characteristic Descriptor (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_13   | x        | Exchange MTU (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_14   |          | GATT Client over BR/EDR (C.3)                |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_89_15   | x        | GATT Client over LE (M)                      |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one.
- C.2: Mandatory to support at least one.
- C.3: Mandatory IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.

GAP requirements
----------------

**Table 90: GAP Requirements: Broadcast Assistant**

Prerequisite: BAP 1/6 "Broadcast Assistant"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_90_1    |          | Observer (O)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_2    |          | Peripheral (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_3    | x        | Central (M)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_4    | x        | Bondable mode (LE) (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_5    | x        | Bonding procedure (M)                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_6    | x        | LE security mode 1 (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_7    | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) with LE Secure Connections Pairing  |
|                  |          | only (M)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_8    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) with LE Secure Connections Pairing  |
|                  |          | only (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_9    |          | Security mode 4, level 2 (C.3)               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_10   |          | 128-bit encryption key size capable          |
|                  |          | (BR/EDR) (C.3)                               |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_11   | x        | Minimum 128 Bit entropy key (LE) (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_12   |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.10)                                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_13   | x        | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.9)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_14   |          | Periodic Advertising Synchronization Transfer|
|                  |          | procedure (Peripheral) (C.6)                 |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_15   |          | Periodic Advertising Synchronization Transfer|
|                  |          | procedure (Central) (C.7)                    |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_16   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | without listening forperiodic advertising    |
|                  |          | (C.8)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_17   |          | Periodic Advertising Synchronization         |
|                  |          | Establishment procedure over an LE connection|
|                  |          | with listening for periodic advertising (C.8)|
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_18   |          | CoD Major Service Class bit 14 (C.3)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_19   |          | BR/EDR Secure Connections (C.10)             |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_20   |          | LE Secure Connections (C.9)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_21   |          | Out of Band (LE) (C.9)                       |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_22   |          | Out-of-Band (BR/EDR) (C.10)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_90_23   |          | LE security mode 1 level 4 (O)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1-C.2: No longer used.
- C.3: Mandatory IF BAP 3/2 "GAP BR/EDR Host", otherwise not defined.
- C.4-C.5: No longer used.
- C.6: Mandatory IF BAP 92/4 "Periodic Advertising Sync Transfer - Sender"
  AND BAP 90/2 "Peripheral" AND NOT BAP 90/3 "Central", otherwise Optional
  IF BAP 92/4 "Periodic Advertising Sync Transfer - Sender", otherwise not
  defined.
- C.7: Mandatory IF BAP 92/4 "Periodic Advertising Sync Transfer - Sender"
  AND BAP 90/3 "Central" AND NOT BAP 90/2 "Peripheral", otherwise Optional
  IF BAP 92/4 "Periodic Advertising Sync Transfer - Sender", otherwise not
  defined.
- C.8: Mandatory to support at least one IF BAP 92/6 "Initiating Periodic
  Advertising Sync Transfer for Remote Periodic Advertising", otherwise not
  defined.
- C.9: Mandatory to support at least one.
- C.10: Mandatory to support at least one IF BAP 3/2 "GAP BR/EDR Host",
  otherwise not defined.

**Table 91: No longer used**

LL requirements
---------------

**Table 92: LL Requirements: Broadcast Assistant**

Prerequisite: BAP 1/6 "Broadcast Assistant"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_BAP_92_1    | x        | LE Encryption (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_92_2    | x        | LE Extended Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_92_3    | x        | LE Periodic Advertising (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_92_4    |          | Periodic Advertising Sync Transfer - Sender  |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_92_5    |          | Initiating Periodic Advertising Sync Transfer|
|                  |          | for Local Periodic Advertising (C.1)         |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_92_6    |          | Initiating Periodic Advertising Sync Transfer|
|                  |          | for Remote Periodic Advertising (C.1)        |
+------------------+----------+----------------------------------------------+
| TSPC_BAP_92_7    |          | Synchronized Receiver (O)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one IF BAP 92/4 "Periodic Advertising
  Sync Transfer - Sender", otherwise not defined.

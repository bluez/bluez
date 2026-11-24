.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

===============
RFComm Protocol
===============
(TCRL pkg101, RFCOMM.ICS.p8)


Versions
========
**Table 0: X.Y Versions**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_RFCOMM_0_1  |          | RFCOMM v1.1 with TS 07.10 (C.1)              |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_0_2  | x        | RFCOMM v1.2 with TS 07.10 (C.1)              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support one and only one.

Core Configuration
==================
**Table 0a: Core Configuration Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_RFCOMM_0a_1 | x        | Protocol supported over BR/EDR (C.1, C.3)    |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_0a_2 |          | 2 Protocol supported over LE (C.2)           |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Protocol IF CORE 41/2 “LE Core Configuration”.
- C.2: Excluded for this Protocol.
- C.3: Mandatory for this Protocol.

2.3 Supported procedures
========================
**Table 1: Supported Procedures**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_RFCOMM_1_1  | x        | Initialize RFCOMM Session (C.5)              |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_2  | x        | Respond to Initialization of an RFCOMM       |
|                  |          | Session (C.5)                                |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_3  | x        | Shutdown RFCOMM Session (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_4  | x        | Respond to a Shutdown of an RFCOMM Session   |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_5  | x        | Establish DLC (C.2)                          |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_6  | x        | Respond to Establishment of a DLC (C.1)      |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_7  | x        | Disconnect DLC (M)                           |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_8  | x        | Respond to Disconnection of a DLC (M)        |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_9  | x        | Respond to and send MSC Command (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_10 | x        | Initiate Transfer Information (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_11 | x        | Respond to Test Command (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_12 | x        | Send Test Command (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_13 | x        | React to Aggregate Flow Control (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_14 | x        | Respond to RLS Command (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_15 |          | Send RLS Command (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_16 | x        | Respond to PN Command (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_17 | x        | Send PN Command (C.3)                        |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_18 | x        | Send Non-Supported Command (NSC) response    |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_19 | x        | Respond to RPN Command (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_20 | x        | Send RPN Command (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_21 | x        | Closing Multiplexer by First Sending a DISC  |
|                  |          | Command (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_RFCOMM_1_22 | x        | Support of Credit Based Flow Control (M)     |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF RFCOMM 1/2 “Respond to Initialization of an RFCOMM
  Session”, otherwise Excluded.
- C.2: Mandatory IF RFCOMM 1/1 “Initialize RFCOMM Session”, otherwise
  Excluded.
- C.3: Mandatory IF RFCOMM 1/1 “Initialize RFCOMM Session”, otherwise
  Optional.
- C.4: Mandatory IF RFCOMM 0/2 “RFCOMM v1.2 with TS 07.10”, otherwise
  Optional.
- C.5: Mandatory to support at least one.
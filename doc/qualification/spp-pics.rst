.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

==================
Serial Port Pofile
==================
(TCRL 2023-1, SPP.ICS.p9)


Versions
========
**Table 0: X.Y Versions**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SPP_0_2     | x        | SPP v1.2 (M)                                 |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Core Configuration
==================
**Table 0a: Core Configuration Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SPP_0a_1    | x        | Profile supported over BR/EDR (C.1, C.3)     |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_0a_2    |          | Profile supported over LE (C.2)              |
+------------------+----------+----------------------------------------------+

- C.1: Excluded for this Profile IF CORE 41/2 “LE Core Configuration”.
- C.2: Excluded for this Profile.
- C.3: Mandatory for this Profile.

Roles
=====
**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
+ Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SPP_1_1     | x        | Device A (C.1)                               |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_1_2     | x        | Device B (C.1)                               |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

Support of SPP Service
======================
**Table 2: Serial Port Service Support**

+------------------+----------+----------------------------------------------+
+ Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SPP_2_1     | x        | Support of SPP as a standalone profile (O)   |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_2_1a    | x        | SPP as a standalone profile - Device A (C.2, |
|                  |          | C.3)                                         |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_2_1b    | x        | SPP as a standalone profile - Device B (C.2, |
|                  |          | C.4)                                         |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.2: Mandatory to support at least one IF SPP 2/1 “Support of SPP as a*
  standalone profile”, otherwise Excluded.
- C.3: Optional IF SPP 1/1 “Device A”, otherwise Excluded.
- C.4: Optional IF SPP 1/2 “Device B”, otherwise Excluded.

Application Procedures
======================
**Table 3: Application Procedures**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SPP_3_1     | x        | Establish link and set up virtual serial     |
|                  |          | connection (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_3_2     | x        | Accept link and virtual serial connection    |
|                  |          | establishment (C.2)                          |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_3_3     | x        | Register Service record for application in   |
|                  |          | local SDP database (C.3)                     |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_3_4     |          | No release in Sniff mode. Sniff mode enabled |
|                  |          | in the Link Manager (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_3_5     |          | No release in Hold mode. Hold mode enabled   |
|                  |          | in the Link Manager (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_3_7     |          | No release after Master/Slave switch. M/S    |
|                  |          | switch enabled in the Link Manager (O)       |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory IF SPP 1/1 “Device A”, otherwise Optional.
- C.2: Mandatory IF SPP 1/2 “Device B”, otherwise Optional.
- C.3: Mandatory IF SPP 2/1b “SPP as a standalone profile – Device B”,
  otherwise Optional.

Service Discovery Protocol
==========================
**Table 4: SDP Dependencies**
Prerequisite: SPP 2/1b “SPP as a standalone profile – Device B”

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SPP_4_1     | x        | ServiceClassIDList (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_4_2     | x        | ProtocolDescriptorList (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_4_5     | x        | ServiceName (O)                              |
+------------------+----------+----------------------------------------------+
| TSPC_SPP_4_6     | x        | BluetoothProfileDescriptorList (M)           |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

Note: If more than one Serial Port Profile Service is available, more than one
SerialPort SDP record can be registered

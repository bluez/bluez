.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

================
Security Manager
================
(TCRL 2023-1, SM.ICS.p11)

Roles and versions
==================
**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_1_1      | x        | Central Role (Initiator) (C.1)               |
+------------------+----------+----------------------------------------------+
| TSPC_SM_1_2      | x        | Peripheral Role (Responder) (C.1)            |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one of SM 1/1 "Central Role (Initiator)"
  OR SM 1/2 "Peripheral Role (Responder)".

Security properties
===================
**Table 2: Security Properties**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_2_1      | x        | Authenticated MITM protection (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_SM_2_2      | x        | Unauthenticated no MITM protection (C.1)     |
+------------------+----------+----------------------------------------------+
| TSPC_SM_2_3      | x        | No security requirements (M)                 |
+------------------+----------+----------------------------------------------+
| TSPC_SM_2_4      |          | OOB supported (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_SM_2_5      | x        | LE Secure Connections (O)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF SM 2/1 "Authenticated MITM protection",
  otherwise Optional.

Pairing algorithms
==================
**Table 3: Encryption Key Size**

Prerequisite: SM 2/1 "Authenticated MITM protection" OR
SM 2/2 "Unauthenticated no MITM protection" OR SM 2/4 "OOB supported"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_3_1      | x        | Encryption Key Size (M)                      |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Pairing algorithms
==================
**Table 4: Pairing Method**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_4_1      | x        | Just Works (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_SM_4_2      | x        | Passkey Entry (C.1)                          |
+------------------+----------+----------------------------------------------+
| TSPC_SM_4_3      |          | Out of Band (C.1)                            |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Mandatory to support at least one of SM 4/2 "Passkey Entry" OR
  SM 4/3 "Out of Band" IF SM 2/1 "Authenticated MITM protection",
  otherwise Excluded.

Key distribution and usage
==========================
**Table 5: Security Initiation**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_5_1      | x        | Encryption Setup using STK (C.3)             |
+------------------+----------+----------------------------------------------+
| TSPC_SM_5_2      | x        | Encryption Setup using LTK (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_SM_5_3      | x        | Peripheral Initiated Security (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_SM_5_4      | x        | Peripheral Initiated Security - Central      |
|                  |          | response (C.2)                               |
+------------------+----------+----------------------------------------------+
| TSPC_SM_5_5      |          | CT2 bit (C.4)                                |
+------------------+----------+----------------------------------------------+

- O: Optional
- C.1: Optional IF SM 1/2 "Peripheral Role (Responder)", otherwise Excluded.
- C.2: Mandatory IF SM 1/1 "Central Role (Initiator)", otherwise Excluded.
- C.3: Mandatory IF SM 2/1 "Authenticated MITM protection" OR
  SM 2/2 "Unauthenticated no MITM protection" OR SM 2/4 "OOB supported",
  otherwise Excluded.
- C.4: Excluded IF NOT SM 8a/1 "Cross Transport Key Derivation Supported"
  AND NOT SM 8b/1 "Cross Transport Key Derivation Supported", otherwise
  Mandatory IF NOT SUM ICS 31/17 "Core v4.2" AND NOT SUM ICS 31/18
  "Core v4.2+HS", otherwise Optional.

Key distribution and usage
==========================
**Table 6: Signing Algorithm**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_6_1      |          | Signing Algorithm - Generation (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_SM_6_2      |          | Signing Algorithm - Resolving (O)            |
+------------------+----------+----------------------------------------------+

- O: Optional

Key distribution and usage
==========================
**Table 7a: Key Distribution by Central**

Prerequisite: SM 1/1 "Central Role (Initiator)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_7a_1     | x        | Encryption Key (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_SM_7a_2     | x        | Identity Key (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_SM_7a_3     |          | Signing Key (O)                              |
+------------------+----------+----------------------------------------------+

- O: Optional

Key distribution and usage
==========================
**Table 7b: Key Distribution by Peripheral**

Prerequisite: SM 1/2 "Peripheral Role (Responder)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_7b_1     | x        | Encryption Key (O)                           |
+------------------+----------+----------------------------------------------+
| TSPC_SM_7b_2     | x        | Identity Key (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_SM_7b_3     | x        | Signing Key (O)                              |
+------------------+----------+----------------------------------------------+

- O: Optional

Key distribution and usage
==========================
**Table 8a: Cross-Transport Key Derivation by Central**

Prerequisite: SM 1/1 "Central Role (Initiator)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_8a_1     |          | Cross Transport Key Derivation Supported     |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_SM_8a_2     |          | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_SM_8a_3     |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF SM 2/5 "LE Secure Connections", otherwise Excluded.
- C.2: Optional IF SM 8a/1 "Cross Transport Key Derivation Supported",
  otherwise Excluded.

Key distribution and usage
==========================
**Table 8b: Cross-Transport Key Derivation by Peripheral**

Prerequisite: SM 1/2 "Peripheral Role (Responder)"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SM_8b_1     |          | Cross Transport Key Derivation Supported     |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_SM_8b_2     |          | Derivation of LE LTK from BR/EDR Link Key    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_SM_8b_3     |          | Derivation of BR/EDR Link Key from LE LTK    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF SM 2/5 "LE Secure Connections", otherwise Excluded.
- C.2: Optional IF SM 8b/1 "Cross Transport Key Derivation Supported",
  otherwise Excluded.

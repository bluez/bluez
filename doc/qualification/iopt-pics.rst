.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

===========================
Interoperability Test Suite
===========================
(TCRL 2023-1)

Interoperability
================
**Table 1: Interoperability Test Specification**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_IOPT_1_1    | x        | Interoperability (M)                         |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Interoperability
================
**Table 2: Design Configuration**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_IOPT_2_1    | x        | BR/EDR (C.1, C.2)                            |
+------------------+----------+----------------------------------------------+
| TSPC_IOPT_2_2    | x        | LE (C.1, C.2)                                |
+------------------+----------+----------------------------------------------+
| TSPC_IOPT_2_3    | x        | BR/EDR/LE (C.3)                              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one transport.
- C.2: Mandatory If IOP 2/3 "BR/EDR/LE" is Supported, otherwise Optional.
- C.3: Mandatory if IOP 2/1 "BR/EDR" AND IOP 2/2 "LE" is Supported, otherwise Excluded.

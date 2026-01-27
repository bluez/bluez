.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

=======================
Scan Parameters Profile
=======================
(TCRL 2023-1, SCPP.ICS.p2)


Versions
========
**Table 0: Major Versions (X.Y)**

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_0_1     | x        | SCPP v1.0 (M)                                        |
+------------------+----------+------------------------------------------------------+

- M: Mandatory

Roles
=====
**Table 1: Role Requirements**

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_1_1     |          | Scan Server (C.1)                                    |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_1_2     | x        | Scan Client (C.1)                                    |
+------------------+----------+------------------------------------------------------+

- C.1: Mandatory to support at least one of SCPP 1/1 "Scan Server" OR SCPP 1/2 "Scan Client".

Transports
==========
**Table 2: Transport Requirements**

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_2_1     |          | Profile supported over BR/EDR (C.1)                  |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_2_2     | x        | Profile supported over LE (M)                        |
+------------------+----------+------------------------------------------------------+

- M: Mandatory
- C.1: Excluded for this Profile.

Scan Server Role
================
**Table 3: Services - Scan Server Role**

Prerequisite: SCPP 1/1 "Scan Server"

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_3_1     |          | Scan Parameters Service (M)                          |
+------------------+----------+------------------------------------------------------+

- M: Mandatory

Scan Server Role
================
**Table 4: GAP Requirements - Scan Server Role**

Prerequisite: SCPP 1/1 "Scan Server"

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_4_1     |          | Peripheral (M)                                       |
+------------------+----------+------------------------------------------------------+

- M: Mandatory

Scan Client Role
================
**Table 7: Discover Services and Characteristics - Scan Client Role**

Prerequisite: SCPP 1/2 "Scan Client"

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_7_1     | x        | Discover Scan Parameters Service (M)                 |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_7_2     | x        | Discover Scan Parameters characteristic: Scan        |
|                  |          | interval Window (M)                                  |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_7_3     | x        | Discover Scan Parameters characteristic: Scan        |
|                  |          | Refresh (M)                                          |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_7_4     | x        | Discover Scan Parameters characteristic: Scan        |
|                  |          | Refresh - Client Characteristic Configuration        |
|                  |          | Descriptor (M)                                       |
+------------------+----------+------------------------------------------------------+

- M: Mandatory

Scan Client Role
================
**Table 8: Features - Scan Client Role**

Prerequisite: SCPP 1/2 "Scan Client"

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_8_1     | x        | Write Scan Interval Window characteristic (M)        |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_8_2     |          | Configure Scan Refresh characteristic: Client        |
|                  |          | Characteristic Configuration characteristic          |
|                  |          | descriptor with (O)                                  |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_8_3     | x        | Notify Scan Refresh characteristic (M)               |
+------------------+----------+------------------------------------------------------+

- M: Mandatory
- O: Optional

Scan Client Role
================
**Table 9: GATT Requirements - Scan Client Role**

Prerequisite: SCPP 1/2 "Scan Client"

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_9_1     | x        | GATT Client over LE (M)                              |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_9_3     | x        | Discover All Primary Services (C.1)                  |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_9_4     | x        | Discover Primary Services by Service UUID (C.1)      |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_9_5     | x        | Discover All Characteristics of a Service (C.2)      |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_9_6     | x        | Discover Characteristics by UUID (C.2)               |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_9_7     | x        | Discover All Characteristic Descriptors (M)          |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_9_8     | x        | Write without Response (M)                           |
+------------------+----------+------------------------------------------------------+
| TSC_SCPP_9_10    | x        | Notifications (M)                                    |
+------------------+----------+------------------------------------------------------+

- M: Mandatory
- C.1: Mandatory to support at least one of SCPP 9/3 "Discover All Primary Services" OR SCPP 9/4 "Discover Primary Services by Service UUID".
- C.2: Mandatory to support at least one of SCPP 9/5 "Discover All Characteristics of a Service" OR SCPP 9/6 "Discover Characteristics by UUID".

Scan Client Role
================
**Table 10: GAP Requirements - Scan Client Role**

Prerequisite: SCPP 1/2 "Scan Client"

+------------------+----------+------------------------------------------------------+
| Parameter Name   | Selected | Description                                          |
+==================+==========+======================================================+
| TSC_SCPP_10_1    | x        | Central (M)                                          |
+------------------+----------+------------------------------------------------------+

- M: Mandatory

.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

=========================
Generic Attribute Profile
=========================
(TCRL 2023-1, GATT.ICS.p17)

Roles
=====
**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_1_1    | x        | Generic Attribute Profile (GATT) Client (C.1)|
+------------------+----------+----------------------------------------------+
| TSPC_GATT_1_2    | x        | Generic Attribute Profile (GATT) Server (C.1)|
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one.

Transports
==========
**Table 1a: Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_1a_1   | x        | GATT Client over LE (C.1)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_1a_2   |          | GATT Client over BR/EDR (C.1)                |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_1a_3   | x        | GATT Server over LE (C.2)                    |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_1a_4   |          | GATT Server over BR/EDR (C.2)                |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one IF GATT 1/1 "Generic Attribute
  Profile (GATT) Client", otherwise Excluded.
- C.2: Mandatory to support at least one IF GATT 1/2 "Generic Attribute
  Profile (GATT) Server", otherwise Excluded.

Transports
==========
**Table 2: Attribute Protocol Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_2_1    |          | Unenhanced ATT bearer over BR/EDR (C.1)      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_2_2    | x        | Unenhanced ATT bearer over LE (C.2)          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_2_3a   |          | Enhanced ATT bearer over LE (C.4, C.3)       |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_2_3b   |          | Enhanced ATT bearer over BR/EDR (C.1, C.3)   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_2_4    | x        | Attribute Protocol Client (C.6)              |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_2_5    | x        | Attribute Protocol Server (C.7)              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one IF GATT 1a/2 "GATT Client over
  BR/EDR" OR GATT 1a/4 "GATT Server over BR/EDR", otherwise not defined.
- C.2: Mandatory IF GATT 1a/1 "GATT Client over LE" OR GATT 1a/3 "GATT Server
  over LE", otherwise not defined.
- C.3: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1", otherwise
  Optional.
- C.4: Optional IF GATT 2/2 "Unenhanced ATT bearer over LE", otherwise not
  defined.
- C.6: Mandatory IF GATT 1/1 "Generic Attribute Profile (GATT) Client",
  otherwise not defined.
- C.7: Mandatory IF GATT 1/2 "Generic Attribute Profile (GATT) Server",
  otherwise not defined.

GATT Features
=============
**Table 3: Generic Attribute Profile Feature Support, by Client**

Prerequisite: GATT 1/1 "Generic Attribute Profile (GATT) Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_3_1    | x        | Exchange MTU (C.11)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_2    | x        | Discover All Primary Services (O)            |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_3    | x        | Discover Primary Services by Service UUID (O)|
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_4    | x        | Find Included Services (O)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_5    | x        | Discover All Characteristics of a Service (O)|
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_6    | x        | Discover Characteristics by UUID (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_7    |          | Discover All Characteristic Descriptors (O)  |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_8    | x        | Read Characteristic Value (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_9    | x        | Read Using Characteristic UUID (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_10   | x        | Read Long Characteristic Values (O)          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_11   |          | Read Multiple Characteristic Values (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_12   | x        | Write without Response (O)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_13   |          | Signed Write Without Response (C.11)         |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_14   | x        | Write Characteristic Value (O)               |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_15   | x        | Write Long Characteristic Values (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_16   |          | Characteristic Value Reliable Writes (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_17   | x        | Notifications (C.7)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_18   | x        | Indications (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_19   | x        | Read Characteristic Descriptors (O)          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_20   | x        | Read Long Characteristic Descriptors (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_21   | x        | Write Characteristic Descriptors (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_22   | x        | Write Long Characteristic Descriptors (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_23   | x        | Service Changed Characteristic (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_24   |          | Configured Broadcast (C.2)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_25   |          | Client Supported Features Characteristic     |
|                  |          | (C.4)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_25a  |          | Enabling Robust Caching (C.12)               |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_26   |          | Database Hash Characteristic (C.4)           |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_27   |          | Read and Interpret Characteristic            |
|                  |          | Presentation Format (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_28   |          | Read and Interpret Characteristic Aggregate  |
|                  |          | Format (C.6)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_29   |          | Read Multiple Variable Length Characteristic |
|                  |          | Values (C.9)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3_30   |          | Multiple Variable Length Notifications (C.10)|
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.2: Optional IF GATT 3/14 "Write Characteristic Value", otherwise Excluded.
- C.4: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0", otherwise Optional.
- C.6: Optional IF GATT 3/27 "Read and Interpret Characteristic Presentation
  Format", otherwise Excluded.
- C.7: Mandatory IF GATT 2/3a "Enhanced ATT bearer over LE" OR GATT 2/3b
  "Enhanced ATT bearer over BR/EDR", otherwise Optional.
- C.9: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1", otherwise
  Optional.
- C.10: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1", otherwise
  Mandatory IF GATT 2/3a "Enhanced ATT bearer over LE" OR GATT 2/3b "Enhanced
  ATT bearer over BR/EDR", otherwise Optional.
- C.11: Optional IF GATT 1a/1 "GATT Client over LE", otherwise Excluded.
- C.12: Optional IF GATT 3/25 "Client Supported Features Characteristic",
  otherwise Excluded.

GATT Features
=============
**Table 3a: GAP Role Requirements for GATT Client**

Prerequisite: GATT 1a/1 "GATT Client over LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_3a_1   |          | Peripheral (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_3a_2   |          | Central (O)                                  |
+------------------+----------+----------------------------------------------+

- O: Optional

GATT Features
=============
**Table 4: Generic Attribute Profile Feature Support, by Server**

Prerequisite: GATT 1/2 "Generic Attribute Profile (GATT) Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_4_1    | x        | Exchange MTU (C.6)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_2    | x        | Discover All Primary Services (M)            |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_3    | x        | Discover Primary Services by Service UUID (M)|
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_4    | x        | Find Included Services (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_5    | x        | Discover All Characteristics of a Service (M)|
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_6    | x        | Discover Characteristics by UUID (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_7    | x        | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_8    | x        | Read Characteristic Value (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_9    | x        | Read Using Characteristic UUID (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_10   | x        | Read Long Characteristic Values (C.12)       |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_11   | x        | Read Multiple Characteristic Values (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_12   | x        | Write without Response (C.2)                 |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_13   |          | Signed Write Without Response (C.6)          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_14   | x        | Write Characteristic Value (C.3)             |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_15   | x        | Write Long Characteristic Values (C.12)      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_16   |          | Characteristic Value Reliable Writes (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_17   | x        | Notifications (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_18   | x        | Indications (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_19   | x        | Read Characteristic Descriptors (C.12)       |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_20   | x        | Read Long Characteristic Descriptors (C.12)  |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_21   | x        | Write Characteristic Descriptors (C.12)      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_22   | x        | Write Long Characteristic Descriptors (O)    |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_23   | x        | Service Changed Characteristic (C.14)        |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_24   |          | Configured Broadcast (C.5)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_25   | x        | Execute Write Request with empty queue (C.7) |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_26   |          | Client Supported Features Characteristic     |
|                  |          | (C.9)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_27   |          | Database Hash Characteristic (C.8)           |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_28   |          | Report Characteristic Value: Characteristic  |
|                  |          | Presentation Format (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_29   |          | Report aggregate Characteristic Value:       |
|                  |          | Characteristic Aggregate Format (C.10)       |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_30   |          | Read Multiple Variable Length Characteristic |
|                  |          | Values (C.13)                                |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4_31   |          | Multiple Variable Length Notifications (C.13)|
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF GATT 4/23 "Service Changed Characteristic", otherwise
  Optional.
- C.2: Mandatory IF GATT 4/13 "Signed Write Without Response" OR GATT 2/3a
  "Enhanced ATT bearer over LE" OR GATT 2/3b "Enhanced ATT bearer over
  BR/EDR", otherwise Optional.
- C.3: Mandatory IF GATT 4/15 "Write Long Characteristic Values" OR GATT 2/3a
  "Enhanced ATT bearer over LE" OR GATT 2/3b "Enhanced ATT bearer over
  BR/EDR", otherwise Optional.
- C.5: Optional IF GATT 4/14 "Write Characteristic Value", otherwise Excluded.
- C.6: Optional IF GATT 1a/3 "GATT Server over LE", otherwise Excluded.
- C.7: Optional IF (SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS")
  AND (GATT 4/15 "Write Long Characteristic Values" OR GATT 4/16
  "Characteristic Value Reliable Writes" OR GATT 4/22 "Write Long
  Characteristic Descriptors"), otherwise Mandatory IF GATT 4/15 "Write Long
  Characteristic Values" OR GATT 4/16 "Characteristic Value Reliable Writes"
  OR GATT 4/22 "Write Long Characteristic Descriptors", otherwise Excluded.
- C.8: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0", otherwise Optional.
- C.9: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0", otherwise Mandatory IF GATT 4/23 "Service
  Changed Characteristic" AND GATT 4/27 "Database Hash Characteristic",
  otherwise Excluded.
- C.10: Optional IF GATT 4/28 "Report Characteristic Value: Characteristic
  Presentation Format", otherwise Excluded.
- C.12: Mandatory IF GATT 2/3a "Enhanced ATT bearer over LE" OR GATT 2/3b
  "Enhanced ATT bearer over BR/EDR", otherwise Optional.
- C.13: Excluded IF SUM ICS 31/17 "Core v4.2" OR SUM ICS 31/18 "Core v4.2+HS"
  OR SUM ICS 31/19 "Core v5.0" OR SUM ICS 31/20 "Core v5.1", otherwise
  Mandatory IF GATT 2/3a "Enhanced ATT bearer over LE" OR GATT 2/3b "Enhanced
  ATT bearer over BR/EDR", otherwise Optional.
- C.14: Mandatory IF service definitions on the server can be added, changed,
  or removed, otherwise Optional.

GATT Features
=============
**Table 4a: GAP Role Requirements for GATT Server**

Prerequisite: GATT 1a/3 "GATT Server over LE"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_4a_1   |          | Peripheral (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_4a_2   |          | Central (O)                                  |
+------------------+----------+----------------------------------------------+

- O: Optional

SDP requirements
================
**Table 6: SDP Interoperability**

Prerequisite: GATT 2/1 "Unenhanced ATT bearer over BR/EDR" OR GATT 2/3b "Enhanced ATT bearer over BR/EDR"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_6_2    |          | Client (C.1)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_6_3    |          | Server (C.2)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_6_4    |          | ProtocolDescriptorList (C.2)                 |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_6_5    |          | BrowseGroupList (C.2)                        |
+------------------+----------+----------------------------------------------+

- C.1: Optional IF GATT 1a/2 "GATT Client over BR/EDR", otherwise not defined.
- C.2: Mandatory IF GATT 1a/4 "GATT Server over BR/EDR", otherwise not defined.

GAP requirements
================
**Table 7: GAP Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_7_2    | x        | LE security mode 1 (C.2)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_7_3    | x        | LE security mode 2 (C.2)                     |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_7_4    | x        | Authentication procedure (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_7_5    |          | Connection data signing procedure (C.2)      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_7_6    |          | Authenticate signed data procedure (C.2)     |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_7_7    | x        | Authorization procedure (C.2)                |
+------------------+----------+----------------------------------------------+

- C.2: Optional IF GATT 2/2 "Unenhanced ATT bearer over LE", otherwise not defined.

Multiple Bearer Support
=======================
**Table 8: Multiple Simultaneous ATT Bearers**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_8_1    |          | Support for multiple simultaneous active ATT |
|                  |          | bearers from same device - ATT over LE and   |
|                  |          | ATT over BR/EDR (C.1)                        |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_8_2    |          | Support for multiple simultaneous active ATT |
|                  |          | bearers from same device - ATT over LE and   |
|                  |          | EATT over LE (C.2)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_8_3    |          | Support for multiple simultaneous active ATT |
|                  |          | bearers from same device - ATT over BR/EDR   |
|                  |          | and EATT over BR/EDR (C.3)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_8_4    |          | Support for multiple simultaneous active ATT |
|                  |          | bearers from same device - ATT over LE and   |
|                  |          | EATT over BR/EDR (C.4)                       |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_8_5    |          | Support for multiple simultaneous active ATT |
|                  |          | bearers from same device - ATT over BR/EDR   |
|                  |          | and EATT over LE (C.5)                       |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_8_6    |          | Support for multiple simultaneous active EATT|
|                  |          | bearers from same device - EATT over BR/EDR  |
|                  |          | and EATT over LE (C.6)                       |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_8_7    |          | Support for multiple simultaneous active EATT|
|                  |          | bearers from same device - EATT over BR/EDR  |
|                  |          | (C.7)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_8_8    |          | Support for multiple simultaneous active EATT|
|                  |          | bearers from same device - EATT over LE (C.7)|
+------------------+----------+----------------------------------------------+

- C.1: Optional IF GATT 2/1 "Unenhanced ATT bearer over BR/EDR" AND GATT 2/2
  "Unenhanced ATT bearer over LE", otherwise Excluded.
- C.2: Optional IF GATT 2/2 "Unenhanced ATT bearer over LE" AND GATT 2/3a
  "Enhanced ATT bearer over LE", otherwise Excluded.
- C.3: Optional IF GATT 2/1 "Unenhanced ATT bearer over BR/EDR" AND GATT 2/3b
  "Enhanced ATT bearer over BR/EDR", otherwise Excluded.
- C.4: Optional IF GATT 2/2 "Unenhanced ATT bearer over LE" AND GATT 2/3b
  "Enhanced ATT bearer over BR/EDR", otherwise Excluded.
- C.5: Optional IF GATT 2/1 "Unenhanced ATT bearer over BR/EDR" AND GATT 2/3a
  "Enhanced ATT bearer over LE", otherwise Excluded.
- C.6: Optional IF GATT 2/3a "Enhanced ATT bearer over LE" AND GATT 2/3b
  "Enhanced ATT bearer over BR/EDR", otherwise Excluded.
- C.7: Optional IF GATT 2/3a "Enhanced ATT bearer over LE" OR GATT 2/3b
  "Enhanced ATT bearer over BR/EDR", otherwise Excluded.

ATT requirements
================
**Table 9: Attribute Protocol Client Requirements**

Prerequisite: GATT 1/1 "Generic Attribute Profile (GATT) Client"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_9_1    | x        | Exchange MTU Request (C.1)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_2    | x        | Find Information Request (C.2)               |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_3    | x        | Find by Type Value Request (C.3)             |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_4    | x        | Read by Type Request (C.4)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_5    | x        | Read Request (C.5)                           |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_6    | x        | Read Blob Request (C.6)                      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_7    |          | Read Multiple Request (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_8    | x        | Write Request (C.8)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_9    | x        | Write Command (C.9)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_10   |          | Signed Write Command (C.10)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_11   | x        | Prepare Write Request (C.11)                 |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_12   | x        | Handle Value Notification (C.12)             |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_13   | x        | Handle Value Indication (C.13)               |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_14   |          | Read Multiple Variable Length Request (C.14) |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_9_15   |          | Handle Value Multiple Notification (C.15)    |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF GATT 3/1 "Exchange MTU", otherwise not defined.
- C.2: Mandatory IF GATT 3/7 "Discover All Characteristic Descriptors",
  otherwise not defined.
- C.3: Mandatory IF GATT 3/3 "Discover Primary Services by Service UUID",
  otherwise not defined.
- C.4: Mandatory IF GATT 3/9 "Read Using Characteristic UUID", otherwise not
  defined.
- C.5: Mandatory IF GATT 3/8 "Read Characteristic Value" OR GATT 3/19 "Read
  Characteristic Descriptors", otherwise not defined.
- C.6: Mandatory IF GATT 3/10 "Read Long Characteristic Values" OR GATT 3/20
  "Read Long Characteristic Descriptors", otherwise not defined.
- C.7: Mandatory IF GATT 3/11 "Read Multiple Characteristic Values", otherwise
  not defined.
- C.8: Mandatory IF GATT 3/14 "Write Characteristic Value" OR GATT 3/21 "Write
  Characteristic Descriptors", otherwise not defined.
- C.9: Mandatory IF GATT 3/12 "Write without Response", otherwise not defined.
- C.10: Mandatory IF GATT 3/13 "Signed Write Without Response", otherwise not
  defined.
- C.11: Mandatory IF GATT 3/15 "Write Long Characteristic Values" OR GATT 3/16
  "Characteristic Value Reliable Writes" OR GATT 3/22 "Write Long
  Characteristic Descriptors", otherwise not defined.
- C.12: Mandatory IF GATT 3/17 "Notifications", otherwise Optional.
- C.13: Mandatory IF GATT 3/18 "Indications", otherwise not defined.
- C.14: Mandatory IF GATT 3/29 "Read Multiple Variable Length Characteristic
  Values", otherwise not defined.
- C.15: Mandatory IF GATT 3/30 "Multiple Variable Length Notifications",
  otherwise not defined.

ATT requirements
================
**Table 10: Attribute Protocol Server Requirements**

Prerequisite: GATT 1/2 "Generic Attribute Profile (GATT) Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_GATT_10_1   | x        | Exchange MTU Request (C.1)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_2   | x        | Read Blob Request (C.2)                      |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_3   |          | Read Multiple Request (C.3)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_4   | x        | Write Request (C.4)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_5   | x        | Write Command (C.5)                          |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_6   |          | Signed Write Command (C.6)                   |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_7   | x        | Prepare Write Request (C.7)                  |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_8   | x        | Handle Value Notification (C.8)              |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_9   | x        | Handle Value Indication (C.9)                |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_10  |          | Execute Write Request with no pending        |
|                  |          | prepared write values (C.10)                 |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_11  |          | Read Multiple Variable Length Request (C.11) |
+------------------+----------+----------------------------------------------+
| TSPC_GATT_10_12  |          | Handle Value Multiple Notification (C.12)    |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory IF GATT 4/1 "Exchange MTU", otherwise not defined.
- C.2: Mandatory IF GATT 4/10 "Read Long Characteristic Values", otherwise not
  defined.
- C.3: Mandatory IF GATT 4/11 "Read Multiple Characteristic Values", otherwise
  Optional.
- C.4: Mandatory IF GATT 4/14 "Write Characteristic Value" OR GATT 4/21 "Write
  Characteristic Descriptors", otherwise Optional.
- C.5: Mandatory IF GATT 4/12 "Write without Response", otherwise Optional.
- C.6: Mandatory IF GATT 4/13 "Signed Write Without Response", otherwise
  Optional.
- C.7: Mandatory IF GATT 4/15 "Write Long Characteristic Values" OR GATT 4/16
  "Characteristic Value Reliable Writes" OR GATT 4/22 "Write Long
  Characteristic Descriptors" OR GATT 2/3a "Enhanced ATT bearer over LE" OR
  GATT 2/3b "Enhanced ATT bearer over BR/EDR", otherwise Optional.
- C.8: Mandatory IF GATT 4/17 "Notifications", otherwise Optional.
- C.9: Mandatory IF GATT 4/18 "Indications", otherwise Optional.
- C.10: Mandatory IF GATT 4/25 "Execute Write Request with empty queue" AND
  SUM ICS 31/19 "Core v5.0", otherwise Optional.
- C.11: Mandatory IF GATT 4/30 "Read Multiple Variable Length Characteristic
  Values", otherwise Optional.
- C.12: Mandatory IF GATT 4/31 "Multiple Variable Length Notifications",
  otherwise Optional.

.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

=====================
HID over GATT Profile
=====================
(TCRL 2023-1, HOGP.ICS.p7)

Version
=======
**Table 0: Major Versions (X.Y)**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_0_1    | x        | HOGP v1.0 (M)                                |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Roles
=====
**Table 1: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_1_1    |          | HID Device (C.1)                             |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_1_2    | x        | Report Host (C.1)                            |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_1_3    |          | Boot Host (C.1)                              |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one of HOGP 1/1 "HID Device" OR HOGP 1/2
  "Report Host" OR HOGP 1/3 "Boot Host".

Transports
==========
**Table 2: Transport Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_2_1    |          | Profile supported over BR/EDR (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_2_2    | x        | Profile supported over LE (M)                |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- C.1: Excluded for this Profile.

HID Device
==========
**Table 3: Services - HID Device**

Prerequisite: HOGP 1/1 "HID Device"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_3_1    |          | HID Service (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_3_2    |          | Multiple Service instances - HID Service (O) |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_3_3    |          | Battery Service (M)                          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_3_4    |          | Device Information Service (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_3_5    |          | Scan Parameters Service (O)                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

HID Device
==========
**Table 4: Features - HID Device**

Prerequisite: HOGP 1/1 "HID Device"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_4_1    |          | Include HID Service UUID in AD in GAP        |
|                  |          | Discoverable Mode (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_4_2    |          | Include Local Name in AD or Scan Response    |
|                  |          | Data (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_4_3    |          | Include Appearance in AD or Scan Response    |
|                  |          | Data (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_4_4    |          | PnP ID (M)                                   |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_4_5    |          | Report Characteristic (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_4_6    |          | Non-HID Service characteristic described     |
|                  |          | within Report Map characteristic (C.1)       |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_4_7    |          | Report Map Characteristic - External Report  |
|                  |          | Reference Characteristic descriptor (C.2)    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one of HOGP 4/5 "Report Characteristic"
  OR HOGP 4/6 "Non-HID Service characteristic described within Report Map
  characteristic".
- C.2: Mandatory IF HOGP 4/6 "Non-HID Service characteristic described within
  Report Map characteristic", otherwise not defined.

HID Device
==========
**Table 5: GAP Requirements - HID Device**

Prerequisite: HOGP 1/1 "HID Device"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_5_1    |          | Peripheral (M)                               |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_5_2    |          | Directed connectable mode (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_5_3    |          | Undirected connectable mode (M)              |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_5_4    |          | Bondable mode (Peripheral) (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_5_5    |          | Bonding procedure (Peripheral) (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_5_6    |          | LE security mode 1 (Peripheral) (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_5_7    |          | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) (Peripheral) (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_5_8    |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) (Peripheral) (O)                    |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

HID Host
========
**Table 7a: GATT based Profile Support - Report Host**

Prerequisite: HOGP 1/2 "Report Host"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_7a_1   | x        | Scan Client (M)                              |
+------------------+----------+----------------------------------------------+

- M: Mandatory

HID Host
========
**Table 9: Discover Service and Characteristics - Report Host**

Prerequisite: HOGP 1/2 "Report Host"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_9_1    | x        | Discover HID Service (M)                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_2    | x        | Discover Battery Service (M)                 |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_3    | x        | Discover Device Information Service (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_4    | x        | Discover Scan Parameters Service (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_5    | x        | Discover HID Service characteristic: Report  |
|                  |          | Map (M)                                      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_6    | x        | Discover HID Service characteristic: Report  |
|                  |          | Map - External Report Reference              |
|                  |          | characteristic descriptor (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_7    | x        | Discover HID Service characteristic: Report  |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_8    | x        | Discover HID Service characteristic: Report -|
|                  |          | Client Characteristic Configuration          |
|                  |          | characteristic descriptor (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_9    | x        | Discover HID Service characteristic: Report -|
|                  |          | Report Reference characteristic descriptor   |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_10   | x        | Discover HID Service characteristic: HID     |
|                  |          | Information (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_11   | x        | Discover HID Service characteristic: HID     |
|                  |          | Control Point (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_12   |          | Discover HID Service characteristic: Protocol|
|                  |          | Mode (O)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_13   | x        | Discover Battery Service characteristic:     |
|                  |          | Battery Level (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_14   | x        | Discover Battery Service characteristic:     |
|                  |          | Battery Level - Client Characteristic        |
|                  |          | Configuration characteristic descriptor (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_15   | x        | Discover Device Information Service          |
|                  |          | characteristic: PnP ID (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_9_16   | x        | Discover non-HID Service characteristic:     |
|                  |          | Report Reference characteristic descriptor   |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

HID Host
========
**Table 10: Discover Service & Characteristics - Boot Host**

Prerequisite: HOGP 1/3 "Boot Host"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_10_1   |          | Discover HID Service (M)                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_2   |          | Discover Battery Service (O)                 |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_3   |          | Discover Device Information Service (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_4   |          | Discover HID Service characteristic: Protocol|
|                  |          | Mode (M)                                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_5   |          | Discover HID Service characteristic: Boot    |
|                  |          | Keyboard Input Report (C.1, C.2)             |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_6   |          | Discover HID Service characteristic: Boot    |
|                  |          | Keyboard Input Report - Client Characteristic|
|                  |          | Configuration characteristic descriptor (C.3)|
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_7   |          | Discover HID Service characteristic: Boot    |
|                  |          | Keyboard Output Report (C.1, C.2)            |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_8   |          | Discover HID Service characteristic: Boot    |
|                  |          | Mouse Input Report (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_9   |          | Discover HID Service characteristic: Boot    |
|                  |          | Mouse Input Report - Client Characteristic   |
|                  |          | Configuration characteristic descriptor (C.4)|
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_10  |          | Discover Battery Service characteristic:     |
|                  |          | Battery Level (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_11  |          | Discover Battery Service characteristic:     |
|                  |          | Battery Level - Client Characteristic        |
|                  |          | Configuration characteristic descriptor (O)  |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_10_12  |          | Discover Device Information Service          |
|                  |          | characteristic: PnP ID (O)                   |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one of HOGP 10/5 "Discover HID Service
  characteristic: Boot Keyboard Input Report" OR HOGP 10/7 "Discover HID
  Service characteristic: Boot Keyboard Output Report" OR HOGP 10/8 "Discover
  HID Service characteristic: Boot Mouse Input Report".
- C.2: Mandatory to support none or all of HOGP 10/5 "Discover HID Service
  characteristic: Boot Keyboard Input Report" OR HOGP 10/7 "Discover HID
  Service characteristic: Boot Keyboard Output Report".
- C.3: Mandatory IF HOGP 10/5 "Discover HID Service characteristic: Boot
  Keyboard Input Report", otherwise Excluded.
- C.4: Mandatory IF HOGP 10/8 "Discover HID Service characteristic: Boot
  Mouse Input Report", otherwise Excluded.

HID Host
========
**Table 11: Features - Report Host**

Prerequisite: HOGP 1/2 "Report Host"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_11_1   | x        | Read Report Map characteristic (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_2   | x        | Read Report Map characteristic: External     |
|                  |          | Report Reference characteristic descriptor   |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_3   |          | Read Report characteristic: Report Type:     |
|                  |          | Input Report (C.2)                           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_4   |          | Write Report characteristic: Report Type:    |
|                  |          | Input Report (C.2)                           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_5   |          | Read Report characteristic: Report Type:     |
|                  |          | Output Report (C.3)                          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_6   |          | Write - Report characteristic: Report Type:  |
|                  |          | Output Report (C.3)                          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_7   |          | Read - Report characteristic: Report Type:   |
|                  |          | Feature Report (C.4)                         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_8   |          | Write - Report characteristic: Report Type:  |
|                  |          | Feature Report (C.4)                         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_9   | x        | Read Report characteristic: Report Reference |
|                  |          | characteristic descriptor (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_10  | x        | Read Report characteristic: Input Report:    |
|                  |          | Client Characteristic Configuration          |
|                  |          | characteristic descriptor (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_11  | x        | Report characteristic configuration: enable  |
|                  |          | notifications (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_11a |          | Report characteristic configuration: disable |
|                  |          | notifications (C.2)                          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_12  |          | Read HID Information characteristic (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_13  |          | Suspend State (O)                            |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_14  |          | Exit Suspend State (C.1)                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_15  |          | Write HID Control Point characteristic:      |
|                  |          | Suspend command (C.1)                        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_16  |          | Write HID Control Point characteristic: Exit |
|                  |          | Suspend command (C.1)                        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_17  |          | Read Protocol Mode characteristic: Get       |
|                  |          | Protocol command (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_18  |          | Write Protocol Mode characteristic: Set      |
|                  |          | Report Protocol Mode command (O)             |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_19  | x        | Read Battery Level characteristic (C.5)      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_20  |          | Read Battery Level characteristic: Client    |
|                  |          | Characteristic Configuration characteristic  |
|                  |          | descriptor (C.6)                             |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_21  |          | Battery Level characteristic configuration:  |
|                  |          | enable notifications (C.6)                   |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_21a |          | Battery Level characteristic configuration:  |
|                  |          | disable notifications (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_22  | x        | Read non-HID Service characteristic: Report  |
|                  |          | Reference characteristic descriptor (M)      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_23  | x        | Read PnP ID characteristic (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_24  | x        | Notify Report characteristic (M)             |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_25  |          | Notify Battery Level characteristic (C.5)    |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_26  | x        | Report Characteristic: Input Report type     |
|                  |          | supported (M)                                |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_27  |          | Report Characteristic: Output Report type    |
|                  |          | supported (O)                                |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_11_28  |          | Report Characteristic: Feature Report type   |
|                  |          | supported (O)                                |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF HOGP 11/13 "Suspend State", otherwise Excluded.
- C.2: Optional IF HOGP 11/26 "Report Characteristic: Input Report type
  supported", otherwise Excluded.
- C.3: Optional IF HOGP 11/27 "Report Characteristic: Output Report type
  supported", otherwise Excluded.
- C.4: Optional IF HOGP 11/28 "Report Characteristic: Feature Report type
  supported", otherwise Excluded.
- C.5: Mandatory to support at least one of HOGP 11/19 "Read Battery Level
  characteristic" OR HOGP 11/25 "Notify Battery Level characteristic".
- C.6: Mandatory IF HOGP 11/25 "Notify Battery Level characteristic",
  otherwise Excluded.

HID Host
========
**Table 12: Features - Boot Host**

Prerequisite: HOGP 1/3 "Boot Host"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_12_1   |          | Read Protocol Mode characteristic: Get       |
|                  |          | Protocol Mode command (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_2   |          | Write Protocol Mode characteristic: Set Boot |
|                  |          | Protocol Mode command (M)                    |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_3   |          | Read HID Service characteristic: Boot        |
|                  |          | Keyboard Input Report (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_4   |          | Write HID Service characteristic: Boot       |
|                  |          | Keyboard Input Report (C.1)                  |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_5   |          | Read Client Characteristic Configuration     |
|                  |          | characteristic descriptor for Boot Keyboard  |
|                  |          | Input Report (C.1)                           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_6   |          | Boot Keyboard Input Report characteristic    |
|                  |          | configuration: enable notifications (C.1)    |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_6a  |          | Boot Keyboard Input Report characteristic    |
|                  |          | configuration: disable notifications (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_7   |          | Read HID Service characteristic: Boot        |
|                  |          | Keyboard Output Report (C.1)                 |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_8   |          | Write HID Service characteristic: Boot       |
|                  |          | Keyboard Output Report (C.1)                 |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_9   |          | Read HID Service characteristic: Boot Mouse  |
|                  |          | Input Report (C.2)                           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_10  |          | Write HID Service characteristic: Boot Mouse |
|                  |          | Input Report (C.2)                           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_11  |          | Read Client Characteristic Configuration     |
|                  |          | characteristic descriptor for Boot Mouse     |
|                  |          | Input Report (C.2)                           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_12  |          | Boot Mouse Input Report characteristic       |
|                  |          | configuration: enable notifications (C.2)    |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_12a |          | Boot Mouse Input Report characteristic       |
|                  |          | configuration: disable notifications (O)     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_13  |          | Notify Boot Keyboard Input Report            |
|                  |          | characteristic (C.1)                         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_14  |          | Notify Boot Mouse Input Report characteristic|
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_15  |          | Read Battery Level characteristic (O)        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_16  |          | Read Battery Level characteristic: Client    |
|                  |          | Characteristic Configuration characteristic  |
|                  |          | descriptor (O)                               |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_17  |          | Battery Level characteristic configuration:  |
|                  |          | enable notifications (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_17a |          | Battery Level characteristic configuration:  |
|                  |          | disable notifications (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_18  |          | Notify Battery Level characteristic (O)      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_12_19  |          | Read PnP ID characteristic (O)               |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory IF HOGP 10/5 "Discover HID Service characteristic: Boot
  Keyboard Input Report" OR HOGP 10/7 "Discover HID Service characteristic:
  Boot Keyboard Output Report", otherwise Excluded.
- C.2: Mandatory IF HOGP 10/8 "Discover HID Service characteristic: Boot
  Mouse Input Report", otherwise Excluded.

HID Host
========
**Table 13: GATT Requirements - Report Host**

Prerequisite: HOGP 1/2 "Report Host"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_13_1   | x        | GATT Client over LE (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_3   | x        | Discover All Primary Services (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_4   | x        | Discover Primary Services by Service UUID    |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_5   | x        | Find Included Services (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_6   | x        | Discover All Characteristics of a Service    |
|                  |          | (C.2)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_7   | x        | Discover Characteristics by UUID (C.2)       |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_8   | x        | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_9   | x        | Read Characteristic Value (C.3)              |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_10  | x        | Read Using Characteristic UUID (C.3)         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_11  | x        | Read Long Characteristic Values (C.4)        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_12  | x        | Read Characteristic Descriptors (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_13  | x        | Write without Response (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_14  | x        | Write Characteristic Value (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_15  | x        | Write Characteristic Descriptors (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_16  | x        | Notifications (M)                            |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_13_17  |          | Exchange MTU (O)                             |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one of HOGP 13/3 "Discover All Primary
  Services" OR HOGP 13/4 "Discover Primary Services by Service UUID".
- C.2: Mandatory to support at least one of HOGP 13/6 "Discover All
  Characteristics of a Service" OR HOGP 13/7 "Discover Characteristics by
  UUID".
- C.3: Mandatory to support at least one of HOGP 13/9 "Read Characteristic
  Value" OR HOGP 13/10 "Read Using Characteristic UUID".
- C.4: Mandatory IF HOGP 13/9 "Read Characteristic Value" OR HOGP 13/10 "Read
  Using Characteristic UUID", otherwise not defined.

HID Host
========
**Table 14: GATT Requirements - Boot Host**

Prerequisite: HOGP 1/3 "Boot Host"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_14_1   |          | GATT Client over LE (M)                      |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_3   |          | Discover All Primary Services (C.1)          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_4   |          | Discover Primary Services by Service UUID    |
|                  |          | (C.1)                                        |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_5   |          | Discover All Characteristics of a Service (O)|
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_6   |          | Discover Characteristics by UUID (O)         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_7   |          | Discover All Characteristic Descriptors (M)  |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_8   |          | Read Characteristic Value (M)                |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_9   |          | Read Using Characteristic UUID (M)           |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_10  |          | Read Characteristic Descriptors (M)          |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_11  |          | Write without Response (M)                   |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_12  |          | Write Characteristic Value (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_13  |          | Write Characteristic Descriptors (M)         |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_14_14  |          | Notifications (M)                            |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one of HOGP 14/3 "Discover All Primary
  Services" OR HOGP 14/4 "Discover Primary Services by Service UUID".

HID Host
========
**Table 15: GAP Requirements - HID Host**

Prerequisite: HOGP 1/2 "Report Host" OR HOGP 1/3 "Boot Host"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_HOGP_15_1   | x        | Central (M)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_15_2   | x        | LE security mode 1 (Central) (M)             |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_15_3   | x        | Unauthenticated Pairing (LE security mode 1  |
|                  |          | level 2) (Central) (M)                       |
+------------------+----------+----------------------------------------------+
| TSPC_HOGP_15_4   |          | Authenticated Pairing (LE security mode 1    |
|                  |          | level 3) (Central) (O)                       |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

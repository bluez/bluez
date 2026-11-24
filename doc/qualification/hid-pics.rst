.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

==============================
Human Interface Device Profile
==============================
(TCRL 2023-1, HID.ICS.p9)

Versions
========
**Table 0: Major Versions (X.Y)**

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_0_1   | x        | HID v1.0 (M)                                   |
+----------------+----------+------------------------------------------------+

Roles
=====
**Table 1: Role Requirements**

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_1_1   | x        | Host, Report protocol (C.1)                    |
+----------------+----------+------------------------------------------------+
| TSPC_HID_1_2   |          | Device (C.1)                                   |
+----------------+----------+------------------------------------------------+
| TSPC_HID_1_3   |          | Host, Boot protocol (C.1)                      |
+----------------+----------+------------------------------------------------+

- C.1: Mandatory to support at least one of HID 1/1 "Host, Report protocol"
  OR HID 1/2 "Device" OR HID 1/3 "Host, Boot protocol".

Host Role
=========
**Table 2: Application Procedures**

Prerequisite: HID 1/1 "Host, Report protocol" OR HID 1/3 "Host, Boot protocol"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_2_1   | x        | Establish HID connection (C.4)                 |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_2   | x        | Accept HID connection (C.4)                    |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_3   | x        | Terminate HID connection (C.4)                 |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_4   | x        | Accept Termination of HID connection (C.4)     |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_5   | x        | Support for virtual cables (C.4)               |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_6   | x        | HID initiated reconnection (C.4)               |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_7   | x        | Host initiated reconnection (C.4)              |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_8   | x        | Host data transfer to HID (C.1)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_9   | x        | HID data transfer to Host (C.1)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_10  |          | HID Boot mode data transfer to Host (C.2)      |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_11  |          | Host Boot mode data transfer to HID (C.2)      |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_12  |          | Support for Application to send GET_REPORT (O) |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_13  |          | Support for Application to send SET_REPORT (O) |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_14  |          | Support for sending HCI_CONTROL with           |
|                |          | VIRTUAL_CABLE_UNPLUG (C.3)                     |
+----------------+----------+------------------------------------------------+
| TSPC_HID_2_15  |          | Support for receiving HCI_CONTROL with         |
|                |          | VIRTUAL_CABLE_UNPLUG (C.3)                     |
+----------------+----------+------------------------------------------------+

- O: Optional
- C.1: Mandatory IF HID 1/1 "Host, Report protocol", otherwise Optional.
- C.2: Mandatory IF HID 1/3 "Host, Boot protocol", otherwise Optional.
- C.3: Optional IF HID 2/5 "Support for virtual cables", otherwise Excluded.
- C.4: Mandatory IF HID 1/1 "Host, Report protocol", otherwise Optional.

Host Role
=========
**Table 3: Device to Host Transfers**

Prerequisite: HID 1/1 "Host, Report protocol" OR HID 1/3 "Host, Boot protocol"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_3_1   |          | Data reports larger than host MTU on Control   |
|                |          | channel (O)                                    |
+----------------+----------+------------------------------------------------+
| TSPC_HID_3_2   |          | Data reports larger than host MTU on Interrupt |
|                |          | channel (C.1)                                  |
+----------------+----------+------------------------------------------------+
| TSPC_HID_3_3   |          | Data reports to host (C.1)                     |
+----------------+----------+------------------------------------------------+
| TSPC_HID_3_4   |          | Boot mode reports to host (C.2)                |
+----------------+----------+------------------------------------------------+

- O: Optional
- C.1: Excluded IF HID 1/3 "Host, Boot protocol", otherwise Mandatory IF HID
  2/12 "Support for Application to send GET_REPORT", otherwise Optional.
- C.2: Mandatory IF HID 1/3 "Host, Boot protocol", otherwise Optional.

Host Role
=========
**Table 4: Host to Device Transfers**

Prerequisite: HID 1/1 "Host, Report protocol" OR HID 1/3 "Host, Boot protocol"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_4_1   |          | Data reports larger than device MTU on Control |
|                |          | channel (C.1)                                  |
+----------------+----------+------------------------------------------------+
| TSPC_HID_4_2   |          | Data reports larger than device MTU on         |
|                |          | Interrupt channel (C.1)                        |
+----------------+----------+------------------------------------------------+
| TSPC_HID_4_3   | x        | Data reports to device (C.2)                   |
+----------------+----------+------------------------------------------------+
| TSPC_HID_4_4   |          | Boot mode reports to device (O)                |
+----------------+----------+------------------------------------------------+

- O: Optional
- C.1: Excluded IF HID 1/3 "Host, Boot protocol", otherwise Optional.
- C.2: Excluded IF HID 1/3 "Host, Boot protocol", otherwise Mandatory.

Host Role
=========
**Table 5: HID Control Commands**

Prerequisite: HID 1/1 "Host, Report protocol" OR HID 1/3 "Host, Boot protocol"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_5_1   |          | Set_Protocol command (C.1, C.4)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_5_2   |          | Get_Protocol command (C.1, C.4)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_5_3   |          | Set_Idle command (O)                           |
+----------------+----------+------------------------------------------------+
| TSPC_HID_5_4   |          | Get_Idle command (O)                           |
+----------------+----------+------------------------------------------------+
| TSPC_HID_5_5   |          | Set_Report command (C.2)                       |
+----------------+----------+------------------------------------------------+
| TSPC_HID_5_6   |          | Get_Report command (C.3)                       |
+----------------+----------+------------------------------------------------+

- O: Optional
- C.1: Mandatory IF HID 1/3 "Host, Boot protocol", otherwise Optional.
- C.2: Mandatory IF HID 1/1 "Host, Report protocol" AND HID 2/13 "Support for
  Application to send SET_REPORT", otherwise Excluded.
- C.3: Mandatory IF HID 1/1 "Host, Report protocol" AND HID 2/12 "Support for
  Application to send GET_REPORT", otherwise Excluded.
- C.4: Mandatory to support none or all of HID 5/1 "Set_Protocol command" OR
  HID 5/2 "Get_Protocol command".

Host Role
=========
**Table 6: LMP Requirements**

Prerequisite: HID 1/1 "Host, Report protocol" OR HID 1/3 "Host, Boot protocol"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_6_8   | x        | Role switch (C.4)                              |
+----------------+----------+------------------------------------------------+
| TSPC_HID_6_9   | x        | Request role switch (C.4)                      |
+----------------+----------+------------------------------------------------+
| TSPC_HID_6_12  | x        | Sniff mode (C.4)                               |
+----------------+----------+------------------------------------------------+

- C.4: Mandatory IF HID 1/1 "Host, Report protocol", otherwise not defined.

HID Role
========
**Table 8: HID Device Types**

Prerequisite: HID 1/2 "Device"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_8_1   |          | Pointing HID (C.1)                             |
+----------------+----------+------------------------------------------------+
| TSPC_HID_8_2   |          | Keyboard HID (C.1)                             |
+----------------+----------+------------------------------------------------+
| TSPC_HID_8_3   |          | Identification HID (C.1)                       |
+----------------+----------+------------------------------------------------+
| TSPC_HID_8_4   |          | Other HID (C.1)                                |
+----------------+----------+------------------------------------------------+

- C.1: Mandatory to support at least one of HID 8/1 "Pointing HID" OR HID 8/2
  "Keyboard HID" OR HID 8/3 "Identification HID" OR HID 8/4 "Other HID" IF
  HID 1/2 "Device", otherwise Excluded.

HID Role
========
**Table 9: Application Procedures**

Prerequisite: HID 1/2 "Device"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_9_1   |          | Establish HID connection (O)                   |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_2   |          | Accept HID connection (M)                      |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_3   |          | Terminate HID connection (O)                   |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_4   |          | Accept Termination of HID connection (M)       |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_5   |          | Support for virtual cables (O)                 |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_6   |          | HID initiated reconnection (C.1)               |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_7   |          | Host initiated reconnection (C.1)              |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_8   |          | Host data transfer to HID (C.2)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_9   |          | HID data transfer to Host (C.2)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_10  |          | HID Boot mode data transfer to Host (C.3)      |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_11  |          | Host Boot mode data transfer to HID (C.4)      |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_12  |          | Output reports declared (C.4)                  |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_13  |          | Input reports declared (C.3)                   |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_14  |          | Feature reports declared (O)                   |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_15  |          | Support for sending HCI_CONTROL with           |
|                |          | VIRTUAL_CABLE_UNPLUG (C.5)                     |
+----------------+----------+------------------------------------------------+
| TSPC_HID_9_16  |          | Support for receiving HCI_CONTROL with         |
|                |          | VIRTUAL_CABLE_UNPLUG (C.5)                     |
+----------------+----------+------------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Mandatory to support at least one of HID 9/6 "HID initiated
  reconnection" OR HID 9/7 "Host initiated reconnection" IF HID 9/5 "Support
  for virtual cables", otherwise Excluded.
- C.2: Mandatory to support at least one of HID 9/8 "Host data transfer to
  HID" OR HID 9/9 "HID data transfer to Host" IF HID 1/2 "Device", otherwise
  Excluded.
- C.3: Mandatory IF HID 8/1 "Pointing HID" OR HID 8/2 "Keyboard HID",
  otherwise Excluded.
- C.4: Mandatory IF HID 8/2 "Keyboard HID", otherwise Excluded.
- C.5: Optional IF HID 9/5 "Support for virtual cables", otherwise Excluded.

HID Role
========
**Table 10: Device to Host Transfers**

Prerequisite: HID 9/13 "Input reports declared" OR HID 9/14 "Feature reports
declared"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_10_1  |          | Data reports larger than host MTU on Control   |
|                |          | channel (O)                                    |
+----------------+----------+------------------------------------------------+
| TSPC_HID_10_2  |          | Data reports larger than host MTU on Interrupt |
|                |          | channel (O)                                    |
+----------------+----------+------------------------------------------------+
| TSPC_HID_10_3  |          | Data reports to host (O)                       |
+----------------+----------+------------------------------------------------+
| TSPC_HID_10_4  |          | Boot mode reports to host (C.1)                |
+----------------+----------+------------------------------------------------+

- O: Optional
- C.1: Mandatory IF HID 8/1 "Pointing HID" OR HID 8/2 "Keyboard HID",
  otherwise Optional IF HID 8/3 "Identification HID" OR HID 8/4 "Other HID",
  otherwise Excluded.

HID Role
========
**Table 11: Host to Device Transfers**

Prerequisite: HID 9/12 "Output reports declared" OR HID 9/14 "Feature reports
declared"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_11_1  |          | Data reports larger than device MTU on Control |
|                |          | channel (O)                                    |
+----------------+----------+------------------------------------------------+
| TSPC_HID_11_2  |          | Data reports larger than device MTU on         |
|                |          | Inetrrupt channel (O)                          |
+----------------+----------+------------------------------------------------+
| TSPC_HID_11_3  |          | Data reports to device (O)                     |
+----------------+----------+------------------------------------------------+
| TSPC_HID_11_4  |          | Boot mode reports to device (C.1)              |
+----------------+----------+------------------------------------------------+

- O: Optional
- C.1: Mandatory IF HID 8/2 "Keyboard HID", otherwise Optional IF HID 8/1
  "Pointing HID" OR HID 8/3 "Identification HID" OR HID 8/4 "Other HID",
  otherwise Excluded.

HID Role
========
**Table 12: HID Control Commands**

Prerequisite: HID 1/2 "Device"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_12_1  |          | Set_Protocol command (C.1, C.5)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_12_2  |          | Get_Protocol command (C.1, C.5)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_12_3  |          | Set_Idle command (C.2)                         |
+----------------+----------+------------------------------------------------+
| TSPC_HID_12_4  |          | Get_Idle command (C.2)                         |
+----------------+----------+------------------------------------------------+
| TSPC_HID_12_5  |          | Set_Report command (C.3)                       |
+----------------+----------+------------------------------------------------+
| TSPC_HID_12_6  |          | Get_Report command (C.4)                       |
+----------------+----------+------------------------------------------------+

- C.1: Mandatory IF HID 8/1 "Pointing HID" OR HID 8/2 "Keyboard HID",
  otherwise Optional IF HID 8/3 "Identification HID" OR HID 8/4 "Other HID",
  otherwise Excluded.
- C.2: Mandatory IF HID 8/2 "Keyboard HID", otherwise Optional IF HID 8/1
  "Pointing HID" OR HID 8/3 "Identification HID" OR HID 8/4 "Other HID",
  otherwise Excluded.
- C.3: Mandatory IF HID 9/12 "Output reports declared" OR HID 9/14 "Feature
  reports declared", otherwise Excluded.
- C.4: Mandatory IF HID 9/13 "Input reports declared" OR HID 9/14 "Feature
  reports declared", otherwise Excluded.
- C.5: Mandatory to support none or all of HID 12/1 "Set_Protocol command" OR
  HID 12/2 "Get_Protocol command".

HID Role
========
**Table 13: LMP Requirements**

Prerequisite: HID 1/2 "Device"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_13_8  |          | Role switch (C.3)                              |
+----------------+----------+------------------------------------------------+

- C.3: Mandatory IF HID 9/6 "HID initiated reconnection", otherwise not
  defined.

HID Role
========
**Table 15: SDP Requirements**

Prerequisite: HID 1/2 "Device"

+----------------+----------+------------------------------------------------+
| Parameter Name | Selected | Description                                    |
+================+==========+================================================+
| TSPC_HID_15_1  |          | Server (M)                                     |
+----------------+----------+------------------------------------------------+
| TSPC_HID_15_2  |          | LanguageBaseAttributeIdList (M)                |
+----------------+----------+------------------------------------------------+
| TSPC_HID_15_3  |          | ServiceClassIDList (M)                         |
+----------------+----------+------------------------------------------------+
| TSPC_HID_15_4  |          | ProtocolDescriptorList (M)                     |
+----------------+----------+------------------------------------------------+
| TSPC_HID_15_5  |          | BluetoothProfileDescriptorList (M)             |
+----------------+----------+------------------------------------------------+
| TSPC_HID_15_6  |          | AdditionalProtocolDescriptorList (M)           |
+----------------+----------+------------------------------------------------+

- M: Mandatory

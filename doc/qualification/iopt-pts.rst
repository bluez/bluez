.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

=================
IOPT test results
=================

:PTS version: 8.5.3 Build 4

Setup
=====

- Remove PTS device from Bluetooth devices

- In ICS select:

  - TSPC_support_AdvancedAudioDistributionProfile_Sink

  - TSPC_support_AdvancedAudioDistributionProfile_Source

  - TSPC_support_AVRemoteControlProfile_CT

  - TSPC_support_AVRemoteControlProfile_TG

  - TSPC_support_HeadsetProfile_AG

  - TSPC_support_SerialPortProfile_Service

Tests
=====

The kernel and BlueZ versions represent the oldest version without backport
for which we know the test passed.

+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| Test name            | Result   | Kernel  | BlueZ |                                                                         |
+======================+==========+=========+=======+=========================================================================+
| IOPT/SR/COD/BV-01-I  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Start '$ bluetoothctl'                                                |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# discoverable on                                        |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| IOPT/SR/SDSS/BV-02-I | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Start '$ bluetoothctl'                                                |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# discoverable on                                        |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run in a second terminal:                                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - python ./test-profile -u spp -s -C 10                               |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| IOPT/SR/SDAS/BV-03-I | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Start '$ bluetoothctl'                                                |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# discoverable on                                        |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run in a second terminal:                                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - python ./test-profile -u spp -s -C 10                               |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| IOPT/CL/SDR/BV-04-I  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Start '$ bluetoothctl'                                                |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | - Pair PTS device                                                       |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Check UUIDs in bluetoothctl: A2DP (110A, 110B), AVRCP (110C),         |
|                      |          |         |       |   HID (1124), HFP (111E, 111F), HSP(1112), OPP(1105), SAP(112D),        |
|                      |          |         |       |   SPP(1101)                                                             |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+

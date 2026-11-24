.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

================
VCP test results
================

:PTS version: 8.12.0 Build 5

Setup
=====

- Remove PTS device from Bluetooth devices

Tests
=====

The kernel and BlueZ versions represent the oldest version without backport
for which we know the test passed.

+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| Test name                    | Result   | Kernel | BlueZ |                                                                         |
+==============================+==========+========+=======+=========================================================================+
| VCP/VC/CGGIT/CHA/BV-01-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| VCP/VC/CGGIT/CHA/BV-02-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| VCP/VC/CGGIT/SER/BV-01-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| VCP/VC/SPE/BI-05-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Volume Control Point'                |
|                              |          |        |       | to handle 0x00DA:                                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| VCP/VC/SPE/BI-06-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Volume Control Point'                |
|                              |          |        |       | to handle 0x00DA:                                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| VCP/VC/SPE/BI-15-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Volume Control Point'                |
|                              |          |        |       | to handle 0x00DA:                                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| VCP/VC/VCCP/BV-05-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Volume Control Point'                |
|                              |          |        |       | to handle 0x00DA:                                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| VCP/VC/VCCP/BV-06-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read Characteristic 'Volume State':                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Volume Control Point'                |
|                              |          |        |       | to handle 0x00DA:                                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+

.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

=================
MICP test results
=================

:PTS version: 8.12.0 Build 6

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
| MICP/CL/CGGIT/CHA/BV-01-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to read Characteristic 'Mute':                                |
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
| MICP/CL/CGGIT/CHA/BV-02-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to read Characteristic 'Audio Input State':                   |
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
| MICP/CL/CGGIT/CHA/BV-03-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to read Characteristic 'Gain Setting Properties':             |
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
| MICP/CL/CGGIT/SER/BV-01-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | Click Yes On 'Please verify that for each supported characteristic,     |
|                              |          |        |       | attribute handle/UUID pair(s) is returned to the upper tester.Mute:     |
|                              |          |        |       | Attribute Handle = 0x00D2.'                                             |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| MICP/CL/CGGIT/SER/BV-02-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | Click Yes on 'Please verify that for each supported characteristic,     |
|                              |          |        |       | attribute handle/UUID pair(s) is returned to the upper tester.Audio:    |
|                              |          |        |       | Input State: Attribute Handle = 0x00F1.'                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| MICP/CL/CP/BV-01-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to read Characteristic 'Audio Input State':                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# select-attribute <handle>                              |
|                              |          |        |       | - [GATT client]# read                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write request to handle 0x00FC                             |
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
| MICP/CL/SPE/BI-01-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to write request to handle 0x00D2                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read the handle 0x00F1                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write request to handle 0x00D3                             |
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
| MICP/CL/SPE/BI-02-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to Client Characteristic Configuration Descriptor             |
|                              |          |        |       | of Audio Input State characteristic to enable notification              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - notify on                                                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read the handle 0x00FC                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write request to handle 0x00F2                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read the handle 0x00F2                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| MICP/CL/SPE/BI-07-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to Client Characteristic Configuration Descriptor             |
|                              |          |        |       | of Audio Input State characteristic to enable notification              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - notify on                                                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read the handle 0x00F2                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Audio Input Control Point with the                   |
|                              |          |        |       | Set Gain Setting Op Code value of 0x01, the Gain Setting parameters     |
|                              |          |        |       | set to a random value greater than 100 and Change Counter parameter set |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Audio Input Control Point with the                   |
|                              |          |        |       | Set Gain Setting Op Code value of 0x01, the Gain Setting parameters     |
|                              |          |        |       | set to a random value less than -100 and Change Counter parameter set   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read the handle 0x00F2                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| MICP/CL/SPE/BI-08-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to Client Characteristic Configuration Descriptor             |
|                              |          |        |       | of Audio Input State characteristic to enable notification              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - notify on                                                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read the handle 0x00F2                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write request to handle 0x00FB                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read the handle 0x00F2                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+

.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

=================
CSIP test results
=================

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
| CSIP/CL/CGGIT/CHA/BV-01-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| CSIP/CL/CGGIT/CHA/BV-02-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to read Characteristic 'Coordinated Set Size':                |
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
| CSIP/CL/CGGIT/CHA/BV-03-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to read Characteristic 'Set Member Lock':                     |
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
| CSIP/CL/CGGIT/CHA/BV-04-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | On demand to read Characteristic 'Set Member Rank':                     |
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
| CSIP/CL/CGGIT/SER/BV-01-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| CSIP/CL/SP/BV-01-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | Click YES on "Please verify that SIRK is not encrypted. Click Yes,      |
|                              |          |        |       | if it is Plain Text otherwise click No."                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| CSIP/CL/SP/BV-03-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
| CSIP/CL/SP/BV-03-C_LT2       |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
| CSIP/CL/SP/BV-03-C_LT3       |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force BlueZ to allow read-write permissions in                        |
|                              |          |        |       |   '/path/to/bluetooth/main.conf'::                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     ExportClaimedServices = read-write                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr1>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr2>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr3>                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Three PTS applications are running and connected 3 dongles            |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d <pts_addr1>                                          |
|                              |          |        |       | - btgatt-client -d <pts_addr2>                                          |
|                              |          |        |       | - btgatt-client -d <pts_addr3>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Set Member Lock' to handle 0x0165:   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please verify IUT write to the Lock characteristic on PTS |
|                              |          |        |       | in ascending order of the Rank characteristic value.                    |
|                              |          |        |       | (LT1, LT2, LT3)."                                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'ExportClaimedServices' to default in                           |
|                              |          |        |       |       '/path/to/bluetooth/main.conf'                                    |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| CSIP/CL/SP/BV-04-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
| CSIP/CL/SP/BV-04-C_LT2       |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
| CSIP/CL/SP/BV-04-C_LT3       |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force BlueZ to allow read-write permissions in                        |
|                              |          |        |       |   '/path/to/bluetooth/main.conf'::                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     ExportClaimedServices = read-write                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr1>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr2>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr3>                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Three PTS applications are running and connected 3 dongles            |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d <pts_addr1>                                          |
|                              |          |        |       | - btgatt-client -d <pts_addr2>                                          |
|                              |          |        |       | - btgatt-client -d <pts_addr3>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Set Member Lock' to handle 0x0165:   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please verify IUT write to the Lock characteristic on PTS |
|                              |          |        |       | in descending order of the Rank characteristic value.                   |
|                              |          |        |       | (LT1, LT2, LT3)."                                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'ExportClaimedServices' to default in                           |
|                              |          |        |       |       '/path/to/bluetooth/main.conf'                                    |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| CSIP/CL/SP/BV-06-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
|                              |          |        |       | Click YES on "Please verify that decrypted SIRK is <SIRK_VALUE>.        |
|                              |          |        |       | Click Yes, if it is Encrypted otherwise click No."                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| CSIP/CL/SP/BV-07-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
| CSIP/CL/SP/BV-07-C_LT2       |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
| CSIP/CL/SP/BV-07-C_LT3       |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr1>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr2>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr3>                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Three PTS applications are running and connected 3 dongles            |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr1>                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr2>                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr3>                                         |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "Please create different workspaces and run this test case  |
|                              |          |        |       | with 3 instances of PTS."                                               |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand disconnect the PTSs.                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please verify the number of discovered Set Members is     |
|                              |          |        |       | equal to 3."                                                            |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| CSIP/CL/SPE/BI-01-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
| CSIP/CL/SPE/BI-01-C_LT2      |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
| CSIP/CL/SPE/BI-01-C_LT3      |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force BlueZ to allow read-write permissions in                        |
|                              |          |        |       |   '/path/to/bluetooth/main.conf'::                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     ExportClaimedServices = read-write                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr1>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr2>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr3>                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Three PTS applications are running and connected 3 dongles            |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d <pts_addr1>                                          |
|                              |          |        |       | - btgatt-client -d <pts_addr2>                                          |
|                              |          |        |       | - btgatt-client -d <pts_addr3>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Set Member Lock' to handle 0x0165:   |
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
|                              |          |        |       |   - Set 'ExportClaimedServices' to default in                           |
|                              |          |        |       |       '/path/to/bluetooth/main.conf'                                    |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| CSIP/CL/SPE/BI-02-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force BlueZ to allow read-write permissions in                        |
|                              |          |        |       |   '/path/to/bluetooth/main.conf'::                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     ExportClaimedServices = read-write                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Set Member Lock' to handle 0x0165:   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read any data:                                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'ExportClaimedServices' to default in                           |
|                              |          |        |       |       '/path/to/bluetooth/main.conf'                                    |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| CSIP/CL/SPE/BI-03-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force BlueZ to allow read-write permissions in                        |
|                              |          |        |       |   '/path/to/bluetooth/main.conf'::                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     ExportClaimedServices = read-write                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to write Characteristic 'Set Member Lock' to handle 0x0165:   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - select-attribute <handle>                                             |
|                              |          |        |       | - write <value that PTS expects> 0x00                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand to read any data:                                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - read                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'ExportClaimedServices' to default in                           |
|                              |          |        |       |       '/path/to/bluetooth/main.conf'                                    |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| CSIP/CL/SPE/BI-04-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm that IUT stopped the                       |
|                              |          |        |       | Coordinated Set Discovery procedure. Click Yes, if stopped.             |
|                              |          |        |       | otherwise click No."                                                    |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+

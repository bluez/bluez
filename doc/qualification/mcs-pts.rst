.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

================
MCS test results
================

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
| GMCS/SR/SGGIT/CHA/BV-01-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/SGGIT/CHA/BV-04-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/SGGIT/CHA/BV-05-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/SGGIT/CHA/BV-06-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/SGGIT/CHA/BV-07-C    | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/SGGIT/CHA/BV-17-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/SGGIT/CHA/BV-18-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/SGGIT/CHA/BV-19-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/SGGIT/CHA/BV-22-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/SGGIT/SER/BV-01-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/MCP/BV-01-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
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
| GMCS/SR/MCP/BV-02-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
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
| GMCS/SR/MCP/BV-03-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
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
| GMCS/SR/MCP/BV-05-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
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
| GMCS/SR/MCP/BV-06-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
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
| GMCS/SR/MCP/BV-07-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
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
| GMCS/SR/MCP/BV-08-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
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
| GMCS/SR/MCP/BV-09-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
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
| GMCS/SR/MCP/BV-10-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
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
| GMCS/SR/MCP/BV-30-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click Ok On 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click Yes On 'Please confirm that Current Track is the same             |
|                              |          |        |       | or has been moved to the Previous Track after Media Control Point       |
|                              |          |        |       | Procedure with Previous Track Opcode.'                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/MCP/BV-31-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click Ok On 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click Yes On 'Please confirm that Current Track is the same             |
|                              |          |        |       | or has been moved to the Previous Track after Media Control Point       |
|                              |          |        |       | Procedure with Previous Track Opcode.'                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/MCP/BV-33-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/MCP/BV-34-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click Ok On 'Please configure that current track set to the next to the |
|                              |          |        |       | Track'                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click Yes On 'Please confirm that Current Track                         |
|                              |          |        |       | has been moved to the Next Track after                                  |
|                              |          |        |       | Procedure with Next Track Opcode.'                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/MCP/BV-35-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click Ok On 'Please configure that current track set to the next to the |
|                              |          |        |       | Track'                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click Yes On 'Please confirm that Current Track                         |
|                              |          |        |       | has been moved to the Next Track after                                  |
|                              |          |        |       | Procedure with Next Track Opcode.'                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/MCP/BV-37-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/MCP/BV-70-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
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
| GMCS/SR/MCP/BV-71-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure an initial state to Inactive state'       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/MCP/BV-72-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure an initial state to Inactive state'       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/MCP/BV-73-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure an initial state to Inactive state'       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/MCP/BV-74-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure an initial state to Inactive state'       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/SP/BV-02-C           | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/SP/BV-03-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | When PTS waits, run 'connect <pts_addr>'                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/SPE/BI-01-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| GMCS/SR/SPE/BI-07-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
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
| IOPT/GMCS/SR/GATTDB/BV-01-I  | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run Lollypop audio player and play an audio file                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Run tools/mpris-proxy in other terminal                               |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on 'Please configure that current track set to the Second      |
|                              |          |        |       | Track'                                                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+

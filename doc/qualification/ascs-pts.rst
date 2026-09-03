.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

=================
ASCS test results
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
| ASCS/SR/ACP/BV-01-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-02-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-03-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-04-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-05-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-06-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-08-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-09-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-10-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-11-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-12-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-13-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-14-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-17-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-18-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-19-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-20-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/ACP/BV-31-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force BlueZ to perform security repairing in                          |
|                              |          |        |       |   '/path/to/bluetooth/main.conf'::                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     JustWorksRepairing = always                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart bluetoothd, PipeWire and WirePlumber                          |
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
|                              |          |        |       | - Reset BlueZ to previous configuration:                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'JustWorksRepairing' to default in                              |
|                              |          |        |       |       '/path/to/bluetooth/main.conf'                                    |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| ASCS/SR/SGGIT/CHA/BV-01-C    | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SGGIT/CHA/BV-02-C    | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SGGIT/CHA/BV-03-C    | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SGGIT/SER/BV-01-C    | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-01-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-02-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-03-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-04-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-05-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-06-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-07-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-08-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-09-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-10-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-11-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-12-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-13-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-14-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-17-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-18-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-19-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| ASCS/SR/SPE/BI-20-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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
| IOPT/ASCS/SR/GATTDB/BV-01-I  | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force Targeted Announcement in 'monitor.bluez.rules' of   |
|                              |          |        |       |   'wireplumber.conf.d/announcement.conf'::                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     monitor.bluez.properties = {                                        |
|                              |          |        |       |       bluez5.bap-server.ascs-announcement = "targeted"                  |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
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

.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Collabora Ltd.

================
BAP test results
================

:PTS version: 8.5.2 Build 5

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
| BAP/CL/CGGIT/SER/BV-01-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand verify that handles and UUIDs are correct from new            |
|                              |          |        |       | characterics listed as::                                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [NEW] Characteristic (Handle <handle - 1>)                            |
|                              |          |        |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<handle - 1>         |
|                              |          |        |       |   0000<UUID>-0000-1000-8000-00805f9b34fb                                |
|                              |          |        |       |   <Characteristic name>                                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - e.g. for PTS device 9C:47:2A:39:56:FE, handle "0x00D2" and UUID       |
|                              |          |        |       |   "0x2BC9"::                                                            |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     [NEW] Characteristic (Handle 0x00d1)                                |
|                              |          |        |       |     /org/bluez/hci0/dev_9C_47_2A_39_56_FE/service00d0/char00d1          |
|                              |          |        |       |     00002bc9-0000-1000-8000-00805f9b34fb                                |
|                              |          |        |       |     Sink PAC                                                            |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/CL/CGGIT/CHA/BV-01-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/CL/CGGIT/CHA/BV-02-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Sink Audio Locations':                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On check if IUT support Write Request: click Yes                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On write request:                                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# write-value <handle> 01 02 03 04                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/CL/CGGIT/CHA/BV-03-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/CL/CGGIT/CHA/BV-04-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Source Audio Locations':              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On check if IUT support Write Request: click Yes                        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On write request:                                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# write-value <handle> 01 02 03 04                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/CL/CGGIT/CHA/BV-05-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Available Audio Contexts':            |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/CL/CGGIT/CHA/BV-06-C     | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Supported Audio Contexts':            |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/ADV/BV-01-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand and after <pts_addr> has been discovered:                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# info <pts_addr>                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Verify that "UUID: Audio Stream Control" exists                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/CGGIT/SER/BV-01-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand verify that handles and UUIDs are correct from new            |
|                              |          |        |       | characterics listed as::                                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [NEW] Characteristic (Handle <handle - 1>)                            |
|                              |          |        |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<handle - 1>         |
|                              |          |        |       |   0000<UUID>-0000-1000-8000-00805f9b34fb                                |
|                              |          |        |       |   <Characteristic name>                                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - e.g. for PTS device 9C:47:2A:39:56:FE, handle "0x0122" and UUID       |
|                              |          |        |       |   "0x2BC4"::                                                            |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     [NEW] Characteristic (Handle 0x0121)                                |
|                              |          |        |       |     /org/bluez/hci0/dev_9C_47_2A_39_56_FE/service0120/char0121          |
|                              |          |        |       |     00002bc4-0000-1000-8000-00805f9b34fb                                |
|                              |          |        |       |     Sink ASE                                                            |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/CGGIT/CHA/BV-01-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Sink Audio Stream Endpoint':          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - repeat on demand                                                    |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/CGGIT/CHA/BV-02-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Source Audio Stream Endpoint':        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - repeat on demand                                                    |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/CGGIT/CHA/BV-03-C    | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On check if IUT support Write Request without Response: click Yes       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On write request:                                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# write-value -w <handle> 01 02 03 04                    |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/DISC/BV-01-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristics:                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - repeat on demand                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On GATT disconnection request, exit btgatt-client using Ctrl-C          |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/DISC/BV-02-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristics:                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - repeat on demand                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On GATT disconnection request, exit btgatt-client using Ctrl-C          |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/DISC/BV-03-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Sink Audio Stream Endpoint':          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On GATT disconnection request, exit btgatt-client using Ctrl-C          |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/DISC/BV-04-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Source Audio Stream Endpoint':        |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On GATT disconnection request, exit btgatt-client using Ctrl-C          |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/DISC/BV-06-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - btgatt-client -d  <pts_addr>                                          |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | On demand to read Characteristic 'Available Audio Contexts':            |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [GATT client]# read-value <handle>                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On GATT disconnection request, exit btgatt-client using Ctrl-C          |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/PD/BV-03-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/PD/BV-04-C           | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-004-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-007-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-008-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-011-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-012-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-014-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-016-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - WirePlumber is stopped                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bc9-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep0] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep0] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep0] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep0] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep0] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep0] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep0] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bcb-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep1] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep1] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep1] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep1] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep1] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep1] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep1] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.presets /local/endpoint/ep1 48_6_1              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - accept the pairing request.                                           |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove local endpoints:                                               |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep0                |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep1                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart Wireplumber                                                   |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-019-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-020-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-023-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-024-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-027-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-028-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-038-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "low-latency"               |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-042-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "low-latency"               |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-046-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "low-latency"               |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-048-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "low-latency"               |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-050-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - WirePlumber is stopped                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bc9-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep0] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep0] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep0] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep0] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep0] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep0] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep0] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bcb-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep1] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep1] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep1] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep1] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep1] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep1] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep1] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.presets /local/endpoint/ep1 48_6_1              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - accept the pairing request.                                           |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove local endpoints:                                               |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep0                |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep1                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart Wireplumber                                                   |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-054-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "low-latency"               |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-058-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "low-latency"               |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-077-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "high-reliabilty"           |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-078-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "high-reliabilty"           |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-080-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "high-reliabilty"           |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-082-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - WirePlumber is stopped                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bc9-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep0] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep0] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep0] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep0] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep0] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep0] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep0] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bcb-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep1] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep1] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep1] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep1] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep1] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep1] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep1] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.presets /local/endpoint/ep1 48_6_2              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - accept the pairing request.                                           |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove local endpoints:                                               |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep0                |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep1                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart Wireplumber                                                   |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-093-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "high-reliabilty"           |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/SCC/BV-094-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force low-latency QoS in 'monitor.bluez.rules' of         |
|                              |          |        |       |   'wireplumber.conf.d/bluetooth.conf'::                                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     {                                                                   |
|                              |          |        |       |       matches = [ { device.name = "~bluez_card.*" } ]                   |
|                              |          |        |       |       actions = {                                                       |
|                              |          |        |       |         update-props = {                                                |
|                              |          |        |       |           bluez5.bap.force-target-latency = "high-reliabilty"           |
|                              |          |        |       |         }                                                               |
|                              |          |        |       |       }                                                                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove the rule in 'wireplumber.conf.d/bluetooth.conf'                |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-523-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | and audio input are set to the PTS device.                              |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-526-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
| BAP/UCL/STR/BV-526-C_LT2     |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr1>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr2>                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       | - Two PTS applications are running and connected 2 dongles              |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr1>                                      |
|                              |          |        |       | - [bluetooth]# connect <pts_addr2>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | and audio input are set to the PTS devices.                             |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-527-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-528-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
| BAP/UCL/STR/BV-528-C_LT2     |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr1>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr2>                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       | - Two PTS applications are running and connected to 2 dongles           |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr1>                                      |
|                              |          |        |       | - [bluetooth]# connect <pts_addr2>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-529-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-530-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
| BAP/UCL/STR/BV-530-C_LT2     |          |        |       | - Remove PTS devices:                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr1>                                     |
|                              |          |        |       |   - bluetoothctl remove <pts_addr2>                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       | - Two PTS applications are running and connected to 2 dongles           |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr1>                                      |
|                              |          |        |       | - [bluetooth]# connect <pts_addr2>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-535-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-537-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-538-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-543-C         | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - WirePlumber is stopped                                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Create data file:                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - dd if=/dev/zero of=/tmp/bap.data bs=512 count=1                     |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bc9-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep0] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep0] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep0] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep0] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep0] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep0] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep0] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bcb-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep1] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep1] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep1] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep1] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep1] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep1] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep1] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | After transport Desynchronized properties are displayed:                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.desync \                                    |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_sink0/fd0 on                        |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.acquire \                                   |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_sink0/fd0                           |
|                              |          |        |       |                                                                         |
|                              |          |        |       | After transport has been acquired:                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.acquire \                                   |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_source0/fd1                         |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.send \                                      |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_sink0/fd0 /tmp/bap.data             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "After processed audio stream data, please click OK"        |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove local endpoints:                                               |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep0                |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep1                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart Wireplumber                                                   |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-546-C         | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - WirePlumber is stopped                                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Create data file:                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - dd if=/dev/zero of=/tmp/bap.data bs=512 count=1                     |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bc9-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep0] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep0] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep0] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep0] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep0] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep0] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep0] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bcb-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep1] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep1] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep1] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep1] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep1] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep1] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep1] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | After transport Desynchronized properties are displayed:                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.desync \                                    |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_source0/fd1 on                      |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.acquire \                                   |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_source0/fd1                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | After transport has been acquired:                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.acquire \                                   |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_sink0/fd0                           |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.send \                                      |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_sink0/fd0 /tmp/bap.data             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "After processed audio stream data, please click OK"        |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove local endpoints:                                               |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep0                |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep1                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart Wireplumber                                                   |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-552-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-553-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-554-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-555-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-556-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-557-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-558-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-559-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-568-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-569-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio input  |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-570-C         | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - WirePlumber is stopped                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bc9-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep0] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep0] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep0] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep0] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep0] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep0] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep0] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# endpoint.register 00002bcb-0000-1000-8000-00805f9b34fb \ |
|                              |          |        |       |   0x06                                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | .. code-block::                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   [/local/endpoint/ep1] Auto Accept (yes/no): y                         |
|                              |          |        |       |   [/local/endpoint/ep1] Max Transports (auto/value): a                  |
|                              |          |        |       |   [/local/endpoint/ep1] Locations: 1                                    |
|                              |          |        |       |   [/local/endpoint/ep1] Supported Context (value): 3                    |
|                              |          |        |       |   [/local/endpoint/ep1] Context (value): 3                              |
|                              |          |        |       |   [/local/endpoint/ep1] CIG (auto/value): 0                             |
|                              |          |        |       |   [/local/endpoint/ep1] CIS (auto/value): 0                             |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | After transport properties are displayed:                               |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [PTS-BAP-FE56]> transport.acquire \                                   |
|                              |          |        |       |   /org/bluez/hci0/dev_<BD_ADDR>/pac_source0/fd0                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "After processed audio stream data, please click OK"        |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove local endpoints:                                               |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep0                |
|                              |          |        |       |   - [bluetooth]# endpoint.unregister /local/endpoint/ep1                |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart Wireplumber                                                   |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-575-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-577-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-578-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/UCL/STR/BV-579-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - PipeWire And WirePlumber are running                                  |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl':                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# scan on                                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand:                                                              |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - [bluetooth]# connect <pts_addr>                                       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | If nothing occurs after connection and pairing, check that audio output |
|                              |          |        |       | is set to the PTS device.                                               |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/USR/ADV/BV-01-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/ADV/BV-04-C          | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/DISC/BV-01-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/DISC/BV-02-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/DISC/BV-05-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/DISC/BV-06-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/DISC/BV-07-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-003-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-004-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-006-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-007-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-008-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-011-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-012-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-013-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-014-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-015-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-016-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-019-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-020-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-023-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-024-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-071-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-072-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-075-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-076-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-079-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-080-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-081-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-082-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-083-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-084-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-087-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-088-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-091-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-092-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-104-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-106-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-111-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-112-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-113-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-114-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-115-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-116-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-135-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-136-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-137-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-138-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-139-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-143-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-144-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-145-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-146-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-147-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-148-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-149-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-150-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-161-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-162-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-163-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-167-C         | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
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
| BAP/USR/SCC/BV-168-C         | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
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
| BAP/USR/SPE/BI-01-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
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
| BAP/USR/SPE/BI-02-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
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
| BAP/USR/SPE/BI-03-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
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
| BAP/USR/SPE/BI-04-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
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
| BAP/USR/SPE/BI-05-C          | PASS     | 6.14   | 5.87  | Pre-condition:                                                          |
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
| BAP/USR/STR/BV-360-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force automatic linking of Bluetooth input and Bluetooth  |
|                              |          |        |       |   output ensuring both are opened using                                 |
|                              |          |        |       |   'wireplumber.conf.d/auto-bluez.conf'::                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     wireplumber.components = [ {                                        |
|                              |          |        |       |       name = /path/to/.config/wireplumber/scripts/                      |
|                              |          |        |       |              link-bt-microphone-with-speakers.lua,                      |
|                              |          |        |       |       type = script/lua,                                                |
|                              |          |        |       |       requires = [ si.standard-link, si.audio-adapter ]                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   Refer Scripts section for 'link-bt-microphone-with-speakers.lua'      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm received streaming data..." request.       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "Please send valid streaming data" request.                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please click yes when IUT has verified audio stream data" |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/USR/STR/BV-362-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force automatic linking of Bluetooth input and Bluetooth  |
|                              |          |        |       |   output ensuring both are opened using                                 |
|                              |          |        |       |   'wireplumber.conf.d/auto-bluez.conf'::                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     wireplumber.components = [ {                                        |
|                              |          |        |       |       name = /path/to/.config/wireplumber/scripts/                      |
|                              |          |        |       |              link-bt-microphone-with-speakers.lua,                      |
|                              |          |        |       |       type = script/lua,                                                |
|                              |          |        |       |       requires = [ si.standard-link, si.audio-adapter ]                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   Refer Scripts section for 'link-bt-microphone-with-speakers.lua'      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm received streaming data..." request.       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "Please send valid streaming data" request.                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please click yes when IUT has verified audio stream data" |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/USR/STR/BV-367-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force automatic linking of Bluetooth input and Bluetooth  |
|                              |          |        |       |   output ensuring both are opened using                                 |
|                              |          |        |       |   'wireplumber.conf.d/auto-bluez.conf'::                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     wireplumber.components = [ {                                        |
|                              |          |        |       |       name = /path/to/.config/wireplumber/scripts/                      |
|                              |          |        |       |              link-bt-microphone-with-speakers.lua,                      |
|                              |          |        |       |       type = script/lua,                                                |
|                              |          |        |       |       requires = [ si.standard-link, si.audio-adapter ]                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   Refer Scripts section for 'link-bt-microphone-with-speakers.lua'      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm received streaming data..." request.       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/USR/STR/BV-369-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force automatic linking of Bluetooth input and Bluetooth  |
|                              |          |        |       |   output ensuring both are opened using                                 |
|                              |          |        |       |   'wireplumber.conf.d/auto-bluez.conf'::                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     wireplumber.components = [ {                                        |
|                              |          |        |       |       name = /path/to/.config/wireplumber/scripts/                      |
|                              |          |        |       |              link-bt-microphone-with-speakers.lua,                      |
|                              |          |        |       |       type = script/lua,                                                |
|                              |          |        |       |       requires = [ si.standard-link, si.audio-adapter ]                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   Refer Scripts section for 'link-bt-microphone-with-speakers.lua'      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm received streaming data..." request.       |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/USR/STR/BV-375-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force automatic linking of Bluetooth input and Bluetooth  |
|                              |          |        |       |   output ensuring both are opened using                                 |
|                              |          |        |       |   'wireplumber.conf.d/auto-bluez.conf'::                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     wireplumber.components = [ {                                        |
|                              |          |        |       |       name = /path/to/.config/wireplumber/scripts/                      |
|                              |          |        |       |              link-bt-microphone-with-speakers.lua,                      |
|                              |          |        |       |       type = script/lua,                                                |
|                              |          |        |       |       requires = [ si.standard-link, si.audio-adapter ]                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   Refer Scripts section for 'link-bt-microphone-with-speakers.lua'      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm received streaming data..." request.       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "Please send valid streaming data" request.                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please click yes when IUT has verified audio stream data" |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/USR/STR/BV-377-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force automatic linking of Bluetooth input and Bluetooth  |
|                              |          |        |       |   output ensuring both are opened using                                 |
|                              |          |        |       |   'wireplumber.conf.d/auto-bluez.conf'::                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     wireplumber.components = [ {                                        |
|                              |          |        |       |       name = /path/to/.config/wireplumber/scripts/                      |
|                              |          |        |       |              link-bt-microphone-with-speakers.lua,                      |
|                              |          |        |       |       type = script/lua,                                                |
|                              |          |        |       |       requires = [ si.standard-link, si.audio-adapter ]                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   Refer Scripts section for 'link-bt-microphone-with-speakers.lua'      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm received streaming data..." request.       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "Please send valid streaming data" request.                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please click yes when IUT has verified audio stream data" |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/USR/STR/BV-378-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force automatic linking of Bluetooth input and Bluetooth  |
|                              |          |        |       |   output ensuring both are opened using                                 |
|                              |          |        |       |   'wireplumber.conf.d/auto-bluez.conf'::                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     wireplumber.components = [ {                                        |
|                              |          |        |       |       name = /path/to/.config/wireplumber/scripts/                      |
|                              |          |        |       |              link-bt-microphone-with-speakers.lua,                      |
|                              |          |        |       |       type = script/lua,                                                |
|                              |          |        |       |       requires = [ si.standard-link, si.audio-adapter ]                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   Refer Scripts section for 'link-bt-microphone-with-speakers.lua'      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm received streaming data..." request.       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "Please send valid streaming data" request.                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please click yes when IUT has verified audio stream data" |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+
| BAP/USR/STR/BV-380-C         | PASS     | 6.14   | 5.85  | Pre-condition:                                                          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Force PTS to perform pairing:                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'TRUE' in IXIT Tool window of PTS          |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Remove PTS device:                                                    |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - bluetoothctl remove <pts_addr>                                      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Add rule to force automatic linking of Bluetooth input and Bluetooth  |
|                              |          |        |       |   output ensuring both are opened using                                 |
|                              |          |        |       |   'wireplumber.conf.d/auto-bluez.conf'::                                |
|                              |          |        |       |                                                                         |
|                              |          |        |       |     wireplumber.components = [ {                                        |
|                              |          |        |       |       name = /path/to/.config/wireplumber/scripts/                      |
|                              |          |        |       |              link-bt-microphone-with-speakers.lua,                      |
|                              |          |        |       |       type = script/lua,                                                |
|                              |          |        |       |       requires = [ si.standard-link, si.audio-adapter ]                 |
|                              |          |        |       |     }                                                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   Refer Scripts section for 'link-bt-microphone-with-speakers.lua'      |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Restart PipeWire And WirePlumber                                      |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Run 'bluetoothctl'.                                                     |
|                              |          |        |       |                                                                         |
|                              |          |        |       | On demand accept the pairing request.                                   |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please confirm received streaming data..." request.       |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click OK on "Please send valid streaming data" request.                 |
|                              |          |        |       |                                                                         |
|                              |          |        |       | Click YES on "Please click yes when IUT has verified audio stream data" |
|                              |          |        |       | request.                                                                |
|                              |          |        |       +-------------------------------------------------------------------------+
|                              |          |        |       | Post-condition:                                                         |
|                              |          |        |       |                                                                         |
|                              |          |        |       | - Reset PTS to previous configuration:                                  |
|                              |          |        |       |                                                                         |
|                              |          |        |       |   - Set 'TSPX_delete_ltk' to 'FALSE' in IXIT Tool window of PTS         |
|                              |          |        |       |                                                                         |
+------------------------------+----------+--------+-------+-------------------------------------------------------------------------+

Scripts
========

The script below is useful to automate the linking of Bluetooth input and
Bluetooth output, ensuring both are opened.

link-bt-microphone-with-speakers.lua::

    #!/usr/bin/wpexec

    log = Log.open_topic('auto-bluez')

    function parseBool (var)
      return var and (var:lower () == "true" or var == "1")
    end

    function createLink (si, target)
      local si_props = si.properties
      local target_props = target.properties
      local out_item = nil
      local in_item = nil
      local si_link = nil

      if si_props["item.node.direction"] == "output" then
        -- playback
        out_item = si
        in_item = target
      else
        -- capture
        in_item = si
        out_item = target
      end

      log:info (si,
        string.format ("link %s <-> %s",
          tostring (si_props ["node.name"]),
          tostring (target_props ["node.name"])))

      -- create and configure link
      si_link = SessionItem ("si-standard-link")
      if not si_link:configure {
        ["out.item"] = out_item,
        ["in.item"] = in_item,
        ["passthrough"] = false,
        ["exclusive"] = parseBool (si_props ["node.exclusive"]),
        ["out.item.port.context"] = "output",
        ["in.item.port.context"] = "input",
        ["media.role"] = si_props["media.role"],
        ["target.media.class"] = target_props["media.class"],
        ["policy.role-based.priority"] = target_props["policy.role-based.priority"],
        ["policy.role-based.action.same-priority"] = target_props["policy.role-based.action.same-priority"],
        ["policy.role-based.action.lower-priority"] = target_props["policy.role-based.action.lower-priority"],
        ["is.role.policy.link"] = nil,
        ["main.item.id"] = si.id,
        ["target.item.id"] = target.id,
      } then
        log:info (si, "Error configuring link")
        return
      end

      -- Register
      si_link:register ()

      -- Activate
      si_link:activate (Feature.SessionItem.ACTIVE, function (l, e)
        if e then
          log:info (si, "Error activating link")
          l:remove ()
        else
          -- Success activating link
          log:info (si, "Link activated")
        end
      end)
    end

    linkables_om = ObjectManager {
      Interest { type = "SiLinkable" }
    }

    links_om = ObjectManager {
      Interest { type = "Link" }
    }

    linkables_om:connect("objects-changed", function (om)
      -- Find the BT microphone linkable
      local bt_microphone = om:lookup {
        type = "SiLinkable",
        Constraint { "node.name", "matches", "bluez_input*"},
      }

      -- Find the speakers linkable
      local speakers = om:lookup {
        type = "SiLinkable",
        Constraint { "node.name", "matches", "alsa_loopback_device*.alsa_output*Speaker*" },
      }

      if bt_microphone ~= nil and speakers ~= nil then
        local link = links_om:lookup {
          Constraint { "link.output.node", "=", bt_microphone.properties["object.id"] },
          Constraint { "link.input.node", "=", speakers.properties["object.id"] }
        }
        if link == nil then
          createLink (bt_microphone, speakers)
        end
      end
    end)

    linkables_om:activate()
    links_om:activate()

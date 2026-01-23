.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

================
GAP test results
================

:PTS version: 8.5.3 Build 4

Setup
=====

- Remove PTS device from Bluetooth devices

- In IXIT update:

  - "TSPX_iut_device_name_in_adv_packet_for_random_address" to the IUT name

  - "TSPX_iut_invalid_connection_interval_min" to "0004"

Tests
=====

The kernel and BlueZ versions represent the oldest version without backport
for which we know the test passed.

+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| Test name              | Result   | Kernel  | BlueZ |                                                                         |
+========================+==========+=========+=======+=========================================================================+
| GAP/BROB/BCST/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt':                                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# add-adv -d                                                    |
|                        |          |         |       |   0201040503001801180D095054532D4741502D3036423803190000 1              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# advertising on                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# advertising off                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# advertising on                                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BROB/BCST/BV-02-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt':                                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# add-adv -d                                                    |
|                        |          |         |       |   0201040503001801180D095054532D4741502D3036423803190000 1              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# advertising on                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# advertising off                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# advertising on                                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BROB/BCST/BV-03-C  | PASS     |     6.9 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# remove <bdaddr>                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# power off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.privacy on                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# power on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise.name on                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.add-adv                                           |
|                        |          |         |       |     0201040503001801180D095054532D4741502D3036423803190000 1            |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.connectable on                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.advertising on                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent DisplayYesNo                                     |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# power off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.privacy off                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# power on                                                 |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BROB/OBSV/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt':                                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# find -l                                                       |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BROB/OBSV/BV-02-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt':                                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [mgmt]# find -l                                                       |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/NONM/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on' on demand                               |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/NONM/BV-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# power off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.bredr off'                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.connectable on'                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.discov off'                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# power on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.advertising on                                    |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# power off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.bredr on                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# power on                                                 |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/LIMM/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl' on demand:                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise.discoverable-timeout 30                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise.timeout 45                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/LIMM/BV-02-C  | PASS     |     6.9 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.connectable on                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.advertising on                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.discov limited 30                                 |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/GENM/BV-01-C  | **FAIL** |     6.1 | 5.69  | **"Does the IUT have an ability to send non-connectable advertising     |
|                        |          |         |       | report?"**                                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/GENM/BV-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run :                                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt connectable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt advertising on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt discov on                                               |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/LIMP/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find -L' on demand                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/LIMP/BV-02-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find -L' on demand                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/LIMP/BV-03-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find -L' on demand                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/LIMP/BV-04-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find -L' on demand                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/LIMP/BV-05-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find -L' on demand                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/GENP/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl scan on' on demand                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/GENP/BV-02-C  | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find -L' on demand                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/GENP/BV-03-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl scan on' on demand                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/GENP/BV-04-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl scan on' on demand                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DISC/GENP/BV-05-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl scan on' on demand                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/NAMP/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on' on demand                               |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/NAMP/BV-02-C  | PASS     |     6.1 | 5.69  |                                                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/GIN/BV-01-C   | PASS     |     6.1 | 5.69  |                                                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/DNDIS/BV-01-C | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run :                                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - bluetoothctl discoverable on                                        |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/LIN/BV-01-C   | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find -L' on demand                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/DED/BV-02-C   | PASS     |     6.1 | 5.69  |                                                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/BON/BV-02-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/BON/BV-03-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/BON/BV-04-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/BON/BV-05-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'l2test -n -P 4097 <bdaddr>' on request                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/IDLE/BON/BV-06-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'l2test -n -P 4097 <bdaddr>' on request                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/NCON/BV-01-C  | PASS     |     6.1 | 5.69  | Reply No to question "Does the IUT have an ability to send              |
|                        |          |         |       | non-connectable advertising report?"                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'sudo btmgmt connectable off' on demand                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/NCON/BV-02-C  | PASS     |     6.1 | 5.69  | Reply No to question "Does the IUT have an ability to send              |
|                        |          |         |       | non-connectable advertising report?"                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/NCON/BV-03-C  | PASS     |     6.1 | 5.69  | Reply No to question "Does the IUT have an ability to send              |
|                        |          |         |       | non-connectable advertising report?"                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/DCON/BV-01-C  | **FAIL** |     6.1 | 5.69  | **"Did not find IUT's advertising packet with the event type = 1"       |
|                        |          |         |       | (Directed Connectable Mode ?)**                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/UCON/BV-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt connectable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt advertising on                                          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/UCON/BV-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt connectable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt advertising on                                          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/UCON/BV-03-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt connectable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt advertising on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo btmgmt discov limited 30                                       |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/ACEP/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'btgatt-client -d <pts_addr>' on demand                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/GCEP/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'btgatt-client -d <pts_addr>' on demand                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/GCEP/BV-02-C  | PASS     |     6.1 | 5.69  | Run 'btgatt-client -d <pts_addr>' on demand                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/SCEP/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'btgatt-client -d <pts_addr>' on demand                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/DCEP/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'btgatt-client -d <pts_addr>' on demand                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/DCEP/BV-03-C  | PASS     |     6.1 | 5.69  | Run 'btgatt-client -d <pts_addr>' on demand                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/CPUP/BV-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Request LE Only dongle for PTS                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - bluetoothctl advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/CPUP/BV-02-C  | **FAIL** |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Request LE Only dongle for PTS                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - bluetoothctl advertise on                                           |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | **'This test case expected the 'connection parameter update request' to |
|                        |          |         |       | timeout. Please consider changing the value(s) in                       |
|                        |          |         |       | TSPX_conn_update_int_max, TSPX_conn_update_int_min,                     |
|                        |          |         |       | TSPX_conn_update_peripheral_latency and                                 |
|                        |          |         |       | TSPX_conn_update_supervision_timeout in the IXIT table item(s) and run  |
|                        |          |         |       | the test again.'**                                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/CPUP/BV-03-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Request LE Only dongle for PTS                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - bluetoothctl advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/CPUP/BV-04-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Request LE Only dongle for PTS                                        |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'btgatt-client -d <pts_le_only_addr>' on demand                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/CPUP/BV-05-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Request LE Only dongle for PTS                                        |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'btgatt-client -d <pts_le_only_addr>' on demand                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/CPUP/BV-06-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Request LE Only dongle for PTS                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - ** Request hcitool**                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo systemctl restart bluetooth                                    |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'btgatt-client -d <pts_le_only_addr>' on demand                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | After services has been displayed run in a second terminal:             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - hcitool lecup 1 0x0032 0x0046 0x0001 0x01F4                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/CPUP/BV-08-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - bluetoothctl advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/CPUP/BV-10-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - ** Request hcitool**                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run:                                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo systemctl restart bluetooth                                    |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'bluetoothctl advertise on' on demand                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | After services has been displayed run in a second terminal:             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - hcitool lecup 1 0x0032 0x0046 0x0001 0x01F4                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/CONN/TERM/BV-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/EST/LIE/BV-02-C    | PASS     |     6.1 | 5.69  |                                                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BOND/NBON/BV-01-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl pair <bdaddr>' on demand                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'sudo btmgmt bondable off' on demand                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>' on demand                                 |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo btmgmt bondable on                                               |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BOND/NBON/BV-02-C  | PASS     |     6.1 | 5.69  | Run 'bluetoothctl pair <bdaddr>' on demand                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BOND/NBON/BV-03-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - bluetoothctl advertise on                                             |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo btmgmt bondable off                                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo btmgmt bondable on                                               |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BOND/BON/BV-01-C   | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on' on demand                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BOND/BON/BV-02-C   | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on' on demand                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BOND/BON/BV-03-C   | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on' on demand                               |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/BOND/BON/BV-04-C   | PASS     |     6.1 | 5.69  | Pair to PTS on demand                                                   |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-04-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -S                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Use '0000' Pin code on demand                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-05-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.bondable off                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent NoInputNoOutput                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.bondable on                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-50-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.bondable off                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent NoInputNoOutput                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.bondable on                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-06-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-51-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in the second terminal on demand:                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-07-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc only                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-52-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc only                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-08-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'l2test -n -P 4097 -E <bdaddr>' on demand                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-09-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent NoInputNoOutput                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 8193 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a third terminal on demand:                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr> -S                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-53-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent NoInputNoOutput                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 8193 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in the second terminal on demand:                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 8193 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a third terminal on demand:                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr> -S                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-10-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -E                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Use '0000' Pin code on demand                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BI-24-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run in a first terminal:                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - sudo bluetoothctl mgmt.sc on                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - bluetoothctl discoverable on                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - l2test -r -P 4097                                                   |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run in a second terminal, when PTs is waiting for L2CAP connection (3   |
|                        |          |         |       | secs, may need multiple retry)                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-11-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -E                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Use '0000' Pin code on demand                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-12-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -E                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Use '0000' Pin code on demand                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-13-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -S                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-47-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -S                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-14-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -S                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-48-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -S                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-15-C    | **INC**  |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | (- [bluetooth]# remove <bdaddr>)                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -S                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | **"Please send L2CAP Connection Response with Security Blocked to PTS"**|
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-49-C    | **INC**  |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -r -P 4097 -S                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | **"Please send L2CAP Connection Response with Security Blocked to PTS"**|
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-16-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'l2test -r -P 4097 -E <bdaddr>' on demand                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Use '0000' Pin code on demand                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-17-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'l2test -r -P 4097 -E <bdaddr>' on demand                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Use '0000' Pin code on demand                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-18-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-54-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in the second terminal on demand:                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-19-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-55-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in the second terminal on demand:                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-20-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'l2test -r -P 4097 -E <bdaddr>' on demand                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Use '0000' Pin code on demand                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-21-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run 'bluetoothctl':                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on "ATT service request" demand:                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-22-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-23-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-24-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc on                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-25-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc only                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-56-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - **Request patch                                                       |
|                        |          |         |       |   shared-gatt-Add-env-variable-to-prefer-indication-ov.patch**          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e '[Service]\nEnvironment="PREFER_INDICATION=1"' | \            |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/indication_env.conf  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Wait for reconnection                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-57-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - **Request patch                                                       |
|                        |          |         |       |   shared-gatt-Add-env-variable-to-prefer-indication-ov.patch**          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e '[Service]\nEnvironment="PREFER_INDICATION=1"' | \            |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/indication_env.conf  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Wait for reconnection                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-58-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - **Request patch                                                       |
|                        |          |         |       |   shared-gatt-Add-env-variable-to-prefer-indication-ov.patch**          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e '[Service]\nEnvironment="PREFER_INDICATION=1"' | \            |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/indication_env.conf  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Wait for reconnection                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-59-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Wait for reconnection                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-60-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Wait for reconnection                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-61-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Wait for reconnection                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-26-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan le                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024]# gatt.select-attribute \                               |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<handle - 1>         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<handle - 1>]# gatt.read             |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-27-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA read,write         |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan le                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On handle request, enter the handle displayed for the characteristic    |
|                        |          |         |       | during register-application                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-28-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl'                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# remove <bdaddr>                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.sc on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent DisplayYesNo                                     |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-29-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl'                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# remove <bdaddr>                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent DisplayYesNo                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA secure-write       |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan le                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-30-C    | PASS     |     6.1 | 5.69  | Run 'sudo bluetoothctl'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc only                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent off                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# agent DisplayYesNo                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan le                                                  |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run in a second terminal on demand:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 4097 <bdaddr>                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-62-C    | PASS     |     6.1 | 5.70  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <bdaddr>                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | In *btgatt-client*:                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# write-value 0x<handle> 02 00                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'btgatt-client -d <bdaddr>' on demand:                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# register-notify 0x<handle - 2>                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-63-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <bdaddr>                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | In *btgatt-client*:                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# write-value 0x<handle> 02 00                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'btgatt-client -d <bdaddr>' on demand:                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# register-notify 0x<handle - 2>                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-64-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <bdaddr>                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | In *btgatt-client*:                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# write-value 0x<handle> 02 00                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'btgatt-client -d <bdaddr>' on demand:                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# register-notify 0x<handle - 2>                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-65-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan le                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-66-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan le                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-67-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan le                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<yyyy>]# gatt.notify on              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - '[PTS-GAP-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<yyyy>' where \      |
|                        |          |         |       |   char<yyyy>/desc<handle>                                               |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BI-09-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BI-10-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# remove <bdaddr>                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# mgmt.sc on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent DisplayYesNo                                     |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | In a second terminal, repeat on demand:                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -s fips -d <bdaddr>                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | In first terminal, repeat on demand:                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.sc off                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/SEM/BV-45-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan le                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Click *No* on "Click Yes if device support User Interaction to pair     |
|                        |          |         |       | with peer" request                                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-11-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA secure-read        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On handle request, enter the handle displayed for the characteristic    |
|                        |          |         |       | during register-application                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-12-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan le                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On handle request, enter the handle displayed for the characteristic    |
|                        |          |         |       | during register-application                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-13-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan le                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On handle request, enter the handle displayed for the characteristic    |
|                        |          |         |       | during register-application                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-14-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On handle request, enter the handle displayed for the characteristic    |
|                        |          |         |       | during register-application                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-17-C    | PASS     |     6.1 | 5.69  | Run 'btgatt-client -d <pts_addr>' on demand                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# read-value 0x<handle>                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Accept pairing                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# read-value 0x<handle>'                                 |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-18-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024]# gatt.select-attribute \                               |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<handle - 1>         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<handle - 1>]# gatt.read             |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-19-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - In a second terminal, run 'sudo btmgmt' to be able to see the         |
|                        |          |         |       |   requested passkey                                                     |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Repeat on demand:                                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# read-value 0x<handle>                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-20-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo mkdir -p /etc/systemd/system/bluetooth.service.d                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - echo -e \                                                             |
|                        |          |         |       |   '[Service]\nExecStart=\nExecStart=/usr/lib/bluetooth/bluetoothd \     |
|                        |          |         |       |   --noplugin=gap' | \                                                   |
|                        |          |         |       |   sudo tee /etc/systemd/system/bluetooth.service.d/no_gap.conf          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'sudo bluetoothctl':                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024]# gatt.select-attribute \                               |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<handle - 1>         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-1024:/service<xxxx>/char<handle - 1>]# gatt.read             |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo rm -rf /etc/systemd/system/bluetooth.service.d                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl daemon-reload                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo systemctl restart bluetooth                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-21-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan le'                                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-22-C    | **INC**  |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | **"Security failed. result = 4 Failed to complete a security procedure."|
|                        |          |         |       | or "Please confirm that IUT has informed of a lost bond."**             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-23-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On handle request, enter the handle displayed for the characteristic    |
|                        |          |         |       | during register-application                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-24-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Set "TSPX_encryption_before_service_request" in IXIT to "True"        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent DisplayOnly                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan le                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On handle request, enter the handle displayed for the characteristic    |
|                        |          |         |       | during register-application                                             |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Set "TSPX_encryption_before_service_request" in IXIT to "False        |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-25-C    | **INC**  |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent DisplayOnly                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan le                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | **"PTS did not receive ATT service request"**                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/AUT/BV-27-C    | **INC**  |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent off                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# agent DisplayOnly                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan le                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | **"PTS did not receive ATT service request"**                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/CSIGN/BV-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Set "TSPX_gap_iut_role" in IXIT to "Central"                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run in a first terminal:                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <bdaddr>                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand run in a first terminal:                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - 'sudo grep -A 1 LocalSignatureKey \                                   |
|                        |          |         |       |   /var/lib/bluetooth/<iut_bdaddr>/<pts_bdaddr>/info | grep -v \         |
|                        |          |         |       |   LocalSignatureKey | cut -d "=" -f 2' to get local CSRK                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <bdaddr>:                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# set-sign-key -c <local_CSRK>                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value -w -s 0x<handle> 0                       |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Post-condition:                                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Set "TSPX_gap_iut_role" in IXIT to "Peripheral                        |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/CSIGN/BV-02-C  | PASS     |     6.1 | 5.73  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/CSIGN/BI-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | No data update message => OK                                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/CSIGN/BI-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | 2 update messages, out of 3 signed write commands => OK                 |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/CSIGN/BI-03-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     encrypt-authenticated-read                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | No data update message => OK                                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/SEC/CSIGN/BI-04-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-service 0xFFFF                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - *yes* when asked if primary service                               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-characteristic 0xAAAA \                  |
|                        |          |         |       |     authenticated-signed-writes,encrypt-authenticated-write             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - enter '1' when prompted                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# gatt.register-application                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | No data update message => OK                                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/ADV/BV-01-C        | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise.uuids AAAA                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/ADV/BV-02-C        | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise.name on                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/ADV/BV-03-C        | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/ADV/BV-04-C        | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise.manufacture 01 01 02 03 04 05 06             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/ADV/BV-05-C        | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise.tx-power on                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/ADV/BV-11-C        | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise.appearance 1                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/GAT/BV-04-C        | **FAIL** |     6.1 | 5.69  | Optional (TSPC_GAP_27_5)                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | **"Failed to find any instances of the characteristic under             |
|                        |          |         |       | test(Peripheral Preferred Connection Parameters)"**                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/NCON/BV-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo btmgmt connectable off                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - bluetoothctl advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Pair to PTS on demand                                                   |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/CON/BV-01-C     | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo btmgmt connectable on                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - bluetoothctl advertise off                                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/BON/BV-01-C     | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo bluetoothctl:                                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan on                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | after "Please set IUT into bondable mode":                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <bdaddr>                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GAP-2410]# disconnect                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <bdaddr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# mgmt.pair -c 0x04 -t 0x01 <bdaddr>                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <bdaddr>                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/GIN/BV-01-C     | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find' on demand                                        |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/LIN/BV-01-C     | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find -L' on demand                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/NAD/BV-01-C     | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt find' on demand                                        |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/NAD/BV-02-C     | PASS     |     6.1 | 5.69  |                                                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/LEP/BV-01-C     | PASS     |     6.1 | 5.69  | Run 'bluetoothctl'                                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Sometimes got "BR/EDR not Supported Flag should be set to 0 for         |
|                        |          |         |       | BR/EDR/LE compliant device", retry                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/LEP/BV-06-C     | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Request LE Only dongle for PTS                                        |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | Run 'btgatt-client -d <pts_le_only_addr>' on demand                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/LEP/BV-07-C     | PASS     |     6.1 | 5.69  | Run 'bluetoothctl'                                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/LEP/BV-08-C     | PASS     |     6.1 | 5.69  | Run 'bluetoothctl'                                                      |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# discoverable on                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/LEP/BV-09-C     | PASS     |     6.1 | 5.69  | On demand, run in a first terminal:                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <bdaddr>                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand, run in a second terminal:                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 31 <bdaddr>                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/LEP/BV-10-C     | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'bluetoothctl':                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# discoverable on                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# advertise on                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [bluetooth]# scan on                                                |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand, run in a second terminal:                                    |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - l2test -n -P 31 <bdaddr>                                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/DM/LEP/BV-11-C     | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - bluetoothctl discoverable on                                          |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <bdaddr>                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/MOD/NDIS/BV-01-C   | PASS     |     6.1 | 5.69  | Run 'bluetoothctl discoverable off' on demand                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/MOD/LDIS/BV-01-C   | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt discov limited 30' on demand                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/MOD/LDIS/BV-02-C   | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt discov limited 30' on demand                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/MOD/LDIS/BV-03-C   | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt discov limited 30' on demand                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/MOD/GDIS/BV-01-C   | PASS     |     6.1 | 5.69  | Run 'bluetoothctl discoverable on' on demand                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/MOD/GDIS/BV-02-C   | PASS     |     6.1 | 5.69  | Run 'bluetoothctl discoverable on' on demand                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/MOD/NCON/BV-01-C   | PASS     |     6.1 | 5.69  | Run 'sudo btmgmt connectable off' before starting the tests             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAP/MOD/CON/BV-01-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - bluetoothctl discoverable on                                          |
|                        |          |         |       +-------------------------------------------------------------------------+
|                        |          |         |       | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - sudo btmgmt connectable on                                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+

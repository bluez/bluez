.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

=================
GATT test results
=================

:PTS version: 8.5.3 Build 4

Setup
=====

- Remove PTS device from Bluetooth devices

- Uncomment and set "[GATT] KeySize" entry to 16 in /etc/bluetooth/main.conf

Tests
=====

The kernel and BlueZ versions represent the oldest version without backport
for which we know the test passed.

+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| Test name              | Result   | Kernel  | BlueZ |                                                                         |
+========================+==========+=========+=======+=========================================================================+
| GATT/CL/GAC/BV-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# connect <pts_addr>                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GATT-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service00c0/char<handle - 1>           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - e.g. for PTS device 00:1B:DC:F2:24:10 and handle "00CD":            |
|                        |          |         |       |     /org/bluez/hci0/dev_00_1B_DC_F2_24_10/service00c0/char00cc          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service<xxxx>/char<handle - 1>]# gatt.write \                  |
|                        |          |         |       |   "11 22 33 44 55 66 77 88 99 00 12 34 56 78 90 12 34"                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service<xxxx>/char<handle - 1>]# disconnect                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAD/BV-01-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On "Please send discover all primary services command to PTS":          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [GATT client]# search-all-primary-services                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - repeat on demand                                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAD/BV-02-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# search-service <uuid>                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - 128-bits UUID should be of the form                               |
|                        |          |         |       |       0000a00c-0000-0000-0123-456789abcdef                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - repeat on demand                                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAD/BV-03-C    | PASS     |     6.1 | 5.72  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - repeat on demand                                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAD/BV-04-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - repeat on demand                                                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAD/BV-05-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# search-characteristics <start_handle> <end_handle> \ |
|                        |          |         |       |     <uuid>                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - 128-bits UUID should be of the form                               |
|                        |          |         |       |       0000a00c-0000-0000-0123-456789abcdef                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - repeat on demand                                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BV-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-value 0x<handle>                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-value 0x<handle>                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-02-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-value 0x<handle>                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-03-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-value 0x<handle>                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-04-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# set-security-retry n                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-value 0x<handle>                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-05-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <pts_addr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GATT-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service0001/char0003                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service0020/char0022]# gatt.read 0                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service0020/char0022]# disconnect                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BV-03-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# search-characteristics 0x0001 0xffff <uuid>          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - 128-bits UUID should be of the form                               |
|                        |          |         |       |       0000a00c-0000-0000-0123-456789abcdef                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - repeat on demand                                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-06-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# search-characteristics <start_handle> <end_handle> \ |
|                        |          |         |       |     <uuid>                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - 128-bits UUID should be of the form                               |
|                        |          |         |       |       0000a00c-0000-0000-0123-456789abcdef                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-07-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# search-characteristics <start_handle> <end_handle> \ |
|                        |          |         |       |     <uuid>                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - 128-bits UUID should be of the form                               |
|                        |          |         |       |       0000a00c-0000-0000-0123-456789abcdef                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-09-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# search-characteristics <start_handle> <end_handle> \ |
|                        |          |         |       |     <uuid>                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - 128-bits UUID should be of the form                               |
|                        |          |         |       |       0000a00c-0000-0000-0123-456789abcdef                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-10-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# set-security-retry n                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# search-characteristics <start_handle> <end_handle> \ |
|                        |          |         |       |     <uuid>                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - 128-bits UUID should be of the form                               |
|                        |          |         |       |       0000a00c-0000-0000-0123-456789abcdef                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-11-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# set-security-retry n                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# search-characteristics <start_handle> <end_handle> \ |
|                        |          |         |       |     <uuid>                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - 128-bits UUID should be of the form                               |
|                        |          |         |       |       0000a00c-0000-0000-0123-456789abcdef                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BV-04-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-long-value 0x<handle> 0                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - repeat on demand                                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-12-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-long-value 0x<handle> 0                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-13-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-long-value 0x<handle> 0x<offset>                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-14-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-long-value 0x<handle> 0                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-15-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-long-value 0x<handle> 0                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-16-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# set-security-retry n                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-long-value 0x<handle> 0                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-17-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <pts_addr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GATT-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<handle - 1>         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service<xxxx>/char<handle - 1>]# gatt.read 0                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service<xxxx>/char<handle - 1>]# disconnect                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BV-06-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-value 0x<handle>                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BV-07-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-long-value 0x<handle> 0                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAR/BI-35-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-value 0x<handle>                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Application error: 0x80 - 0x9F                                          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BV-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value --without-response 0x<handle> 0          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BV-03-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value 0x<handle> 0                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-02-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value 0x<handle> 0                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-03-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value 0x<handle> 0                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-04-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value 0x<handle> 0                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-05-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# set-security-retry n                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value 0x<handle> 0                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-06-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <pts_addr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GATT-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<handle - 1>         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service<xxxx>/char<handle - 1>]# gatt.write 0                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service<xxxx>/char<handle - 1>]# disconnect                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BV-05-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-long-value 0x<handle> 0 0                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-07-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-long-value 0x<handle> 0 0                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-08-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-long-value 0x<handle> 0 0                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-09-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-long-value 0x<handle> 0x<offset> 0             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-11-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-long-value 0x<handle> 0 0                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-12-C    | PASS     |     6.1 | 5.73  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# set-security-retry n                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-long-value 0x<handle> 0 0                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-13-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# scan on                                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | On demand:                                                              |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# pair <pts_addr>                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [PTS-GATT-1024]# gatt.select-attribute \                              |
|                        |          |         |       |   /org/bluez/hci0/<dev_pts_addr>/service<xxxx>/char<handle - 1>         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service<xxxx>/char<handle - 1>]# gatt.write \                  |
|                        |          |         |       |   "11 22 33 44 55 66 77 88 99 00 12 34 56 78 90 12 34 56 78 90"         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Disconnect on demand:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [Test:/service<xxxx>/char<handle - 1>]# disconnect                    |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BV-08-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value 0x<handle> 0                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BV-09-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-long-value 0x<handle> 0 0                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-33-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value 0x<handle> 1 2                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAW/BI-34-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-long-value 0x<handle> 0 0 1 2 3 4 5 6 7 8 9 \  |
|                        |          |         |       |     10 11 12 13 14 15 16 17 18 19 20 21 22 23 24                        |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAN/BV-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# register-notify 0x<handle - 2>                       |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAI/BV-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# register-notify 0x<handle - 1>                       |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAI/BI-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# register-notify 0x<handle - 1>                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       |     - repeat on demand                                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAS/BV-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAT/BV-01-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# read-value 0x<handle>                                |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/CL/GAT/BV-02-C    | PASS     |     6.1 | 5.69  | On demand run:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - btgatt-client -d <pts_addr>                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT client]# write-value 0x<handle> 0                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAC/BV-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'btgatt-server'                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - repeat on demand                                                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAD/BV-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAD/BV-02-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAD/BV-03-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAD/BV-04-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAD/BV-05-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAD/BV-06-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BV-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-02-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "0010" on handle request                                          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-03-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write,authorize |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Reply no on authorization requests in bluetoothctl                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-04-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA secure-read          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-05-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA encrypt-read         |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BV-03-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Remove PTS device from Bluetooth devices                              |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-06-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA write                |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "AAAA" on UUID request                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter the handle displayed for the characteristic during                |
|                        |          |         |       | register-application on handle request                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-07-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA write                |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "BBBB" on UUID request                                            |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-08-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-09-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write,authorize |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "AAAA" on UUID request                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter the handle displayed for the characteristic during                |
|                        |          |         |       | register-application on handle request                                  |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Reply no on authorization requests in bluetoothctl                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-10-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA secure-read          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "AAAA" on UUID request                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter the handle displayed for the characteristic during                |
|                        |          |         |       | register-application on handle request                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-11-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA encrypt-read         |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "AAAA" on UUID request                                            |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter the handle displayed for the characteristic during                |
|                        |          |         |       | register-application on handle request                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BV-04-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'btgatt-server'                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - expected value is : 56 65 72 79 20 4c 6f 6e 67 20 54 65 73 74 20 44   |
|                        |          |         |       |   65 76 69 63 65 20 4e 61 6d 65 20 46 6f 72 20 54 65 73 74 69 6e 67 20  |
|                        |          |         |       |   41 54 54 20 50 72 6f 74 6f 63 6f 6c 20 4f 70 65 72 61 74 69 6f 6e 73  |
|                        |          |         |       |   20 4f 6e 20 47 41 54 54 20 53 65 72 76 65 72 00                       |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-12-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA write                |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4' when prompted                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter the handle displayed for the characteristic during                |
|                        |          |         |       | register-application on handle request                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-13-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'btgatt-server'                                                     |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-14-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "0010" on handle request                                          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-15-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write,authorize |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23  |
|                        |          |         |       |     24 25' when prompted                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Reply no on authorization requests in bluetoothctl                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-16-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA secure-read          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x10 0x11 0x12  |
|                        |          |         |       |     0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x20 0x21 0x22 0x23 0x24 0x25'   |
|                        |          |         |       |     when prompted                                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-17-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA encrypt-read         |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23  |
|                        |          |         |       |     24 25' when prompted                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BV-05-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-18-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA write                |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter the handle displayed for the characteristic during                |
|                        |          |         |       | register-application on handle request                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-19-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "0010" on handle request                                          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-20-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write,authorize |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xBBBB read,write,authorize |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '2' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Reply no on authorization requests in bluetoothctl                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-21-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA secure-read          |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-22-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <pts_addr>                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA encrypt-read         |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BV-06-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BV-07-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-descriptor 0xBBBB read                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x10 0x11 0x12  |
|                        |          |         |       |     0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x20 0x21 0x22 0x23 0x24 0x25'   |
|                        |          |         |       |     when prompted                                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BV-08-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-descriptor 0xBBBB read                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x10 0x11 0x12  |
|                        |          |         |       |     0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x20 0x21 0x22 0x23 0x24 0x25'   |
|                        |          |         |       |     when prompted                                                       |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAR/BI-45-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BV-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA \                    |
|                        |          |         |       |   read,write-without-response                                           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BV-03-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
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
| GATT/SR/GAW/BI-02-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "0030" on handle request                                          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-03-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-04-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write,authorize |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Reply no on authorization requests in bluetoothctl                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-05-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,secure-write    |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | "Cannot find characteristic in the IUT database"                        |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-06-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,encrypt-write   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BV-05-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23  |
|                        |          |         |       |     24 25' when prompted                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-07-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7' when prompted                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter "0030" on handle request                                          |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-08-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7' when prompted                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-09-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7' when prompted                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-11-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write,authorize |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23  |
|                        |          |         |       |     24 25' when prompted                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Reply no on authorization requests in bluetoothctl                      |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-12-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,secure-write    |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23  |
|                        |          |         |       |     24 25' when prompted                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-13-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,encrypt-write   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23  |
|                        |          |         |       |     24 25' when prompted                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BV-08-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-descriptor 0xBBBB read,write               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '2' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BV-09-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-descriptor 0xBBBB read,write               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23  |
|                        |          |         |       |     24 25' when prompted                                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-32-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-descriptor 0xBBBB read,write               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '2' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter the handle displayed for the characteristic during                |
|                        |          |         |       | register-application on handle request                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAW/BI-33-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-service 0xFFFF                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - *yes* when asked if primary service                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-characteristic 0xAAAA read,write           |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1' when prompted                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-descriptor 0xBBBB read,write               |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - enter '1 2 3 4 5 6 7' when prompted                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# gatt.register-application                                |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Enter the handle displayed for the characteristic during                |
|                        |          |         |       | register-application on handle request                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAN/BV-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
|                        |          |         |       |                                                                         |
|                        |          |         |       | Run 'btgatt-server -r'                                                  |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAI/BV-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
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
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAS/BV-01-C    | PASS     |     6.1 | 5.69  | In a first terminal run 'bluetoothctl':                                 |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# remove <pts_addr>                                        |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
|                        |          |         |       |                                                                         |
|                        |          |         |       | In a second terminal:                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'btgatt-server'                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'btgatt-server'                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - Run 'btgatt-server'                                                   |
|                        |          |         |       |                                                                         |
|                        |          |         |       |   - [GATT server]# notify -i 0x0009 00 01                               |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/GAT/BV-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl':                                                     |
|                        |          |         |       |                                                                         |
|                        |          |         |       | - [bluetooth]# advertise on                                             |
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
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/UNS/BI-01-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GATT/SR/UNS/BI-02-C    | PASS     |     6.1 | 5.69  | Run 'bluetoothctl advertise on'                                         |
+------------------------+----------+---------+-------+-------------------------------------------------------------------------+

.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

================
SPP test results
================

:PTS version: 8.5.2 Build 5

Setup
=====

- Remove PTS device from Bluetooth devices

Tests
=====

The kernel and BlueZ versions represent the oldest version without backport
for which we know the test passed.

+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| Test name                    | Result   | Kernel  | BlueZ |                                                                         |
+==============================+==========+=========+=======+=========================================================================+
| SPP/DEVA/APP/BV-01-C         | PASS     |     6.1 | 5.69  | Run 'rctest -n -U spp <BD_ADDR>' before starting the test               |
|                              |          |         |       |                                                                         |
|                              |          |         |       | Kill rctest upon request                                                |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SPP/DEVB/APP/BV-02-C         | PASS     |     6.1 | 5.69  | Run 'python ./test-profile -u spp -s -C 10'                             |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| IOPT/CL/SPP-DEVA/SFC/BV-24-I | PASS     |     6.1 | 5.69  | Remove PTS device from Bluetooth devices                                |
|                              |          |         |       |                                                                         |
|                              |          |         |       | Run 'rctest -n -U spp <BD_ADDR>'                                        |
|                              |          |         |       |                                                                         |
|                              |          |         |       | Kill rctest upon request                                                |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+

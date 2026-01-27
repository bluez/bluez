.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

==================
GAVDP test results
==================

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
| GAVDP/ACP/APP/CON/BV-01-C    | PASS     |     6.1 | 5.69  | It may need to pair the device from IUT during the test                 |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAVDP/ACP/APP/TRC/BV-02-C    | PASS     |     6.1 | 5.69  | It may need to pair the device from IUT during the test                 |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAVDP/INT/APP/CON/BV-01-C    | PASS     |     6.1 | 5.69  |                                                                         |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| GAVDP/INT/APP/TRC/BV-02-C    | PASS     |     6.1 | 5.69  | Wait for device to disconnect then connect from IUT                     |
|                              |          |         |       |                                                                         |
|                              |          |         |       | Wait on "Suspend the streaming channel"                                 |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+

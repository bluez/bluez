.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

=================
ScPP test results
=================

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
| SCPP/CL/CGGIT/SER/BV-01-C    | PASS     |     6.1 | 5.69  |                                                                         |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SCPP/CL/CGGIT/CHA/BV-01-C    | PASS     |     6.1 | 5.69  | Cancel 'Please take action to discover the Scan Interval Window …'      |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SCPP/CL/CGGIT/CHA/BV-02-C    | PASS     |     6.1 | 5.69  | Cancel 'Please take action to discover the Scan Refresh caracteristic…' |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SCPP/CL/SNPF/BV-01-I         | PASS     |     6.1 | 5.69  |                                                                         |
+------------------------------+----------+---------+-------+-------------------------------------------------------------------------+

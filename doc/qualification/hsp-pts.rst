.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

================
HSP test results
================

:PTS version: 8.5.3 Build 4

Setup
=====

- Remove PTS device from Bluetooth devices

- PipeWire version >= 1.1.81

Tests
=====

The kernel and BlueZ versions represent the oldest version without backport
for which we know the test passed.

+----------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| Test name                  | Result   | Kernel  | BlueZ |                                                                         |
+============================+==========+=========+=======+=========================================================================+
| HSP/AG/IAC/BV-01-I         | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                            |          |         |       |                                                                         |
|                            |          |         |       | - Start PulseAudio Volume Control                                       |
|                            |          |         |       +-------------------------------------------------------------------------+
|                            |          |         |       | Pair to PTS                                                             |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Verify in Configuration tab that PTS-HFP profile is set to Headset Head |
|                            |          |         |       | Unit, or select it                                                      |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Start playing file using Lollypop                                       |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Verify in PulseAudio Volume Control's Output Devices tab that audio is  |
|                            |          |         |       | playing on PTS-HFP device                                               |
|                            |          |         |       |                                                                         |
|                            |          |         |       | On request disconnect                                                   |
+----------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| HSP/AG/ACR/BV-01-I         | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                            |          |         |       |                                                                         |
|                            |          |         |       | - Start PulseAudio Volume Control                                       |
|                            |          |         |       |                                                                         |
|                            |          |         |       | - Start playing file using Lollypop                                     |
|                            |          |         |       +-------------------------------------------------------------------------+
|                            |          |         |       | Verify in Configuration tab that PTS-HFP profile is set to Headset Head |
|                            |          |         |       | Unit, or select it                                                      |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Verify in PulseAudio Volume Control's Output Devices tab that audio is  |
|                            |          |         |       | playing on PTS-HFP device                                               |
|                            |          |         |       |                                                                         |
|                            |          |         |       | On request disconnect                                                   |
+----------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| HSP/AG/ACT/BV-01-I         | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                            |          |         |       |                                                                         |
|                            |          |         |       | - Start PulseAudio Volume Control                                       |
|                            |          |         |       +-------------------------------------------------------------------------+
|                            |          |         |       | Verify in Configuration tab that PTS-HFP profile is set to Headset Head |
|                            |          |         |       | Unit, or select it                                                      |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Start playing file using Lollypop                                       |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Verify in PulseAudio Volume Control's Output Devices tab that audio is  |
|                            |          |         |       | playing on PTS-HFP device                                               |
|                            |          |         |       |                                                                         |
|                            |          |         |       | On request disconnect                                                   |
+----------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| HSP/AG/ACT/BV-02-I         | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                            |          |         |       |                                                                         |
|                            |          |         |       | - Start PulseAudio Volume Control                                       |
|                            |          |         |       +-------------------------------------------------------------------------+
|                            |          |         |       | Connect to PTS                                                          |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Verify in Configuration tab that PTS-HFP profile is set to Headset Head |
|                            |          |         |       | Unit, or select it                                                      |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Start playing file using Lollypop                                       |
|                            |          |         |       |                                                                         |
|                            |          |         |       | Verify in PulseAudio Volume Control's Output Devices tab that audio is  |
|                            |          |         |       | playing on PTS-HFP device                                               |
|                            |          |         |       |                                                                         |
|                            |          |         |       | On request disconnect                                                   |
+----------------------------+----------+---------+-------+-------------------------------------------------------------------------+
| IOPT/CL/HSP-AG/SFC/BV-16-I | PASS     |     6.1 | 5.69  |                                                                         |
+----------------------------+----------+---------+-------+-------------------------------------------------------------------------+

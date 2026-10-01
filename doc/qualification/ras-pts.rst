.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Qualcomm Technologies, Inc.

================
RAS test results
================

:PTS version: 8.14.0.4
:BlueZ: 5.87 with Channel Sounding support

RAP Requester and Responder test results are in ``rap-pts.rst``.

Setup
=====

- Enable ``Experimental = true`` in ``/etc/bluetooth/main.conf``.
- Use a ``NoInputNoOutput`` bluetoothctl agent and make it the default agent.
- Before cases that establish a new encrypted link, delete the DUT bond and the
  corresponding PTS LTK/bond. Removing only one side causes authentication
  failure.
- The DUT acts as the CS Reflector. Set the role from the bluetoothctl Channel
  Sounding menu before the first case::

      menu cs
      role 0x02

Tests
=====

+------------------------------+----------+----------------------------------------------------------------+
| Test name                    | Result   | Notes                                                          |
+==============================+==========+================================================================+
| IOPT/RAS/SR/GATTDB/BV-01-I   | PASS     | RAS database validation.                                       |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SGGIT/SER/BV-01-C     | PASS     | Primary, unique Ranging Service discovery.                     |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SGGIT/CHA/BV-01-C     | PASS     | RAS Features characteristic declaration.                       |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SGGIT/CHA/BV-02-C     | PASS     | Real-time Ranging Data characteristic declaration.             |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SGGIT/CHA/BV-03-C     | PASS     | On-demand Ranging Data characteristic declaration.             |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SGGIT/CHA/BV-04-C     | PASS     | RAS Control Point characteristic declaration.                  |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SGGIT/CHA/BV-08-C     | PASS     | Ranging Data Ready characteristic declaration.                 |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SGGIT/CHA/BV-12-C     | PASS     | Ranging Data Overwritten characteristic declaration.           |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-01-C           | PASS     | RAS Features read.                                             |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-02-C           | PASS     | Ranging Data Ready notification or indication.                 |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-03-C           | PASS     | Ranging Data Ready read.                                       |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-04-C           | PASS     | Ranging Data Overwritten read.                                 |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-05-C           | PASS     | Ranging Data Ready, Indication transport.                      |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-06-C           | PASS     | Ranging Data Ready, Notification transport.                    |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-07-C           | PASS     | Ranging Data Ready, Indication and Read.                       |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-08-C           | PASS     | Ranging Data Overwritten is indicated when the client enabled  |
|                              |          | both transports.                                               |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCO/BV-09-C           | PASS     | Ranging Data Ready is indicated when the client enabled both   |
|                              |          | transports.                                                    |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RRD/BV-01-C           | PASS     | Real-time Ranging Data delivery.                               |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RRD/BV-03-C           | PASS     | Real-time Ranging Data is notified when the client enabled     |
|                              |          | both transports.                                               |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RRD/BV-04-C           | PASS     | Overwritten Real-time data restarts on the new Ranging         |
|                              |          | Counter.                                                       |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RRD/BV-05-C           | PASS     | Real-time subscription is dropped on disconnection.            |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCP/BV-01-C           | PASS     | Get Ranging Data, segmented transfer and ACK.                  |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCP/BV-03-C           | PASS     | Abort Operation stops an in-progress transfer.                 |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/RCP/BV-05-C           | PASS     | Control Point state is reset on disconnection.                 |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SPE/BI-01-C           | PASS     | Op Code Not Supported, Retrieve Lost Ranging Data Segments.    |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SPE/BI-03-C           | PASS     | Op Code Not Supported, Set Filter.                             |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SPE/BI-04-C           | PASS     | Op Code Not Supported, RFU.                                    |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SPE/BI-05-C           | PASS     | Invalid Parameter, Abort Operation.                            |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SPE/BI-06-C           | PASS     | Get Ranging Data and ACK Ranging Data errors.                  |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SPE/BI-07-C           | PASS     | Server Busy.                                                   |
+------------------------------+----------+----------------------------------------------------------------+
| RAS/SR/SPE/BI-11-C           | PASS     | Real-time and On-demand CCCDs are mutually exclusive.          |
+------------------------------+----------+----------------------------------------------------------------+

Not applicable
==============

+------------------------------+-----------------------------------------------+
| Test name                    | Reason                                        |
+==============================+===============================================+
| RAS/SR/SPE/BI-02-C           | Applies when Abort Operation is not supported |
|                              | (NOT RAS 3/4 in RAS.TS Table 5.1). The IUT    |
|                              | supports it, so RAS/SR/RCP/BV-03-C and        |
|                              | RAS/SR/SPE/BI-05-C are run instead.           |
+------------------------------+-----------------------------------------------+

Pre-generated ranging data
==========================

With ``TSPX_test_method`` set to pre-generated CS data, the whole ranging data
arrives in one go rather than one CS subevent at a time, so the On-demand
notification path sends its segments back to back with no air time between
them. ``RAS/SR/SPE/BI-05-C`` writes an invalid Abort Operation mid-transfer
and needs the transfer to still be running when it does, so the per-segment
delay has to leave the peer a window: it fails at 0 ms and passes at the 5 ms
``RAS_SEGMENT_NFY_PACE_MS`` uses. Feeding the test data one subevent at a
time rather than in one go does not change that, since the segments of a
subevent still go out back to back. Raise the delay if PTS reports Complete
Ranging Data where it expected Invalid Parameter.

Transport selection
===================

When a client enables both notifications and indications on a characteristic,
the transport the server must use differs per characteristic:

- Ranging Data Ready and Ranging Data Overwritten are indicated (RAS 3.4.2 and
  3.5.2), covered by ``RAS/SR/RCO/BV-08-C`` and ``RAS/SR/RCO/BV-09-C``.
- On-demand and Real-time Ranging Data are notified (RAS 3.2.2 and 3.2.3.1),
  covered by ``RAS/SR/RCO/BV-05..07-C`` and ``RAS/SR/RRD/BV-03-C``.

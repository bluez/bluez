.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2026 Qualcomm Technologies, Inc.

================
RAP test results
================

:PTS version: 8.14.0.4
:BlueZ: 5.87 with Channel Sounding support

RAS Server test results are in ``ras-pts.rst``.

Setup
=====

- Enable ``Experimental = true`` in ``/etc/bluetooth/main.conf``.
- Use a ``NoInputNoOutput`` bluetoothctl agent and make it the default agent.
- Before cases that establish a new encrypted link, delete the DUT bond and the
  corresponding PTS LTK/bond. Removing only one side causes authentication
  failure.
- Do not use the bluetoothctl ``gatt`` menu to write RAS CCCDs. Use the
  ``cs ranging-data-mode`` command so RAP owns subscription lifetime.

Requester results
=================

+----------------------------+----------+--------------------------------------------------------------------------+
| Test name                  | Result   | Notes                                                                    |
+============================+==========+==========================================================================+
| RAP/REQ/RRD/BV-01-C        | PASS     | Configure the requested Real-time notification or indication transport.  |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/RRD/BI-01-C        | PASS     | The Requester disables the Real-time CCCD after 5 seconds without a      |
|                            |          | first segment.                                                           |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/RRD/BI-02-C        | PASS     | The Requester disables the Real-time CCCD after 1 second without a       |
|                            |          | continuation segment.                                                    |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/CGGIT/SER/BV-01-C  | PASS     | Discover the remote primary Ranging Service.                             |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/CGGIT/CHA/BV-01-C  | PASS     | Discover the RAS Features characteristic.                                |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/CGGIT/CHA/BV-02-C  | PASS     | Discover the Real-time Ranging Data characteristic.                      |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/CGGIT/CHA/BV-03-C  | PASS     | Discover the On-demand Ranging Data characteristic.                      |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/CGGIT/CHA/BV-04-C  | PASS     | Discover the RAS Control Point characteristic.                           |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/CGGIT/CHA/BV-05-C  | PASS     | Discover the Ranging Data Ready characteristic.                          |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/CGGIT/CHA/BV-06-C  | PASS     | Discover the Ranging Data Overwritten characteristic.                    |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/ORD/BV-01-C        | PASS     | See the On-demand ranging data procedures below.                         |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/ORD/BI-01-C        | PASS     | The Requester sends Abort Operation after 5 seconds without the first    |
|                            |          | On-demand segment.                                                       |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/ORD/BI-02-C        | PASS     | The Requester sends Abort Operation when a continuation segment is       |
|                            |          | missing for more than one second.                                        |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/ORD/BI-03-C        | PASS     | Ignore Complete Lost and RFU Control Point responses; receive normal     |
|                            |          | data and ACK the subsequent Complete response.                           |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/ORD/BV-05-C        | PASS     | Configure On-demand notification transport; PTS validates Ranging Data   |
|                            |          | Ready notification handling.                                             |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/ORD/BV-06-C        | PASS     | On the PTS MMI, promptly read Ranging Data Ready after PTS suppresses    |
|                            |          | its notification.                                                        |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/ORD/BV-07-C        | PASS     | Configure On-demand indication transport; PTS validates Ranging Data     |
|                            |          | Overwritten indication reception.                                        |
+----------------------------+----------+--------------------------------------------------------------------------+
| RAP/REQ/ORD/BV-08-C        | PASS     | Configure On-demand notification transport; PTS validates Ranging Data   |
|                            |          | Overwritten notification reception.                                      |
+----------------------------+----------+--------------------------------------------------------------------------+

Responder results
=================

+----------------------------+----------+--------------------------------------------------------------------------+
| Test name                  | Result   | Notes                                                                    |
+============================+==========+==========================================================================+
| RAP/RES/RSPF/BV-01-C       | PASS     | Discoverable advertising includes the Ranging Service UUID (0x185B).     |
+----------------------------+----------+--------------------------------------------------------------------------+


Before ``RAP/RES/RSPF/BV-01-C``, advertise the Ranging Service UUID so PTS can
discover the Responder::

    menu advertise
    uuids 0000185b-0000-1000-8000-00805f9b34fb
    back
    advertise peripheral

Stop it after the case with ``advertise off``.

On-demand ranging data procedures
=================================

Some RAS Requester cases are exercised against PTS's SIG pre-generated ranging
data (``TSPX_test_method``) when the PTS controller does not support Channel
Sounding. The procedures below use the ``ranging-data-mode`` command to select
the transport PTS expects for each case.

For ``RAP/REQ/ORD/BV-01-C``, set ``TSPX_test_method`` to ``pre-generated
ranging data`` and select the ``2_procedures`` input.

After connection, pairing, and encryption complete, run the following in the
same bluetoothctl session::

    menu cs
    ranging-data-mode <pts_addr> ondemand indicate

This configures indications for Ranging Data Ready, RAS Control Point, and
Ranging Data Overwritten. Segmented On-demand Ranging Data remains configured
for notifications so large pre-generated streams are not stalled by
per-indication confirmation pacing.

The Requester reads the Ranging Data Ready characteristic, waits for the PTS
Ready indication, writes ``Get Ranging Data``, reassembles the data, and writes
``ACK Ranging Data`` after the PTS Complete response.

For ``RAP/REQ/ORD/BI-01-C``, use the same setup but configure PTS not to send
the first On-demand segment after ``Get Ranging Data``. The Requester writes
``Abort Operation`` after five seconds. For ``RAP/REQ/ORD/BI-02-C``, have PTS
send only First Segment; the Requester's one-second continuation watchdog
sends Abort within the PTS assertion window.

For ``RAP/REQ/ORD/BI-03-C``, use the same setup and allow PTS to inject
Complete Lost Ranging Data Segments and RFU Control Point responses during the
transfer. No additional DUT action is required: the Requester ignores them,
then ACKs the normal Complete Ranging Data response.

For ``RAP/REQ/ORD/BV-05-C``, select notification transport after security is
complete::

    menu cs
    ranging-data-mode <pts_addr> ondemand notify

This configures the Ranging Data Ready path for the PTS notification round.

For ``RAP/REQ/ORD/BV-07-C``, select indication transport to receive the
Ranging Data Overwritten indication::

    menu cs
    ranging-data-mode <pts_addr> ondemand indicate

PTS can log failed attempts to send an indication during this case even though
its final verdict is PASS; record the final PTS verdict rather than treating
that server-side diagnostic alone as a DUT failure.

For ``RAP/REQ/ORD/BV-08-C``, select notification transport to receive the
Ranging Data Overwritten notification::

    menu cs
    ranging-data-mode <pts_addr> ondemand notify

For ``RAP/REQ/ORD/BV-06-C``, after connection and security complete, first use
indication transport to enter the PTS On-demand flow, then switch to the
notification transport used by the lost-Ready round::

    menu cs
    ranging-data-mode <pts_addr> ondemand indicate
    ranging-data-mode <pts_addr> ondemand notify

Wait for ``Ranging Data mode updated`` after each command. PTS does not advance
to the lost-Ready MMI until both transitions have been completed. It then
suppresses the Ranging Data Ready notification and presents an MMI asking for a
read of the Ranging Data Ready characteristic. Complete the MMI promptly, before
its short timeout, from the bluetoothctl GATT menu::

    back
    menu gatt
    select-attribute 00002c18-0000-1000-8000-00805f9b34fb
    read

Selecting the characteristic by UUID avoids depending on the handles PTS
happens to assign; ``select-attribute`` matches characteristics before
descriptors, so this selects the value attribute and not its CCCD. Use
``list-attributes`` if the remote database needs to be inspected first. Return
to PTS and continue the MMI after the read request is sent.

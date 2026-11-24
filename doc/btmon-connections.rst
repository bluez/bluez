.. This file is included by btmon.rst.

CONNECTION TRACKING
===================

HCI uses **connection handles** (16-bit integers) to identify individual
connections. Understanding how handles map to devices is essential for
reading traces.

Handle Types
------------

Different connection types use different handle ranges, but these ranges
are controller-specific and not standardized. The connection type can be
determined by looking at the event that created the handle:

.. list-table::
   :header-rows: 1
   :widths: 15 25 60

   * - Type
     - Creation Event
     - Description
   * - BR/EDR ACL
     - Connection Complete
     - Classic Bluetooth data connection
   * - LE ACL
     - LE (Enhanced) Connection Complete
     - Low Energy data connection
   * - CIS
     - LE CIS Established
     - Connected Isochronous Stream (LE Audio)
   * - BIS
     - LE BIG Complete
     - Broadcast Isochronous Stream (LE Audio)
   * - SCO/eSCO
     - Synchronous Connection Complete
     - Voice/audio synchronous connection (classic)

A single device may have multiple handles simultaneously. For example,
an LE Audio device will have an LE ACL handle for control traffic and
one or more CIS handles for audio streams. The ``LE CIS Established``
event includes the ACL connection handle that the CIS is associated
with.

Controller Buffer Tracking
--------------------------

Buffer tracking may show a indicator in square brackets::

    < ACL: Handle 2048 [1/6] flags 0x00 dlen 16

The ``[1/6]`` means this is buffer slot 1 of 6 available controller
ACL buffers. This reflects the host-side HCI flow control: the host
tracks how many buffers the controller has available and shows the
current usage. When the controller sends ``Number of Completed Packets``
events, buffers are freed and the count decreases.

HCI ERROR AND DISCONNECT REASON CODES
======================================

HCI status and disconnect reason codes use the same code space. These
appear in ``Status:`` and ``Reason:`` fields throughout the trace.
btmon decodes them automatically, but the hex values are useful for
searching and filtering.

Common Disconnect Reasons
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 8 40 52

   * - Code
     - Name
     - Diagnostic Meaning
   * - 0x05
     - Authentication Failure
     - Pairing or encryption setup failed. Key may be
       stale or devices have mismatched security databases.
   * - 0x08
     - Connection Timeout
     - The supervision timer expired. The remote device
       moved out of range or stopped responding. This is
       an RF link loss.
   * - 0x13
     - Remote User Terminated Connection
     - The remote device intentionally disconnected.
       This is the normal graceful disconnect.
   * - 0x14
     - Remote Device Terminated due to Low Resources
     - The remote device ran out of resources (memory,
       connection slots).
   * - 0x15
     - Remote Device Terminated due to Power Off
     - The remote device is powering down.
   * - 0x16
     - Connection Terminated By Local Host
     - The local BlueZ stack intentionally disconnected.
       Normal when bluetoothd initiates disconnect.
   * - 0x1f
     - Unspecified Error
     - Generic error. Often indicates a firmware issue.
   * - 0x22
     - LMP/LL Response Timeout
     - Link layer procedure timed out. The remote device
       stopped responding to LL control PDUs.
   * - 0x28
     - Instant Passed
     - A timing-critical operation missed its deadline.
       Often seen with connection parameter updates.
   * - 0x2f
     - Insufficient Security
     - The required security level (encryption, MITM
       protection) was not met.
   * - 0x3b
     - Unacceptable Connection Parameters
     - The remote rejected a connection parameter update.
   * - 0x3d
     - Connection Terminated due to MIC Failure
     - Encryption integrity check failed. Possible key
       mismatch or corruption.
   * - 0x3e
     - Connection Failed to be Established
     - Connection attempt failed entirely (e.g., the
       remote device did not respond to connection
       requests).
   * - 0x3f
     - MAC Connection Failed
     - MAC-level connection failure.
   * - 0x44
     - Operation Cancelled by Host
     - The host cancelled the operation before it
       completed.

Full Error Code Table
---------------------

The complete set of HCI error codes (0x00-0x45) is defined in the
Bluetooth Core Specification, Volume 1, Part F. btmon decodes all
of them automatically in ``Status:`` and ``Reason:`` fields. The
source mapping is in ``monitor/packet.c`` (``error2str_table``).

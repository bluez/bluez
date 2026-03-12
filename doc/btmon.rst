=====
btmon
=====

-----------------
Bluetooth monitor
-----------------

:Authors: - Marcel Holtmann <marcel@holtmann.org>
          - Tedd Ho-Jeong An <tedd.an@intel.com>
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Version: BlueZ
:Date: April 2021
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**btmon** [*OPTIONS* ...]

DESCRIPTION
===========

The  btmon(1) command  provides  access  to the Bluetooth subsystem monitor
infrastructure for reading HCI traces.

OPTIONS
=======

-r FILE, --read FILE        Read traces in btsnoop format from *FILE*.
-w FILE, --write FILE       Save traces in btsnoop format to *FILE*.
-a FILE, --analyze FILE     Analyze traces in btsnoop format from *FILE*.
                            It displays the devices found in the *FILE* with
			    its packets by type. If gnuplot is installed on
			    the system it also attempts to plot packet latency
			    graph.
-s SOCKET, --server SOCKET  Start monitor server socket.
-p PRIORITY, --priority PRIORITY  Show only priority or lower for user log.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1

   * - *PRIORITY*
     - NAME

   * - **3**
     - Error

   * - **4**
     - Warning

   * - **6**
     - Information (Default)

   * - **7**
     - Debug. **debug** can be used.

-i NUM, --index NUM         Show only specified controller. *hciNUM* is also
                            acceptable. This is useful to capture the traces
                            from the specific controller when the multiple
                            controllers are presented.

-d TTY, --tty TTY           Read data from *TTY*.

-B SPEED, --rate SPEED      Set TTY speed. The default *SPEED* is 115300

-V COMPID, --vendor COMPID  Set the default company identifier. The *COMPID* is
                            a unique number assigned by the Bluetooth SIG to
                            a member company and can be found/searched from the
                            Bluetooth SIG webpage.

                            For example, Intel is 2 and Realtek is 93.

-M, --mgmt                  Open channel for mgmt events.

-K, --kernel                Open kmsg for kernel messages.

-t, --time                  Show a time instead of time offset.

-T, --date                  Show a time and date information instead of
                            time offset.

-N, --no-time               Suppress the time offset display entirely.

-S, --sco                   Dump SCO traffic in raw hex format.

-A, --a2dp                  Dump A2DP stream traffic in a raw hex format.

-I, --iso                   Dump ISO stream traffic in raw hex format. Required
                            to see LE Audio isochronous data in the output.

-E IP, --ellisys IP         Send Ellisys HCI Injection.

-P, --no-pager              Disable pager usage while reading the log file.

-J OPTIONS, --jlink OPTIONS     Read data from RTT.  Each options are comma(,)
                                separated without spaces.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1

   * - *OPTIONS*
     - Description

   * - **DEVICE**
     - Required. Set the target device.

   * - **SERIALNO**
     - (Optional) Set the USB serial number. Default is **0**.

   * - **INTERFACE**
     - (Optional) Target interface. Default is **swd**.

   * - **SPEED**
     - (Optional) Set target interface speed in kHz. Default is **1000**.

-R OPTIONS, --rtt OPTIONS   RTT control block parameters. Each options are
                            comma(,) separated without spaces.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1

   * - *OPTIONS*
     - Description

   * - **ADDRESS**
     - (Optional) Address of RTT buffer. Default is **0x00**

   * - **AREA**
     - (Optional) Size of range to search in RTT buffer. Default is **0**

   * - **NAME**
     - (Optional) Buffer name. Default is **btmonitor**

-C WIDTH, --columns WIDTH   Output width if not a terminal

-c MODE, --color MODE       Set output color. The possible *MODE* values are:
                            **auto|always|never**.

                            Default value is **auto**

-v, --version               Show version

-h, --help                  Show help options

READING THE OUTPUT
==================

btmon output is organized as a stream of frames, each representing a single
event in the Bluetooth subsystem. Understanding the output format is essential
for debugging Bluetooth issues.

Line Prefixes
-------------

Every frame begins with a single-character prefix that identifies its source
and type:

.. list-table::
   :header-rows: 1
   :widths: 5 20 75

   * - Prefix
     - Meaning
     - Description
   * - ``<``
     - **HCI Command / Data TX**
     - Sent from host to controller (outgoing). HCI commands,
       ACL/SCO/ISO data transmitted to the controller.
   * - ``>``
     - **HCI Event / Data RX**
     - Received from controller to host (incoming). HCI events,
       ACL/SCO/ISO data received from the controller.
   * - ``@``
     - **Management traffic**
     - Management interface (MGMT) commands and events between
       bluetoothd and the kernel management layer.
   * - ``=``
     - **System notes**
     - System-level annotations: kernel information, index changes,
       process log messages, and D-Bus signals.

HCI Traffic (``<`` and ``>``)
-----------------------------

HCI frames represent the actual communication between the host software and
the Bluetooth controller hardware.

**Anatomy of an HCI command line**::

    < HCI Command: Reset (0x03|0x0003) plen 0             #5 [hci0] 12:35:01.843185
    │                    │    │    │          │              │  │       │
    │                    │    │    │          │              │  │       └─ Timestamp
    │                    │    │    │          │              │  └─ Controller
    │                    │    │    │          │              └─ Frame number
    │                    │    │    │          └─ Parameter length (bytes)
    │                    │    │    └─ Full opcode (16-bit)
    │                    │    └─ OGF|OCF (Opcode Group / Command Field)
    │                    └─ Command name (human-readable)
    └─ Direction: < = Host to Controller (outgoing)

**Anatomy of an HCI event line**::

    > HCI Event: Command Complete (0x0e) plen 4           #6 [hci0] 12:35:01.864922
    │                              │      │                │  │       │
    │                              │      │                │  │       └─ Timestamp
    │                              │      │                │  └─ Controller
    │                              │      │                └─ Frame number
    │                              │      └─ Parameter length
    │                              └─ Event code
    │
    └─ Direction: > = Controller to Host (incoming)

The ``<`` direction means the host is **sending** to the controller (commands
and data). The ``>`` direction means the controller is **sending** to the host
(events and data). Think of it from the controller's perspective: ``<`` is
input going into the controller, ``>`` is output coming from it.

**HCI commands with parameters** are followed by indented detail lines::

    < HCI Command: LE Set Extende.. (0x08|0x0039) plen 2  #1 [hci0] 12:35:01.738352
            Extended advertising: Disabled (0x00)
            Number of sets: Disable all sets (0x00)

**HCI event responses** reference the command they complete::

    > HCI Event: Command Complete (0x0e) plen 4           #6 [hci0] 12:35:01.864922
          Reset (0x03|0x0003) ncmd 2
            Status: Success (0x00)

Here ``ncmd 2`` indicates the controller can accept 2 more commands
(HCI flow control). The indented body shows the command this event
completes and the result status.

**LE Meta Events** contain a subevent type::

    > HCI Event: LE Meta Event (0x3e) plen 31           #487 [hci0] 12:36:18.974201
          LE Enhanced Connection Complete (0x0a)
            Status: Success (0x00)
            Handle: 2048
            Role: Peripheral (0x01)
            Peer address type: Public (0x00)
            Peer address: AA:BB:CC:DD:EE:FF (OUI Company)
            Connection interval: 60.00 msec (0x0030)
            Connection latency: 0 (0x0000)
            Supervision timeout: 9600 msec (0x03c0)

**ACL Data** shows data plane traffic with handle and protocol decoding::

    < LE-ACL: Handle 2048 [66:B0:26:F1:D3:BC] [1/6] flags 0x00 dlen 16  #493 [hci0] 12:36:18.977915
    │   │            │     │                   │          │         │    │    │     │
    │   │            │     │                   │          │         │    │    │     └─ Timestamp
    │   │            │     │                   │          │         │    │    └─ Controller
    │   │            │     │                   │          │         │    └─ Frame number
    │   │            │     │                   │          │         └─ Data length
    │   │            │     │                   │          └─ flags
    │   │            │     │                   └─ Buffer tracking (optional)
    │   │            │     └─ Peer address (optional)
    │   │            └─ Handle number
    │   └─ Connection-type-aware label (e.g. BR-ACL, LE-ACL, BR-SCO, LE-ISO)
    └─ Direction marker: '<' = host->controller (TX), '>' = controller->host (RX)

ACL data is automatically decoded into higher-layer protocols::

    < LE-ACL: Handle 2048 [2/6] flags 0x00 dlen 7  #494 [hci0] 12:36:18.978488
          ATT: Exchange MTU Request (0x02) len 2
            Client RX MTU: 517

    > LE-ACL: Handle 2048 flags 0x02 dlen 11       #497 [hci0] 12:36:19.000048
          SMP: Pairing Request (0x01) len 6
            IO capability: NoInputNoOutput (0x03)
            OOB data: Authentication data not present (0x00)
            Authentication requirement: Bonding, MITM, SC, No Keypresses, CT2 (0x2d)
            Max encryption key size: 16

Management Traffic (``@``)
--------------------------

Lines starting with ``@`` show management interface traffic -- the structured
command/event protocol between ``bluetoothd`` and the kernel (see
``doc/mgmt-protocol.rst``).

**Anatomy of a management line**::

    @ MGMT Command: Set Powered (0x0005) plen 1     {0x0001} [hci0] 12:35:04.033564
    │                            │        │           │        │       │
    │                            │        │           │        │       └─ Timestamp
    │                            │        │           │        └─ Controller
    │                            │        │           └─ MGMT socket ID
    │                            │        └─ Parameter length
    │                            └─ MGMT opcode
    └─ @ = Management channel

The ``{0x0001}`` is the management socket identifier -- it distinguishes
between multiple management clients (e.g. bluetoothd and btmgmt running
simultaneously).

**MGMT Open/Close** track when processes connect to the management channel::

    @ MGMT Open: bluetoothd (privileged) version 1.23      {0x0001} 12:34:49.881936
    @ MGMT Close: bluetoothd                               {0x0001} 12:35:01.866256

These show the process name, privilege level, and protocol version.

**MGMT commands with parameters**::

    @ MGMT Command: Set Powered (0x0005) plen 1     {0x0001} [hci0] 12:35:04.033564
            Powered: Enabled (0x01)

**MGMT events** (responses and notifications)::

    @ MGMT Event: Command Complete (0x0001) plen 7  {0x0001} [hci0] 12:35:04.114789
          Set Powered (0x0005) plen 4
            Status: Success (0x00)
            Current settings: 0x004e0ac1
              Powered
              Secure Simple Pairing

**MGMT without controller index** (global operations)::

    @ MGMT Command: Read Management Ver.. (0x0001) plen 0  {0x0001} 12:35:04.027771
    @ MGMT Event: Command Complete (0x0001) plen 6         {0x0001} 12:35:04.027776

Notice there is no ``[hci0]`` -- these operate at the system level,
not on a specific controller.

System Notes (``=``)
--------------------

Lines starting with ``=`` are system-level annotations injected by the
kernel or by processes via the monitor channel. They are **not** HCI or
MGMT protocol traffic.

**Kernel information** (shown at startup)::

    = Note: Linux version 6.16.0-rc6-0903 (x86_64)                  12:34:49.881926
    = Note: Bluetooth subsystem version 2.22                        12:34:49.881930

**Index lifecycle** (controller added/removed/opened/closed)::

    = New Index: 00:11:22:33:44:55 (Primary,USB,hci0)        [hci0] 12:34:49.881932
    = Open Index: 00:11:22:33:44:55                          [hci0] 12:34:49.881933
    = Index Info: 00:11:22:33:44:55 (OUI Company)              [hci0] 12:34:49.881934
    = Close Index: 00:11:22:33:44:55                         [hci0] 12:35:01.865125

- ``New Index`` -- a controller was registered with the kernel
- ``Open Index`` -- a controller was activated
- ``Index Info`` -- controller vendor information
- ``Close Index`` -- a controller was deactivated

**Process log messages** (debug output from bluetoothd and other daemons)::

    = bluetoothd: src/adapter.c:connected_callback() hci0 devic..   12:36:18.975307
      │           │                                                  │
      │           │                                                  └─ Timestamp
      │           └─ Source file, function, and message (may be truncated)
      └─ Process name

These appear when ``bluetoothd`` is running with debug enabled (``-d``)
or when a process writes to the kernel logging channel. They show the
source file path, function name, and a log message -- invaluable for
correlating daemon-internal decisions with the HCI traffic around them.

**D-Bus activity** (signals and method calls)::

    = bluetoothd: [:1.21220:method_call] > org.freedesktop.DBus..   12:34:53.912508
    = bluetoothd: [:1.21220:method_return] < [#5]                   12:34:53.912546
    = bluetoothd: [signal] org.freedesktop.DBus.ObjectManager.I..   12:36:18.975691

The format is ``[bus_name:message_type]`` followed by ``>`` (outgoing) or
``<`` (incoming). Note that ``>`` and ``<`` within D-Bus system notes
indicate D-Bus message direction, not HCI direction.

Right-Side Metadata
-------------------

Every line has metadata right-aligned at the end. The exact fields depend
on the line type::

    ┌─ Main content (left-aligned, variable width)
    │                                        ┌─ Frame # ─┐ ┌Controller┐ ┌─ Timestamp ─┐
    │                                        │            │ │          │ │              │
    < HCI Command: Reset (0x03|0x0003) plen 0             #5 [hci0] 12:35:01.843185
    > HCI Event: Command Complete (0x0e) plen 4           #6 [hci0] 12:35:01.864922
    @ MGMT Command: Set Powered (0x0005) plen 1     {0x0001} [hci0] 12:35:04.033564
    = Note: Linux version 6.16.0-rc6-0903 (x86_64)                  12:34:49.881926
    = Open Index: 00:11:22:33:44:55                          [hci0] 12:34:49.881933

**Frame number** (``#N``): Sequential counter for HCI frames only. Useful
for identifying specific packets in a trace. Only HCI traffic (``<`` and
``>``) gets frame numbers -- MGMT (``@``) and system notes (``=``) do not.

**Controller** (``[hciN]``): Identifies which Bluetooth controller the
frame belongs to. Absent for global operations (kernel notes, MGMT
commands without a controller index).

**MGMT socket ID** (``{0xNNNN}``): Shown on ``@`` lines instead of frame
numbers. Identifies which management socket (process) sent the command.

**Timestamp**: Always the rightmost field. The format depends on the
command-line option used:

.. list-table::
   :header-rows: 1
   :widths: 15 25 30

   * - Option
     - Format
     - Example
   * - *(default)*
     - Seconds since trace start
     - ``0.881932``
   * - ``-t``
     - Time of day (HH:MM:SS.usec)
     - ``12:35:01.843185``
   * - ``-T``
     - Full date and time
     - ``2026-01-13 12:34:49.881926``

Indented Detail Lines
---------------------

Lines indented below a frame header contain the decoded payload of that
frame. The indentation level indicates the protocol layer:

- **First level** (6 spaces): direct payload of the HCI/MGMT frame
- **Second level** (8 spaces): decoded fields within the payload
- **Third level** (10+ spaces): nested protocol data (e.g. L2CAP inside
  ACL, ATT inside L2CAP)

Example of protocol layering in ACL data::

    > ACL: Handle 2048 flags 0x02 dlen 11       #497 [hci0] 12:36:19.000048
          SMP: Pairing Request (0x01) len 6                          ← L2CAP/SMP layer
            IO capability: NoInputNoOutput (0x03)                    ← SMP fields
            OOB data: Authentication data not present (0x00)
            Authentication requirement: Bonding, MITM, SC (0x2d)
            Max encryption key size: 16

Timestamp Notes
---------------

When reading btsnoop files with ``-t`` or ``-T``, timestamps reflect the
wall-clock time recorded in the btsnoop file. The precision depends on
the source:

- **Live capture** (``btmon`` monitor channel): Microsecond precision
  from the kernel.
- **btsnoop files**: The btsnoop format stores timestamps as
  microseconds since epoch, so full microsecond precision is
  preserved. Trailing zeros in the display (e.g., ``14:38:46.589000``)
  indicate the original capture source had millisecond granularity.

The default timestamp mode shows seconds elapsed since the first
packet in the trace, which is useful for measuring intervals between
events without needing to know the absolute time.

Frame Numbers vs Line Numbers
-----------------------------

btmon assigns sequential **frame numbers** (``#N``) to HCI packets.
These are stable identifiers for specific packets regardless of output
formatting. However, when processing btmon text output with tools like
``grep`` or ``sed``, the relevant unit is **line numbers** in the output
file. The two are unrelated:

- A single frame may produce many output lines (header + decoded
  fields).
- Frame numbers only apply to HCI traffic (``<`` and ``>``). MGMT
  (``@``) and system notes (``=``) do not have frame numbers.
- When referencing specific packets, prefer frame numbers (``#487``)
  over line numbers, as frame numbers are stable across different
  terminal widths and formatting options.

Practical Reading Guide
-----------------------

**Typical command-response pair**::

    < HCI Command: Read BD ADDR (0x04|0x0009) plen 0     #13 [hci0] 12:35:04.057866
    > HCI Event: Command Complete (0x0e) plen 10         #14 [hci0] 12:35:04.058750
          Read BD ADDR (0x04|0x0009) ncmd 1
            Status: Success (0x00)
            Address: 00:11:22:33:44:55 (OUI Company)

Read this as: Frame #13, the host asked the controller for its Bluetooth
address. Frame #14, the controller replied with success and the address
``00:11:22:33:44:55``. The response arrived ~0.9ms later.

**Typical MGMT flow showing relation to HCI**::

    @ MGMT Command: Set Powered (0x0005) plen 1     {0x0001} [hci0] 12:35:04.033564
            Powered: Enabled (0x01)
    < HCI Command: Reset (0x03|0x0003) plen 0             #7 [hci0] 12:35:04.033907
    > HCI Event: Command Complete (0x0e) plen 4           #8 [hci0] 12:35:04.055753
          Reset (0x03|0x0003) ncmd 2
            Status: Success (0x00)
      ... (more HCI commands to configure the controller) ...
    @ MGMT Event: Command Complete (0x0001) plen 7  {0x0001} [hci0] 12:35:04.114789
          Set Powered (0x0005) plen 4
            Status: Success (0x00)

Read this as: bluetoothd sent ``Set Powered`` via MGMT. The kernel
translated this into a sequence of HCI commands (Reset, then
configuration). After all HCI commands completed, the kernel sent the
MGMT Command Complete event back to bluetoothd.

**Connection establishment flow**::

    > HCI Event: LE Meta Event (0x3e) plen 31           #487 [hci0] 12:36:18.974201
          LE Enhanced Connection Complete (0x0a)
            Status: Success (0x00)
            Handle: 2048
            Role: Peripheral (0x01)
            Peer address: AA:BB:CC:DD:EE:FF (OUI Company)
    @ MGMT Event: Device Connec.. (0x000b) plen 13  {0x0001} [hci0] 12:36:18.974319
    = bluetoothd: src/adapter.c:connected_callback() hci0 devic..   12:36:18.975307
    < ACL: Handle 2048 [1.. flags 0x00 dlen 16  #493 [hci0] 12:36:18.977915
          LE L2CAP: Connection Parameter Update Request (0x12) ident 1 len 8
    < ACL: Handle 2048 [2/6] flags 0x00 dlen 7  #494 [hci0] 12:36:18.978488
          ATT: Exchange MTU Request (0x02) len 2
            Client RX MTU: 517

Read this as: The controller reported a new LE connection (HCI event).
The kernel forwarded this as a MGMT Device Connected event. bluetoothd
logged its ``connected_callback()``. Then data exchange began -- an L2CAP
parameter update and ATT MTU negotiation over the new ACL connection.

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

ANALYZE MODE
============

The ``-a`` (``--analyze``) option reads a btsnoop file and produces a
statistical summary instead of the full decoded trace.

Usage
-----

.. code-block::

   $ btmon -a hcidump.log

Output Contents
---------------

Analyze mode reports, for each controller found in the trace:

- **Packet counts**: Total HCI packets broken down by type (commands,
  events, ACL, SCO, ISO, vendor diagnostics, system notes, user
  logs, control messages).

- **Per-connection statistics**: For each connection handle found:

  - Connection type (BR-ACL, LE-ACL, BR-SCO, BR-ESCO, LE-ISO)
  - Device address
  - TX and RX packet counts and completion counts
  - Latency statistics (min, max, median) in milliseconds
  - Packet size statistics (min, max, average) in octets
  - Throughput estimate in Kb/s

- **Per-channel statistics**: For each L2CAP channel within a
  connection, the same packet/latency/size statistics.

- **Latency plots**: If ``gnuplot`` is installed, ASCII-art latency
  distribution plots are rendered in the terminal.

RECONSTRUCTING A GATT DATABASE FROM SNOOP TRACES
=================================================

A btsnoop trace contains the complete ATT protocol exchange used by
GATT clients and servers to discover each other's services. By reading
the discovery requests and responses, it is possible to reconstruct the
full GATT database of a remote device -- even without access to the
device itself.

This section explains the GATT discovery procedure and how each ATT
operation appears in ``btmon`` output.

Overview of GATT Discovery
---------------------------

GATT discovery is a multi-phase process where a client queries the
server's attribute database using ATT protocol operations. The phases
are:

1. **Primary Service Discovery** -- Find all primary services and their
   handle ranges.
2. **Secondary Service Discovery** -- Find any secondary (included-only)
   services.
3. **Included Service Discovery** -- Find which services include other
   services.
4. **Characteristic Discovery** -- Find all characteristics within each
   service.
5. **Descriptor Discovery** -- Find all descriptors for each
   characteristic.
6. **Characteristic Value Reading** -- Read the values of readable
   characteristics.

Each phase uses a specific ATT operation and produces a
request/response pattern in the trace. The client repeats each request
with advancing handle ranges until the server responds with
``Attribute Not Found``, indicating the end of that phase.

Phase 1: Primary Service Discovery (Read By Group Type)
--------------------------------------------------------

The client discovers primary services using ``Read By Group Type
Request`` with the ``Primary Service`` UUID (0x2800) as the group type.

**Request**::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 11       #516 [hci0] 0.124726
          ATT: Read By Group Type Request (0x10) len 6
            Handle range: 0x0001-0xffff
            Attribute group type: Primary Service (0x2800)

The first request always starts at handle 0x0001 and searches through
0xffff (the entire handle space).

**Response**::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 42       #523 [hci0] 0.240151
          ATT: Read By Group Type Response (0x11) len 37
            Attribute data length: 6
            Attribute group list: 6 entries
            Handle range: 0x0001-0x0009
            UUID: Generic Access Profile (0x1800)
            Handle range: 0x000a-0x0011
            UUID: Generic Attribute Profile (0x1801)
            Handle range: 0x0012-0x0014
            UUID: Device Information (0x180a)
            Handle range: 0x0015-0x0039
            UUID: Generic Telephony Bearer (0x184c)
            Handle range: 0x003a-0x0059
            UUID: Generic Media Control (0x1849)
            Handle range: 0x005a-0x005c
            UUID: Telephony and Media Audio (0x1855)

Each entry provides:

- **Handle range** -- The start and end handle of the service. All
  attributes belonging to this service (characteristics, descriptors)
  have handles within this range.
- **UUID** -- The service UUID. Standard 16-bit UUIDs are shown with
  their name (e.g., ``Generic Access Profile``). 128-bit vendor-specific
  UUIDs appear as full UUID strings.

The client continues by sending another request starting after the last
handle in the response::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 11       #525 [hci0] 0.240641
          ATT: Read By Group Type Request (0x10) len 6
            Handle range: 0x005d-0xffff
            Attribute group type: Primary Service (0x2800)

This continues until the server responds with ``Attribute Not Found``::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 9        #532 [hci0] 0.360069
          ATT: Error Response (0x01) len 4
            Read By Group Type Request (0x10)
            Handle: 0x005d
            Error: Attribute Not Found (0x0a)

This error indicates that no more primary services exist beyond handle
0x005d. The client now has the complete list of primary services.

.. note::

   The ``Attribute data length`` field indicates the size of each entry
   in the response. A value of 6 means 16-bit UUIDs (2 bytes start
   handle + 2 bytes end handle + 2 bytes UUID). A value of 20 means
   128-bit UUIDs (2 + 2 + 16). If the server has both 16-bit and
   128-bit service UUIDs, they are returned in separate responses
   because all entries in a single response must have the same length.

Phase 2: Secondary Service Discovery
--------------------------------------

After primary services, the client may discover secondary services
using the same ``Read By Group Type Request`` but with the ``Secondary
Service`` UUID (0x2801)::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 11       #534 [hci0] 0.360752
          ATT: Read By Group Type Request (0x10) len 6
            Handle range: 0x0001-0xffff
            Attribute group type: Secondary Service (0x2801)

If no secondary services exist, the server responds with
``Attribute Not Found``. Secondary services are not directly accessible
to clients -- they are only reachable via include references from
primary services.

Phase 3: Included Service Discovery (Read By Type)
----------------------------------------------------

To discover which services include other services, the client uses
``Read By Type Request`` with the ``Include`` UUID (0x2802)::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 11       #540 [hci0] 0.480731
          ATT: Read By Type Request (0x08) len 6
            Handle range: 0x0001-0x005c
            Attribute type: Include (0x2802)

The handle range typically spans the entire discovered database. Each
include declaration in the response identifies a service that is
included by the service containing that handle.

Phase 4: Characteristic Discovery (Read By Type)
--------------------------------------------------

For each service, the client discovers its characteristics using
``Read By Type Request`` with the ``Characteristic`` UUID (0x2803).
The handle range is limited to the service's handle range.

**Request**::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 11       #531 [hci0] 0.360063
          ATT: Read By Type Request (0x08) len 6
            Handle range: 0x0008-0x0011
            Attribute type: Characteristic (0x2803)

**Response**::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 27       #533 [hci0] 0.360714
          ATT: Read By Type Response (0x09) len 22
            Attribute data length: 7
            Attribute data list: 3 entries
            Handle: 0x0009
            Value[5]: 200a00052a
                Properties: 0x20
                  Indicate (0x20)
                Value Handle: 0x000a
                Value UUID: Service Changed (0x2a05)
            Handle: 0x000c
            Value[5]: 0a0d00292b
                Properties: 0x0a
                  Read (0x02)
                  Write (0x08)
                Value Handle: 0x000d
                Value UUID: Client Supported Features (0x2b29)
            Handle: 0x000e
            Value[5]: 020f002a2b
                Properties: 0x02
                  Read (0x02)
                Value Handle: 0x000f
                Value UUID: Database Hash (0x2b2a)

Each characteristic entry provides:

- **Handle** -- The handle of the characteristic declaration attribute.
- **Properties** -- A bitmask indicating supported operations:

  .. list-table::
     :header-rows: 1
     :widths: 10 30 60

     * - Bit
       - Property
       - Description
     * - 0x01
       - Broadcast
       - Can be broadcast in advertising data
     * - 0x02
       - Read
       - Can be read
     * - 0x04
       - Write Without Response
       - Can be written without acknowledgment
     * - 0x08
       - Write
       - Can be written with acknowledgment
     * - 0x10
       - Notify
       - Server can send notifications
     * - 0x20
       - Indicate
       - Server can send indications
     * - 0x40
       - Authenticated Signed Writes
       - Supports signed write commands
     * - 0x80
       - Extended Properties
       - Has extended properties descriptor

- **Value Handle** -- The handle where the characteristic's value is
  stored (always declaration handle + 1).
- **Value UUID** -- The UUID identifying the characteristic type.

The client continues with advancing handle ranges until it receives
``Attribute Not Found``::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 9        #572 [hci0] 1.200228
          ATT: Error Response (0x01) len 4
            Read By Type Request (0x08)
            Handle: 0x005c
            Error: Attribute Not Found (0x0a)

Phase 5: Descriptor Discovery (Find Information)
--------------------------------------------------

Descriptors occupy the handles between a characteristic's value handle
and the next characteristic declaration (or end of service). The client
discovers them using ``Find Information Request``.

**Request**::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 9        #556 [hci0] 0.959965
          ATT: Find Information Request (0x04) len 4
            Handle range: 0x000b-0x000b

The handle range covers the gap between the characteristic value handle
and the next characteristic declaration handle.

**Response**::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 10       #561 [hci0] 0.961049
          ATT: Find Information Response (0x05) len 5
            Format: UUID-16 (0x01)
            Handle: 0x000b
            UUID: Client Characteristic Configuration (0x2902)

Common descriptor UUIDs:

.. list-table::
   :header-rows: 1
   :widths: 15 40 45

   * - UUID
     - Name
     - Purpose
   * - 0x2900
     - Characteristic Extended Properties
     - Additional property bits
   * - 0x2901
     - Characteristic User Description
     - Human-readable description string
   * - 0x2902
     - Client Characteristic Configuration (CCC)
     - Enable/disable notifications or indications
   * - 0x2903
     - Server Characteristic Configuration
     - Server-side broadcast configuration
   * - 0x2904
     - Characteristic Presentation Format
     - Data format, exponent, unit

Phase 6: Reading Characteristic Values
----------------------------------------

After discovery, the client may read characteristic values using
``Read Request``::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 7        #577 [hci0] 1.380203
          ATT: Read Request (0x0a) len 2
            Handle: 0x000f

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #579 [hci0] 1.380774
          ATT: Read Response (0x0b) len 16
            Value[16]: a470d508da8751a2a50b79da0250bfda

The ``Handle`` in the request corresponds to a characteristic value
handle from the discovery phase. btmon shows the raw value bytes; the
interpretation depends on the characteristic UUID.

Find By Type Value (Targeted Service Search)
----------------------------------------------

In addition to discovering all services, a client can search for a
specific service UUID using ``Find By Type Value Request``::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 13       #513 [hci0] 0.124195
          ATT: Find By Type Value Request (0x06) len 8
            Handle range: 0x0001-0xffff
            Attribute type: Primary Service (0x2800)
              UUID: Generic Attribute Profile (0x1801)

    < ACL Data TX: Handle 2048 flags 0x00 dlen 9        #515 [hci0] 0.124684
          ATT: Find By Type Value Response (0x07) len 4
            Handle range: 0x0008-0x0011

This returns only the handle range for the matching service, without
iterating through all services. If the service is not found::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 9        #524 [hci0] 0.240607
          ATT: Error Response (0x01) len 4
            Find By Type Value Request (0x06)
            Handle: 0x0012
            Error: Attribute Not Found (0x0a)

Bidirectional Discovery
------------------------

Both devices in a connection can act as GATT client and server
simultaneously. In a btsnoop trace, you may see interleaved discovery
in both directions:

- **TX (``<``) requests + RX (``>``) responses** -- The local device
  (whose trace this is) is acting as a GATT client, discovering the
  remote device's services.
- **RX (``>``) requests + TX (``<``) responses** -- The remote device
  is acting as a GATT client, discovering the local device's services.

For example, the local server responding to the remote's discovery::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 11       #584 [hci0] 1.512006
          ATT: Read By Group Type Request (0x10) len 6
            Handle range: 0x0001-0xffff
            Attribute group type: Primary Service (0x2800)

    < ACL Data TX: Handle 2048 flags 0x00 dlen 66       #586 [hci0] 1.518778
          ATT: Read By Group Type Response (0x11) len 61
            Attribute data length: 6
            Attribute group list: 10 entries
            Handle range: 0x0001-0x0007
            UUID: Generic Access Profile (0x1800)
            Handle range: 0x0008-0x0011
            UUID: Generic Attribute Profile (0x1801)
            Handle range: 0x0012-0x0014
            UUID: Device Information (0x180a)
            Handle range: 0x0015-0x001e
            UUID: Coordinated Set Identification (0x1846)
            Handle range: 0x001f-0x0020
            UUID: Common Audio (0x1853)
            Handle range: 0x0021-0x0024
            UUID: Microphone Control (0x184d)
            Handle range: 0x0041-0x004b
            UUID: Volume Control (0x1844)
            Handle range: 0x006b-0x0073
            UUID: Broadcast Audio Scan (0x184f)
            Handle range: 0x0074-0x0086
            UUID: Published Audio Capabilities (0x1850)
            Handle range: 0x0087-0x0096
            UUID: Audio Stream Control (0x184e)

This shows the local device's own GATT database as seen by the remote.
To reconstruct the remote device's database, focus on the TX requests
and RX responses (the local device acting as client).

Building the Attribute Table
-----------------------------

To reconstruct the GATT database, extract the discovery responses and
organize them into a table. Using the trace above as an example, the
remote device at address 00:11:22:33:44:55 has:

**Services** (from Read By Group Type Response)::

    Handle Range    UUID                            Service Name
    ──────────────  ──────────────────────────────  ────────────────────────────
    0x0001-0x0009   0x1800                          Generic Access Profile
    0x000a-0x0011   0x1801                          Generic Attribute Profile
    0x0012-0x0014   0x180a                          Device Information
    0x0015-0x0039   0x184c                          Generic Telephony Bearer
    0x003a-0x0059   0x1849                          Generic Media Control
    0x005a-0x005c   0x1855                          Telephony and Media Audio

**Characteristics** (from Read By Type Response, within GAP 0x0001-0x0009)::

    Handle  Value Handle  Properties  UUID    Name
    ──────  ────────────  ──────────  ──────  ────────────────────────────────
    0x0002  0x0003        Read        0x2a00  Device Name
    0x0004  0x0005        Read        0x2a01  Appearance
    0x0006  0x0007        Read        0x2a04  Peripheral Preferred Conn Params
    0x0008  0x0009        Read        0x2aa6  Central Address Resolution

**Characteristics** (within GATT 0x000a-0x0011)::

    Handle  Value Handle  Properties       UUID    Name
    ──────  ────────────  ───────────────  ──────  ────────────────────────────
    0x000b  0x000c        Indicate         0x2a05  Service Changed
    0x000e  0x000f        Read, Write      0x2b29  Client Supported Features
    0x0010  0x0011        Read             0x2b2a  Database Hash

**Descriptors** (from Find Information Response)::

    Handle  UUID    Name
    ──────  ──────  ────────────────────────────────────
    0x000d  0x2902  Client Characteristic Configuration

The CCC descriptor at handle 0x000d belongs to the Service Changed
characteristic (0x000c), because it falls between that value handle
and the next characteristic declaration at 0x000e.

SMP PAIRING FLOW
================

The Security Manager Protocol (SMP) handles pairing, key generation,
and key distribution between Bluetooth devices. SMP traffic appears
inside L2CAP on fixed CID 0x0006 (LE) or CID 0x0007 (BR/EDR). btmon
decodes all SMP operations automatically.

Pairing Phases
--------------

SMP pairing proceeds in three phases. Each phase produces a distinct
pattern in the btmon output.

**Phase 1: Feature Exchange**

Pairing begins when one device sends a Security Request (peripheral)
or the host initiates pairing directly. The initiator sends a Pairing
Request and the responder replies with a Pairing Response::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 11       #497 [hci0] 0.026107
          SMP: Pairing Request (0x01) len 6
            IO capability: NoInputNoOutput (0x03)
            OOB data: Authentication data not present (0x00)
            Authentication requirement: Bonding, MITM, SC, CT2 (0x2d)
            Max encryption key size: 16
            Initiator key distribution: IdKey Sign (0x06)
            Responder key distribution: IdKey Sign (0x06)

    < ACL Data TX: Handle 2048 flags 0x00 dlen 11       #499 [hci0] 0.026894
          SMP: Pairing Response (0x02) len 6
            IO capability: KeyboardDisplay (0x04)
            OOB data: Authentication data not present (0x00)
            Authentication requirement: Bonding, SC, CT2 (0x29)
            Max encryption key size: 16
            Initiator key distribution: IdKey (0x02)
            Responder key distribution: IdKey (0x02)

Key fields to check:

- **Authentication requirement** -- The ``SC`` flag indicates Secure
  Connections. Its absence means Legacy Pairing.
- **IO capability** -- Determines the association model (Just Works,
  Passkey Entry, Numeric Comparison, OOB).
- **Key distribution** -- Which keys each side will send after
  encryption is established. ``IdKey`` = Identity Resolving Key (IRK),
  ``EncKey`` = Long Term Key (legacy only), ``Sign`` = CSRK.

**Phase 2: Authentication (Secure Connections)**

For Secure Connections pairing (``SC`` flag set), both devices exchange
public keys, then perform confirm/random value exchange::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 69       #501 [hci0] 0.098224
          SMP: Pairing Public Key (0x0c) len 64
            X: 1a2b3c4d...
            Y: 5e6f7a8b...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 69       #503 [hci0] 0.148556
          SMP: Pairing Public Key (0x0c) len 64
            X: 9c8d7e6f...
            Y: 0a1b2c3d...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #505 [hci0] 0.149003
          SMP: Pairing Confirm (0x03) len 16
            Confirm value: a1b2c3d4e5f6...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #507 [hci0] 0.212884
          SMP: Pairing Random (0x04) len 16
            Random value: 1122334455...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #509 [hci0] 0.213100
          SMP: Pairing Random (0x04) len 16
            Random value: 6677889900...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #511 [hci0] 0.278003
          SMP: Pairing DHKey Check (0x0d) len 16
            E: aabbccddee...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #513 [hci0] 0.278450
          SMP: Pairing DHKey Check (0x0d) len 16
            E: ffeeddccbb...

After DHKey Check, the initiator starts encryption at the HCI level::

    < HCI Command: LE Start Encryption (0x08|0x0019) plen 28  #515 [hci0] 0.279002
    > HCI Event: Encryption Change (0x08) plen 4              #517 [hci0] 0.342556
          Status: Success (0x00)
          Handle: 2048
          Encryption: Enabled with AES-CCM (0x01)

**Phase 2: Authentication (Legacy Pairing)**

Legacy pairing (no ``SC`` flag) skips the Public Key and DHKey Check
exchanges. Only Confirm and Random values are exchanged::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #501 [hci0] 0.098224
          SMP: Pairing Confirm (0x03) len 16
            Confirm value: ...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #503 [hci0] 0.162556
          SMP: Pairing Confirm (0x03) len 16
            Confirm value: ...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #505 [hci0] 0.163003
          SMP: Pairing Random (0x04) len 16
            Random value: ...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #507 [hci0] 0.228884
          SMP: Pairing Random (0x04) len 16
            Random value: ...

**Phase 3: Key Distribution**

After encryption is established, each device distributes keys as
negotiated in Phase 1::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #519 [hci0] 0.343002
          SMP: Identity Information (0x08) len 16
            Identity resolving key: 00112233445566778899aabbccddeeff

    > ACL Data RX: Handle 2048 flags 0x02 dlen 12       #521 [hci0] 0.343556
          SMP: Identity Address Information (0x09) len 7
            Address type: Public (0x00)
            Address: 00:11:22:33:44:55

The Identity Address Information reveals the device's true public or
static random address (as opposed to a Resolvable Private Address used
during connection).

For Legacy Pairing, LTK distribution also appears::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #519 [hci0] 0.343002
          SMP: Encryption Information (0x06) len 16
            Long term key: 00112233...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 15       #521 [hci0] 0.343556
          SMP: Central Identification (0x07) len 10
            EDIV: 0x1234
            Rand: 0x0123456789abcdef

Pairing Failure
---------------

When pairing fails, one device sends a Pairing Failed PDU::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 6        #505 [hci0] 0.213002
          SMP: Pairing Failed (0x05) len 1
            Reason: Authentication requirements (0x03)

SMP failure reasons:

.. list-table::
   :header-rows: 1
   :widths: 8 35 57

   * - Code
     - Reason
     - Diagnostic Meaning
   * - 0x01
     - Passkey Entry Failed
     - User cancelled or entered wrong passkey
   * - 0x02
     - OOB Not Available
     - OOB data expected but not provided
   * - 0x03
     - Authentication Requirements
     - Devices cannot agree on security level (e.g.,
       one requires MITM but IO caps only allow Just Works)
   * - 0x04
     - Confirm Value Failed
     - Cryptographic check failed; possible MITM attack
   * - 0x05
     - Pairing Not Supported
     - Remote does not support pairing
   * - 0x06
     - Encryption Key Size
     - Cannot agree on key size
   * - 0x07
     - Command Not Supported
     - Received unrecognized SMP command
   * - 0x08
     - Unspecified Reason
     - Generic failure
   * - 0x09
     - Repeated Attempts
     - Pairing rate-limited; wait before retry
   * - 0x0a
     - Invalid Parameters
     - Invalid fields in SMP command
   * - 0x0b
     - DHKey Check Failed
     - ECDH key agreement failed (SC only)
   * - 0x0c
     - Numeric Comparison Failed
     - User rejected numeric comparison
   * - 0x0d
     - BR/EDR Pairing In Progress
     - Classic pairing already active
   * - 0x0e
     - Cross-Transport Key Derivation Not Allowed
     - CTKD rejected by policy

Automating Pairing Analysis
----------------------------

**Identify all pairing attempts**::

    grep -n "Pairing Request\|Pairing Response\|Pairing Failed\|Pairing Public Key\|DHKey Check" output.txt

**Check pairing method (Secure Connections vs Legacy)**:

- If ``Pairing Public Key`` appears between Request/Response and
  Confirm: Secure Connections.
- If only Confirm/Random follow Request/Response: Legacy Pairing.
- Check the ``Authentication requirement`` line for the ``SC`` flag.

**Detect pairing failures**::

    grep -n "Pairing Failed" output.txt

**Correlate pairing with encryption**:

After successful pairing, expect ``Encryption Change`` with
``Status: Success``. Search for::

    grep -n "Encryption Change\|Encryption:" output.txt

**Identify re-pairing on reconnect**:

Reconnections to a bonded device should show ``Encryption Change``
without SMP traffic (using stored keys). If SMP Pairing Request
appears on reconnection, the bond was lost on one side.

**Full pairing diagnosis pattern**:

1. Find ``Pairing Request`` -- note the handle, IO capabilities,
   auth requirements
2. Find ``Pairing Response`` -- compare IO capabilities to determine
   association model
3. Check for ``Pairing Failed`` -- if present, the reason code
   identifies the failure
4. Check for ``Encryption Change`` with ``Status: Success`` -- confirms
   pairing completed
5. Check for ``Identity Address Information`` -- reveals the device's
   true address

L2CAP CHANNEL TRACKING
=======================

L2CAP (Logical Link Control and Adaptation Protocol) multiplexes
multiple logical channels over a single ACL connection. btmon decodes
L2CAP signaling automatically and routes data to higher-layer protocol
decoders based on the channel.

Fixed Channels
--------------

Fixed channels have pre-assigned Channel Identifiers (CIDs) and do
not require signaling to establish:

.. list-table::
   :header-rows: 1
   :widths: 10 30 60

   * - CID
     - Protocol
     - Description
   * - 0x0001
     - L2CAP Signaling (BR/EDR)
     - Channel management for classic connections
   * - 0x0002
     - Connectionless Reception
     - Connectionless L2CAP data
   * - 0x0003
     - AMP Manager
     - AMP (Alternate MAC/PHY) control
   * - 0x0004
     - ATT
     - Attribute Protocol (GATT operations)
   * - 0x0005
     - L2CAP Signaling (LE)
     - Channel management for LE connections
   * - 0x0006
     - SMP (LE)
     - Security Manager Protocol
   * - 0x0007
     - SMP (BR/EDR)
     - Security Manager over classic transport

In btmon output, fixed channel traffic is decoded directly without
any L2CAP signaling preamble. For example, ATT on CID 0x0004 appears
as::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 7    #494 [hci0] 0.004488
          ATT: Exchange MTU Request (0x02) len 2
            Client RX MTU: 517

Dynamic Channels (BR/EDR)
--------------------------

Classic Bluetooth uses L2CAP signaling on CID 0x0001 to establish
dynamic channels. Each channel is identified by a PSM (Protocol/Service
Multiplexer) that determines which protocol runs on it.

**Channel establishment**::

    > ACL Data RX: Handle 256 flags 0x02 dlen 16    #142 [hci0] 2.034556
          L2CAP: Connection Request (0x02) ident 3 len 4
            PSM: 25 (0x0019)
            Source CID: 0x0040

    < ACL Data TX: Handle 256 flags 0x00 dlen 20    #144 [hci0] 2.035002
          L2CAP: Connection Response (0x03) ident 3 len 8
            Destination CID: 0x0041
            Source CID: 0x0040
            Result: Connection successful (0x0000)
            Status: No further information available (0x0000)

After connection, configuration is exchanged::

    > ACL Data RX: Handle 256 flags 0x02 dlen 20    #146 [hci0] 2.035556
          L2CAP: Configure Request (0x04) ident 4 len 8
            Destination CID: 0x0041
            Flags: 0x0000
            Option: MTU (0x01) [2]
              MTU: 1024

    < ACL Data TX: Handle 256 flags 0x00 dlen 18    #148 [hci0] 2.036003
          L2CAP: Configure Response (0x05) ident 4 len 6
            Source CID: 0x0040
            Flags: 0x0000
            Result: Success (0x0000)

Common PSM-to-protocol mappings:

.. list-table::
   :header-rows: 1
   :widths: 12 25 63

   * - PSM
     - Protocol
     - Description
   * - 0x0001
     - SDP
     - Service Discovery Protocol
   * - 0x0003
     - RFCOMM
     - Serial port emulation (SPP, HFP, etc.)
   * - 0x000f
     - BNEP
     - Bluetooth Network Encapsulation Protocol
   * - 0x0017
     - AVCTP
     - Audio/Video Control Transport (AVRCP)
   * - 0x0019
     - AVDTP
     - Audio/Video Distribution Transport (A2DP)
   * - 0x001b
     - AVCTP Browsing
     - AVRCP browsing channel
   * - 0x001f
     - ATT (BR/EDR)
     - Attribute Protocol over classic transport
   * - 0x0027
     - EATT
     - Enhanced Attribute Protocol

LE Credit-Based Channels
--------------------------

LE connections use L2CAP signaling on CID 0x0005 for dynamic
channels. The LE Credit Based Connection mechanism provides flow
control::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 18   #600 [hci0] 1.824003
          LE L2CAP: LE Connection Request (0x14) ident 1 len 10
            PSM: 39 (0x0027)
            Source CID: 0x0040
            MTU: 517
            MPS: 251
            Credits: 10

    > ACL Data RX: Handle 2048 flags 0x02 dlen 18   #602 [hci0] 1.886556
          LE L2CAP: LE Connection Response (0x15) ident 1 len 10
            Destination CID: 0x0041
            MTU: 517
            MPS: 251
            Credits: 10
            Result: Connection successful (0x0000)

EATT (Enhanced ATT) uses PSM 0x0027 over LE Credit-Based channels to
provide multiple parallel ATT bearers.

Connection Parameter Updates
-----------------------------

LE peripherals frequently request connection parameter changes via
L2CAP signaling::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 16   #493 [hci0] 0.003915
          LE L2CAP: Connection Parameter Update Request (0x12) ident 1 len 8
            Min interval: 24
            Max interval: 40
            Peripheral latency: 0
            Timeout multiplier: 256

    > ACL Data RX: Handle 2048 flags 0x02 dlen 10   #495 [hci0] 0.066003
          LE L2CAP: Connection Parameter Update Response (0x13) ident 1 len 2
            Result: Connection Parameters accepted (0x0000)

A result of ``Connection Parameters rejected (0x0001)`` means the
central denied the request.

Automating L2CAP Analysis
--------------------------

**Find all L2CAP channel establishments**::

    grep -n "Connection Request\|Connection Response\|LE Connection Request\|LE Connection Response" output.txt

**Track PSM usage** (identifies which protocols are active)::

    grep -n "PSM:" output.txt

**Find connection parameter update issues**::

    grep -n "Parameter Update Request\|Parameter Update Response\|Parameters rejected" output.txt

**Find EATT channel setup**::

    grep -n "PSM: 39\|Enhanced Credit" output.txt

**Trace a specific L2CAP channel**: To follow traffic on a dynamic
channel, note the Source CID and Destination CID from the Connection
Request/Response pair. Then search for those CIDs in subsequent data
frames.

.. include:: btmon-le-audio.rst

PROTOCOL ERROR CODES
=====================

btmon automatically decodes error codes from multiple protocol layers.
This section provides a reference for interpreting errors seen across
ATT, SMP, and L2CAP layers.

ATT Error Codes
----------------

ATT errors appear in ``Error Response (0x01)`` PDUs. Beyond the GATT
discovery context (where ``Attribute Not Found`` is normal), these
errors indicate real problems:

.. list-table::
   :header-rows: 1
   :widths: 8 35 57

   * - Code
     - Error
     - Diagnostic Meaning
   * - 0x01
     - Invalid Handle
     - Client used a handle that does not exist
   * - 0x02
     - Read Not Permitted
     - Characteristic does not allow reads
   * - 0x03
     - Write Not Permitted
     - Characteristic does not allow writes
   * - 0x05
     - Authentication Insufficient
     - Operation requires an authenticated (MITM-protected)
       bond. Triggers SMP pairing if not yet bonded.
   * - 0x06
     - Request Not Supported
     - Server does not support this ATT operation
   * - 0x07
     - Invalid Offset
     - Read/write blob offset exceeds attribute length
   * - 0x08
     - Authorization Insufficient
     - Server requires additional authorization
   * - 0x09
     - Prepare Queue Full
     - Too many prepared writes queued
   * - 0x0a
     - Attribute Not Found
     - No attributes in requested range. Normal termination
       for GATT discovery procedures.
   * - 0x0b
     - Attribute Not Long
     - Attribute cannot be read with Read Blob
   * - 0x0c
     - Insufficient Encryption Key Size
     - Encryption key is too short
   * - 0x0d
     - Invalid Attribute Value Length
     - Write value length is incorrect for this attribute
   * - 0x0e
     - Unlikely Error
     - Generic unlikely error
   * - 0x0f
     - Insufficient Encryption
     - Link is not encrypted. Triggers encryption setup.
   * - 0x10
     - Unsupported Group Type
     - Attribute type is not a valid grouping type
   * - 0x11
     - Insufficient Resources
     - Server out of resources
   * - 0x12
     - Value Not Allowed
     - Value is not within permitted range
   * - 0x80-0x9f
     - Application Error
     - Application-specific error; meaning depends on the
       profile/service. ASCS uses these for ASE-specific
       errors.
   * - 0xfc
     - Write Request Rejected
     - Write rejected (CSIP, ASCS)
   * - 0xfd
     - CCC Descriptor Improperly Configured
     - CCC must be enabled before certain operations
   * - 0xfe
     - Procedure Already in Progress
     - Another procedure is already running
   * - 0xff
     - Out of Range
     - Value is outside valid range

L2CAP Connection Response Results
----------------------------------

L2CAP Connection Response and LE Connection Response include a result
code:

.. list-table::
   :header-rows: 1
   :widths: 8 35 57

   * - Code
     - Result
     - Diagnostic Meaning
   * - 0x0000
     - Connection successful
     - Channel established normally
   * - 0x0001
     - Connection pending
     - Connection in progress (BR/EDR only)
   * - 0x0002
     - Connection refused - PSM not supported
     - Remote does not have a server for this protocol
   * - 0x0003
     - Connection refused - security block
     - Security requirements not met
   * - 0x0004
     - Connection refused - no resources
     - Remote ran out of channel resources
   * - 0x0005
     - Connection refused - invalid Source CID
     - Source CID is invalid or already in use
   * - 0x0006
     - Connection refused - Source CID already allocated
     - CID collision
   * - 0x0007
     - Connection refused - unacceptable parameters
     - LE credit-based: MTU, MPS, or credits unacceptable
   * - 0x0008
     - Connection refused - invalid parameters
     - Parameter values are invalid
   * - 0x0009
     - Connection refused - insufficient authentication
     - Not authenticated
   * - 0x000a
     - Connection refused - insufficient authorization
     - Not authorized
   * - 0x000b
     - Connection refused - insufficient encryption key size
     - Encryption key too short
   * - 0x000c
     - Connection refused - insufficient encryption
     - Link not encrypted

Automating Error Detection
---------------------------

**Find all ATT errors** (excluding normal discovery termination)::

    grep -n "Error Response" output.txt

Then check whether each error is ``Attribute Not Found (0x0a)``
within a discovery sequence (normal) or a different error code
(problem).

**Find all authentication/encryption related errors**::

    grep -n "Authentication Insufficient\|Insufficient Encryption\|Insufficient Security\|security block" output.txt

These indicate the link needs pairing or encryption. Check whether
SMP pairing follows.

**Find all L2CAP channel rejections**::

    grep -n "Connection refused" output.txt

**Cross-layer error correlation**:

Errors often cascade across layers. Common patterns:

1. ATT ``Insufficient Encryption`` (0x0f) → triggers HCI
   ``LE Start Encryption`` → ``Encryption Change`` success → ATT
   operation retried
2. ATT ``Authentication Insufficient`` (0x05) → triggers SMP
   ``Pairing Request`` → pairing completes → ATT operation retried
3. SMP ``Pairing Failed`` → ``Disconnect Complete`` with reason
   ``Authentication Failure (0x05)``
4. L2CAP ``Connection refused - security block`` → triggers SMP
   pairing

.. include:: btmon-advertising.rst

EXAMPLES
========

Capture the traces from hci0 to hcidump.log file
------------------------------------------------

.. code-block::

   $ btmon -i hci0 -w hcidump.log

Open the trace file
-------------------

.. code-block::

   $ btmon -r hcidump.log

Open the trace file with wall-clock timestamps
-----------------------------------------------

.. code-block::

   $ btmon -t -r hcidump.log

Open the trace file with full date and time
--------------------------------------------

.. code-block::

   $ btmon -T -r hcidump.log

AUTOMATED TRACE ANALYSIS
=========================

This section provides guidance for analyzing btmon traces
programmatically or with AI assistance. Each topic references
the detailed protocol section earlier in this document.

Recommended Workflow
--------------------

1. **Get an overview**: Start with ``btmon -a <file>`` to see packet
   counts, connection handles, device addresses, and traffic volumes.

2. **Decode with timestamps**: Use ``btmon -t -r <file> > output.txt``
   to produce a text file with wall-clock timestamps for analysis.

3. **Identify connections**: Search for connection establishment events
   to build a handle-to-address mapping::

       grep -n "Connection Complete\|Enhanced Connection Complete\|CIS Established" output.txt

4. **Track disconnections**: Search for disconnect events and their
   reasons::

       grep -n "Disconnect Complete" output.txt

   Then examine the lines following each match for the ``Reason:``
   field. See `HCI ERROR AND DISCONNECT REASON CODES`_ for
   interpretation.

5. **Check pairing/security**: Search for SMP activity (see
   `SMP PAIRING FLOW`_)::

       grep -n "Pairing Request\|Pairing Response\|Pairing Failed\|Encryption Change" output.txt

6. **Identify LE Audio**: Search for ASCS and CIS activity (see
   `LE AUDIO PROTOCOL FLOW`_)::

       grep -n "ASE Control Point\|CIG Parameters\|Create Connected Isochronous\|CIS Established\|Setup ISO Data Path" output.txt

7. **Check for errors**: Search across all protocol layers (see
   `PROTOCOL ERROR CODES`_)::

       # HCI-level errors
       grep -n "Status:" output.txt | grep -v "Success"

       # ATT-level errors
       grep -n "Error Response" output.txt

       # SMP failures
       grep -n "Pairing Failed" output.txt

       # L2CAP rejections
       grep -n "Connection refused" output.txt

8. **Extract GATT discovery**: Filter the GATT service/characteristic
   discovery traffic (see `RECONSTRUCTING A GATT DATABASE FROM SNOOP
   TRACES`_)::

       # Find all service discovery responses
       grep -n "Read By Group Type Response\|Attribute group list\|Handle range.*UUID" output.txt

       # Find all characteristic discovery responses
       grep -n "Read By Type Response\|Properties:\|Value Handle:\|Value UUID:" output.txt

       # Find all descriptor discovery responses
       grep -n "Find Information Response\|Format:\|Handle:.*UUID:" output.txt

       # Find targeted service searches
       grep -n "Find By Type Value" output.txt

9. **Check L2CAP channels**: Identify protocol usage and channel
   issues (see `L2CAP CHANNEL TRACKING`_)::

       grep -n "PSM:\|Connection Request\|Connection Response\|Parameter Update" output.txt

10. **Check advertising**: See what devices are visible and what
    they advertise (see `ADVERTISING AND SCANNING`_)::

        grep -n "Advertising Report\|Name (complete):\|Appearance:" output.txt

Key Patterns for Connection Lifecycle
-------------------------------------

A complete connection lifecycle for an LE ACL connection follows this
pattern in the trace:

1. ``LE Enhanced Connection Complete`` -- connection established,
   note the Handle and Peer address
2. ``LE Connection Update Complete`` -- connection parameters changed
   (may occur zero or more times)
3. ``Encryption Change`` -- link encrypted (may show encryption
   algorithm). See `SMP PAIRING FLOW`_ for the SMP exchange that
   precedes this.
4. ACL Data with ATT/SMP/L2CAP -- service discovery and data exchange.
   See `RECONSTRUCTING A GATT DATABASE FROM SNOOP TRACES`_ for GATT,
   `L2CAP CHANNEL TRACKING`_ for channel setup, and
   `PROTOCOL ERROR CODES`_ for error interpretation.
5. ``Disconnect Complete`` -- connection ended, check Reason field.
   See `HCI ERROR AND DISCONNECT REASON CODES`_ for reason codes.

For LE Audio connections, additional steps appear between 3 and 5
(see `LE AUDIO PROTOCOL FLOW`_ for full details):

- ATT operations on PACS/ASCS characteristics (codec negotiation)
- ``LE Set CIG Parameters`` command and response
- ``LE Create CIS`` command
- ``LE CIS Established`` event (note the CIS handle)
- ``LE Setup ISO Data Path`` command
- ISO Data TX/RX (audio streaming)
- ``Disconnect Complete`` on CIS handle (stream ended)
- ``LE Remove CIG`` (group removed)

Common Debugging Scenarios
---------------------------

**Pairing failure diagnosis**:

1. Find ``Pairing Request`` -- note IO capabilities and auth
   requirements
2. Find ``Pairing Response`` -- compare to determine association model
3. If ``Pairing Failed`` appears, the reason code identifies the
   failure (see `SMP PAIRING FLOW`_)
4. If ``Encryption Change`` shows ``Status: Success``, pairing
   succeeded
5. If no SMP traffic on reconnect but ``Encryption Change`` fails,
   the bond was lost on one side

**Audio streaming failure diagnosis** (see `LE AUDIO PROTOCOL FLOW`_):

1. Check PACS reads -- do both devices support compatible codecs?
2. Check ASE Control Point Config Codec -- was it accepted?
3. Check ASE state notifications -- did the ASE reach Streaming?
4. Check ``CIS Established`` -- was Status Success?
5. Check ``Setup ISO Data Path`` -- was it configured?
6. Check for ISO Data packets -- is audio actually flowing?

**GATT operation rejected** (see `PROTOCOL ERROR CODES`_):

1. Find ``Error Response`` -- note the error code
2. ``Insufficient Encryption`` (0x0f) → expect ``LE Start Encryption``
   to follow
3. ``Authentication Insufficient`` (0x05) → expect SMP pairing to
   follow
4. After security is established, the ATT operation should be retried

**Connection parameter negotiation failure**:

1. Find ``Connection Parameter Update Request`` (L2CAP level)
2. Check the Response -- ``rejected`` means the central denied it
3. Alternatively, find ``LE Connection Update Complete`` (HCI level)
4. Check Status -- non-zero means the controller rejected the update

Vendor-Specific Events
----------------------

Vendor-specific HCI events (event code 0xFF) contain
controller-manufacturer diagnostic data. btmon decodes some vendor
events for known manufacturers (Intel, Broadcom, etc.) but many
sub-events show as ``Unknown`` with raw hex data. These are expected
and generally not actionable without vendor documentation.

Intel controllers emit extended telemetry events (subevent 0x8780)
that include connection quality metrics, error counters, and firmware
state. Partial decoding is available in ``monitor/intel.c``.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

SEE ALSO
========

btsnoop(7)

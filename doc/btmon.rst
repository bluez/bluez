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

    < ACL Data TX: Handle 2048 [1.. flags 0x00 dlen 16  #493 [hci0] 12:36:18.977915
    │              │              │            │          │    │       │
    │              │              │            │          │    │       └─ Timestamp
    │              │              │            │          │    └─ Controller
    │              │              │            │          └─ Frame number
    │              │              │            └─ Data length
    │              │              └─ Fragment info / flags
    │              └─ Connection handle
    └─ Direction: TX = outgoing, RX = incoming

ACL data is automatically decoded into higher-layer protocols::

    < ACL Data TX: Handle 2048 [2/6] flags 0x00 dlen 7  #494 [hci0] 12:36:18.978488
          ATT: Exchange MTU Request (0x02) len 2
            Client RX MTU: 517

    > ACL Data RX: Handle 2048 flags 0x02 dlen 11       #497 [hci0] 12:36:19.000048
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

    > ACL Data RX: Handle 2048 flags 0x02 dlen 11       #497 [hci0] 12:36:19.000048
          SMP: Pairing Request (0x01) len 6                          ← L2CAP/SMP layer
            IO capability: NoInputNoOutput (0x03)                    ← SMP fields
            OOB data: Authentication data not present (0x00)
            Authentication requirement: Bonding, MITM, SC (0x2d)
            Max encryption key size: 16

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
    < ACL Data TX: Handle 2048 [1.. flags 0x00 dlen 16  #493 [hci0] 12:36:18.977915
          LE L2CAP: Connection Parameter Update Request (0x12) ident 1 len 8
    < ACL Data TX: Handle 2048 [2/6] flags 0x00 dlen 7  #494 [hci0] 12:36:18.978488
          ATT: Exchange MTU Request (0x02) len 2
            Client RX MTU: 517

Read this as: The controller reported a new LE connection (HCI event).
The kernel forwarded this as a MGMT Device Connected event. bluetoothd
logged its ``connected_callback()``. Then data exchange began -- an L2CAP
parameter update and ATT MTU negotiation over the new ACL connection.

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

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

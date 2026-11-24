.. This file is included by btmon.rst.

MGMT PROTOCOL FLOWS
=====================

The Management Interface (MGMT) is the structured command/event protocol
between userspace (typically ``bluetoothd``) and the kernel Bluetooth
subsystem. In btmon output, MGMT traffic is prefixed with ``@`` and
provides insight into adapter configuration, device discovery, pairing,
and connection management at a higher level than raw HCI. This section
covers common MGMT protocol flows as seen through btmon.

For MGMT output format basics (line anatomy, Open/Close, parameters,
events), see the "Management Traffic" subsection in READING THE OUTPUT
above.

Initialization and Version Handshake
--------------------------------------

When ``bluetoothd`` starts, it opens a management socket and queries
the kernel for protocol version and supported features. This handshake
must succeed before any controller operations::

    @ MGMT Open: bluetoothd (privileged) version 1.23      {0x0001} 12:34:49.881936
    @ MGMT Command: Read Management Ver.. (0x0001) plen 0  {0x0001} 12:34:49.882003
    @ MGMT Event: Command Complete (0x0001) plen 6         {0x0001} 12:34:49.882010
          Read Management Version Information (0x0001) plen 3
            Status: Success (0x00)
            Version: 1.23
    @ MGMT Command: Read Management Sup.. (0x0002) plen 0  {0x0001} 12:34:49.882050
    @ MGMT Event: Command Complete (0x0001) plen 58        {0x0001} 12:34:49.882055
          Read Supported Commands (0x0002) plen 55
            Status: Success (0x00)
            Num of commands: 120
            Num of events: 38

After the version check, ``bluetoothd`` reads the controller list and
queries each controller's information::

    @ MGMT Command: Read Controller Index List (0x0003) plen 0  {0x0001} 12:34:49.882100
    @ MGMT Event: Command Complete (0x0001) plen 7              {0x0001} 12:34:49.882105
          Read Controller Index List (0x0003) plen 4
            Status: Success (0x00)
            Num controllers: 1
            Controller: hci0

    @ MGMT Command: Read Controller Inf.. (0x0004) plen 0  {0x0001} [hci0] 12:34:49.882200
    @ MGMT Event: Command Complete (0x0001) plen 283       {0x0001} [hci0] 12:34:49.882210
          Read Controller Information (0x0004) plen 280
            Status: Success (0x00)
            Address: 00:11:22:33:44:55
            Bluetooth version: 5.4
            Manufacturer: Intel (2)
            Supported settings: 0x003effff
            Current settings: 0x00000080

Key things to check in the initialization flow:

- **MGMT Open** -- Confirms ``bluetoothd`` connected. If missing, the
  daemon did not start or crashed before reaching MGMT setup.
- **Version mismatch** -- If ``bluetoothd`` expects a newer MGMT version
  than the kernel provides, some features may be unavailable.
- **Num controllers: 0** -- No Bluetooth hardware detected. Check
  ``dmesg`` for driver issues.
- **Current settings** -- The bitmask shows what is currently enabled on
  the controller (Powered, LE, BR/EDR, SSP, etc.).

Adapter Configuration
----------------------

After reading controller info, ``bluetoothd`` configures the adapter
with a series of MGMT commands before powering it on. The exact
sequence depends on ``main.conf`` settings and adapter capabilities.

**Loading stored keys**::

    @ MGMT Command: Load Link Keys (0x0012) plen 3  {0x0001} [hci0] 12:34:50.001200
          Debug keys: Disabled (0x00)
          Key count: 0
    @ MGMT Event: Command Complete (0x0001) plen 4   {0x0001} [hci0] 12:34:50.001220
          Load Link Keys (0x0012) plen 1
            Status: Success (0x00)

    @ MGMT Command: Load Long Term Keys (0x0013) plen 2  {0x0001} [hci0] 12:34:50.001300
          Key count: 0
    @ MGMT Event: Command Complete (0x0001) plen 4        {0x0001} [hci0] 12:34:50.001315
          Load Long Term Keys (0x0013) plen 1
            Status: Success (0x00)

    @ MGMT Command: Load Identity Resolving Keys (0x0030) plen 2  {0x0001} [hci0] 12:34:50.001400
          Key count: 0
    @ MGMT Event: Command Complete (0x0001) plen 4                {0x0001} [hci0] 12:34:50.001415
          Load Identity Resolving Keys (0x0030) plen 1
            Status: Success (0x00)

When bonded devices exist, the Key count will be non-zero and btmon
will list each key entry. A large number of keys can indicate many
paired devices; this is normal.

**Setting adapter properties**::

    @ MGMT Command: Set Secure Connections (0x002d) plen 1  {0x0001} [hci0] 12:34:50.002100
          Secure connections: Enabled (0x01)
    @ MGMT Event: Command Complete (0x0001) plen 7          {0x0001} [hci0] 12:34:50.002120
          Set Secure Connections (0x002d) plen 4
            Status: Success (0x00)
            Current settings: 0x004e0a81

    @ MGMT Command: Set Bondable (0x0009) plen 1            {0x0001} [hci0] 12:34:50.002200
          Bondable: Enabled (0x01)
    @ MGMT Event: Command Complete (0x0001) plen 7          {0x0001} [hci0] 12:34:50.002220
          Set Bondable (0x0009) plen 4
            Status: Success (0x00)
            Current settings: 0x004e0a91

**Powering on**::

    @ MGMT Command: Set Powered (0x0005) plen 1     {0x0001} [hci0] 12:35:04.033564
          Powered: Enabled (0x01)
    @ MGMT Event: Command Complete (0x0001) plen 7   {0x0001} [hci0] 12:35:04.114789
          Set Powered (0x0005) plen 4
            Status: Success (0x00)
            Current settings: 0x004e0ac1

Between the ``Set Powered`` command and its response, btmon will show
the HCI commands the kernel sends to initialize the radio (see
`HCI INITIALIZATION SEQUENCE`_).

Discovery
----------

Device discovery is initiated through MGMT rather than raw HCI commands.
``bluetoothd`` (or ``btmgmt``) sends a Start Discovery command
specifying which transport types to scan.

**Starting discovery**::

    @ MGMT Command: Start Discovery (0x0023) plen 1  {0x0001} [hci0] 12:36:00.100200
          Address type: 0x07
            BR/EDR
            LE Public
            LE Random
    @ MGMT Event: Command Complete (0x0001) plen 5   {0x0001} [hci0] 12:36:00.100500
          Start Discovery (0x0023) plen 2
            Status: Success (0x00)
            Address type: 0x07

After this, btmon shows the HCI-level scan commands the kernel issues
(``LE Set Scan Parameters``, ``LE Set Scan Enable``, and/or
``Inquiry`` for BR/EDR). Discovered devices appear as MGMT events::

    @ MGMT Event: Device Found (0x0012) plen 38      {0x0001} [hci0] 12:36:00.250003
          LE Address: AA:BB:CC:DD:EE:FF (Random)
          RSSI: -62
          Flags: 0x0000
          EIR Data:
            Name (complete): My Device
            TX power: 0

**Service discovery** uses a filtered variant::

    @ MGMT Command: Start Service Discovery (0x003a) plen 19  {0x0001} [hci0] 12:36:10.100200
          Address type: 0x06
            LE Public
            LE Random
          RSSI threshold: -127
          UUIDs: 1
            UUID: Heart Rate (0x180d)
    @ MGMT Event: Command Complete (0x0001) plen 5            {0x0001} [hci0] 12:36:10.100500
          Start Service Discovery (0x003a) plen 2
            Status: Success (0x00)

**Stopping discovery**::

    @ MGMT Command: Stop Discovery (0x0024) plen 1   {0x0001} [hci0] 12:36:15.200100
          Address type: 0x07
    @ MGMT Event: Command Complete (0x0001) plen 5    {0x0001} [hci0] 12:36:15.200400
          Stop Discovery (0x0024) plen 2
            Status: Success (0x00)

    @ MGMT Event: Discovering (0x0013) plen 2         {0x0001} [hci0] 12:36:15.200500
          Address type: 0x07
          Discovery: Disabled (0x00)

Discovery problems to look for:

- **Status: Busy (0x0a)** on Start Discovery -- Another discovery
  session is already active.
- **Status: Not Powered (0x0f)** -- The adapter is not powered on.
- **Status: RFKilled (0x12)** -- The radio is blocked by rfkill.
- **No Device Found events** -- The remote device may not be
  advertising, or address type filtering may be wrong.

Pairing and Bonding via MGMT
------------------------------

MGMT provides a high-level pairing interface. The host sends a
``Pair Device`` command; the kernel coordinates SMP or SSP as
appropriate and reports the result.

**Initiating pairing**::

    @ MGMT Command: Pair Device (0x0019) plen 8      {0x0001} [hci0] 12:37:00.500200
          LE Address: AA:BB:CC:DD:EE:FF (Random)
          Capability: KeyboardDisplay (0x04)

After this command, btmon shows the underlying SMP or SSP exchange
(see `SMP PAIRING FLOW`_ and `HCI INITIALIZATION SEQUENCE`_ for
details). User interaction events may appear::

    @ MGMT Event: User Confirmation Request (0x000f) plen 12  {0x0001} [hci0] 12:37:01.200100
          LE Address: AA:BB:CC:DD:EE:FF (Random)
          Value: 123456

    @ MGMT Command: User Confirmation Reply (0x001e) plen 6   {0x0001} [hci0] 12:37:03.800200
          LE Address: AA:BB:CC:DD:EE:FF (Random)
    @ MGMT Event: Command Complete (0x0001) plen 10            {0x0001} [hci0] 12:37:03.800350
          User Confirmation Reply (0x001e) plen 7
            Status: Success (0x00)

Or for passkey entry::

    @ MGMT Event: User Passkey Request (0x0010) plen 6        {0x0001} [hci0] 12:37:01.200100
          LE Address: AA:BB:CC:DD:EE:FF (Random)

    @ MGMT Command: User Passkey Reply (0x0020) plen 10       {0x0001} [hci0] 12:37:05.100200
          LE Address: AA:BB:CC:DD:EE:FF (Random)
          Passkey: 123456

**Pairing success**::

    @ MGMT Event: New Long Term Key (0x000a) plen 37   {0x0001} [hci0] 12:37:06.100200
          Store hint: Yes (0x01)
          LE Address: AA:BB:CC:DD:EE:FF (Random)
          Key type: Authenticated P-256 (0x03)
          Central: 0x00
          Encryption size: 16

    @ MGMT Event: New Identity Resolving Key (0x0018) plen 30  {0x0001} [hci0] 12:37:06.100300
          Store hint: Yes (0x01)
          Random address: AA:BB:CC:DD:EE:FF
          LE Address: 11:22:33:44:55:66 (Public)
          Key: 00112233445566778899aabbccddeeff

    @ MGMT Event: Command Complete (0x0001) plen 10   {0x0001} [hci0] 12:37:06.100500
          Pair Device (0x0019) plen 7
            Status: Success (0x00)
            LE Address: AA:BB:CC:DD:EE:FF (Random)

Key events to check after pairing:

- **New Long Term Key** with ``Store hint: Yes`` -- The kernel is
  telling userspace to persist this key for future reconnections.
- **New Identity Resolving Key** -- Reveals the device's real address
  behind an RPA. This is essential for address resolution on reconnect.
- **Key type** -- ``Authenticated P-256`` indicates Secure Connections
  with MITM protection. ``Unauthenticated P-256`` means Just Works SC.
  ``Authenticated`` (no P-256) means Legacy with MITM.

**Pairing failure**::

    @ MGMT Event: Command Complete (0x0001) plen 10   {0x0001} [hci0] 12:37:06.100500
          Pair Device (0x0019) plen 7
            Status: Authentication Failed (0x05)
            LE Address: AA:BB:CC:DD:EE:FF (Random)

MGMT pairing error codes:

.. list-table::
   :header-rows: 1
   :widths: 8 30 62

   * - Code
     - Status
     - Diagnostic Meaning
   * - 0x03
     - Failed
     - Generic failure; check SMP or HCI errors preceding this
   * - 0x04
     - Connect Failed
     - Could not establish connection before pairing
   * - 0x05
     - Authentication Failed
     - SMP or SSP authentication did not succeed; check SMP Pairing
       Failed reason or HCI Authentication Failure event
   * - 0x08
     - Timeout
     - Pairing timed out; remote device may have gone out of range
   * - 0x0b
     - Rejected
     - Remote device rejected the pairing request
   * - 0x0d
     - Invalid Parameters
     - Bad address type or capability value in the Pair Device command

Device Connection and Disconnection
--------------------------------------

MGMT reports connection lifecycle events that complement the HCI-level
events shown elsewhere in the trace.

**Device connected**::

    @ MGMT Event: Device Connected (0x000b) plen 13   {0x0001} [hci0] 12:36:18.974319
          LE Address: AA:BB:CC:DD:EE:FF (Random)
          Flags: 0x0000
          EIR Data Length: 0

This event follows the HCI ``LE (Enhanced) Connection Complete`` event.
It tells userspace that a new connection is ready.

**Device disconnected**::

    @ MGMT Event: Device Disconnected (0x000c) plen 8  {0x0001} [hci0] 12:38:20.500200
          LE Address: AA:BB:CC:DD:EE:FF (Random)
          Reason: Connection timeout (0x01)

Disconnect reasons reported by MGMT:

.. list-table::
   :header-rows: 1
   :widths: 8 30 62

   * - Code
     - Reason
     - Diagnostic Meaning
   * - 0x00
     - Unspecified
     - No reason provided; typically a local disconnect
   * - 0x01
     - Connection timeout
     - Link supervision timeout expired; device may be out of range
   * - 0x02
     - Connection terminated by local host
     - Local side initiated the disconnection
   * - 0x03
     - Connection terminated by remote host
     - Remote device initiated the disconnection

**Unpair Device** removes stored keys and optionally disconnects::

    @ MGMT Command: Unpair Device (0x001a) plen 7     {0x0001} [hci0] 12:39:00.100200
          LE Address: AA:BB:CC:DD:EE:FF (Random)
          Disconnect: Enabled (0x01)
    @ MGMT Event: Command Complete (0x0001) plen 10    {0x0001} [hci0] 12:39:00.100500
          Unpair Device (0x001a) plen 7
            Status: Success (0x00)

Advertising via MGMT
---------------------

Modern BlueZ configures advertising through MGMT commands rather than
sending HCI LE advertising commands directly. This provides a
multi-client advertising infrastructure.

**Adding an advertisement**::

    @ MGMT Command: Add Advertising (0x003e) plen 22   {0x0001} [hci0] 12:40:00.100200
          Instance: 1
          Flags: 0x0006
            The connectable flag will be managed
            The limited discoverable flag will be managed
          Duration: 0
          Timeout: 0
          Advertising data length: 6
          Scan response length: 0
    @ MGMT Event: Command Complete (0x0001) plen 5      {0x0001} [hci0] 12:40:00.100500
          Add Advertising (0x003e) plen 2
            Status: Success (0x00)
            Instance: 1

**Removing an advertisement**::

    @ MGMT Command: Remove Advertising (0x003f) plen 1  {0x0001} [hci0] 12:41:00.100200
          Instance: 1
    @ MGMT Event: Command Complete (0x0001) plen 5       {0x0001} [hci0] 12:41:00.100500
          Remove Advertising (0x003f) plen 2
            Status: Success (0x00)
            Instance: 1

For the HCI-level advertising commands that result from these MGMT
operations, see `ADVERTISING AND SCANNING`_.

Error Diagnosis
----------------

MGMT Command Status and Command Complete events carry error codes that
are distinct from HCI error codes. When diagnosing failures, check
both layers.

**MGMT error in Command Complete**::

    @ MGMT Event: Command Complete (0x0001) plen 4    {0x0001} [hci0] 12:42:00.100200
          Set Powered (0x0005) plen 1
            Status: RFKilled (0x12)

**MGMT Command Status** (asynchronous command accepted or rejected)::

    @ MGMT Event: Command Status (0x0002) plen 3     {0x0001} [hci0] 12:42:01.100200
          Start Discovery (0x0023) plen 0
            Status: Busy (0x0a)

MGMT error codes:

.. list-table::
   :header-rows: 1
   :widths: 8 30 62

   * - Code
     - Status
     - Diagnostic Meaning
   * - 0x00
     - Success
     - Command completed successfully
   * - 0x01
     - Unknown Command
     - Kernel does not recognize the command; MGMT version may be
       too old
   * - 0x02
     - Not Connected
     - Operation requires an active connection that does not exist
   * - 0x03
     - Failed
     - Generic failure; check HCI events for root cause
   * - 0x04
     - Connect Failed
     - Connection attempt failed at HCI level
   * - 0x05
     - Authentication Failed
     - Pairing or authentication procedure failed
   * - 0x06
     - Not Paired
     - Operation requires an existing bond; device not paired
   * - 0x07
     - No Resources
     - Kernel ran out of resources (memory, handles, etc.)
   * - 0x08
     - Timeout
     - Operation timed out
   * - 0x09
     - Already Connected
     - Connection already exists to target device
   * - 0x0a
     - Busy
     - Another operation is in progress (e.g., discovery running)
   * - 0x0b
     - Rejected
     - Operation rejected by remote device or policy
   * - 0x0c
     - Not Supported
     - Feature not supported by this controller or kernel version
   * - 0x0d
     - Invalid Parameters
     - Bad parameters in the command
   * - 0x0e
     - Disconnected
     - Connection was lost during the operation
   * - 0x0f
     - Not Powered
     - Controller is not powered on; call Set Powered first
   * - 0x10
     - Cancelled
     - Operation was cancelled by the user or another command
   * - 0x11
     - Invalid Index
     - Controller index does not exist
   * - 0x12
     - RFKilled
     - Radio is disabled by rfkill; unblock with ``rfkill unblock bluetooth``
   * - 0x13
     - Already Paired
     - Device is already paired; unpair first if re-pairing is needed
   * - 0x14
     - Permission Denied
     - Process lacks required privileges (CAP_NET_ADMIN)

**Correlating MGMT and HCI errors**: When MGMT reports ``Failed``
(0x03) or ``Authentication Failed`` (0x05), look at the HCI events
immediately preceding the MGMT response. The HCI-level error
(e.g., ``Authentication Failure (0x05)``, ``Connection Timeout
(0x08)``) provides the specific hardware-level cause.

Automating MGMT Analysis
--------------------------

**List all MGMT commands and events**::

    grep -n "@ MGMT" output.txt

**Find MGMT errors (non-zero status)**::

    grep -n "@ MGMT" output.txt | grep -v "Status: Success"

**Track adapter power state changes**::

    grep -n "Set Powered\|RFKilled\|Not Powered" output.txt

**Find all discovery activity**::

    grep -n "Start Discovery\|Stop Discovery\|Device Found\|Discovering" output.txt

**Find pairing activity via MGMT**::

    grep -n "Pair Device\|User Confirmation\|User Passkey\|New Long Term Key\|New Identity Resolving Key\|Authentication Failed" output.txt

**Find connection lifecycle events**::

    grep -n "Device Connected\|Device Disconnected\|Unpair Device" output.txt

**Identify which MGMT clients are active**::

    grep -n "@ MGMT Open\|@ MGMT Close" output.txt

**Full MGMT diagnosis pattern**:

1. Find ``MGMT Open`` -- confirm ``bluetoothd`` connected and note
   socket ID
2. Check ``Read Controller Information`` -- verify address, version,
   and current settings
3. Find ``Set Powered`` -- confirm the adapter was powered on
   successfully
4. Search for non-Success status codes -- these indicate failures
5. For pairing issues, find ``Pair Device`` and trace forward to its
   ``Command Complete`` response
6. For connection issues, find ``Device Connected``/``Device
   Disconnected`` and check the disconnect reason

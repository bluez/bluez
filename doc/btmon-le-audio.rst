.. This file is included by btmon.rst.

LE AUDIO PROTOCOL FLOW
=======================

LE Audio uses a multi-layer protocol stack visible in btmon traces.
The setup sequence involves ATT operations on specific GATT
characteristics (PACS, ASCS) followed by HCI-level CIS/BIG
management. btmon fully decodes all layers.

PACS: Published Audio Capabilities
------------------------------------

Before audio streaming begins, devices exchange codec capabilities
via the Published Audio Capabilities Service (PACS). The client reads
PACS characteristics to learn what the remote device supports.

**Sink PAC read** (remote device's receive capabilities)::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 7    #550 [hci0] 0.824003
          ATT: Read Request (0x0a) len 2
            Handle: 0x0075

    > ACL Data RX: Handle 2048 flags 0x02 dlen 30   #552 [hci0] 0.886556
          ATT: Read Response (0x0b) len 25
            Handle: 0x0075
              Number of PAC(s): 1
              Codec: LC3 (0x06)
              Codec Specific Capabilities: #0
                Sampling Frequency: 8000 Hz 16000 Hz 24000 Hz 32000 Hz 48000 Hz
                Frame Duration: 7.5 ms 10 ms
                Audio Channel Counts: 1
                Frame Length: 26 - 240

The PAC record shows codec capabilities using LTV (Length-Type-Value)
encoding. Key fields:

- **Codec** -- ``LC3 (0x06)`` is the mandatory LE Audio codec
- **Sampling Frequency** -- Supported sample rates (bitmask)
- **Frame Duration** -- Supported frame durations (7.5 ms and/or 10 ms)
- **Audio Channel Counts** -- Supported channel counts
- **Frame Length** -- Min and max octets per codec frame

**Audio Locations** (channel assignment)::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 9    #554 [hci0] 0.948003
          ATT: Read Response (0x0b) len 4
            Handle: 0x0077
              Location: Front Left

**Available Audio Contexts** (current use cases)::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 9    #558 [hci0] 1.012556
          ATT: Read Response (0x0b) len 4
            Handle: 0x007b
              Sink Context: Media Conversational
              Source Context: Unspecified

ASCS: Audio Stream Control
----------------------------

The Audio Stream Control Service (ASCS) manages the ASE (Audio Stream
Endpoint) state machine. Each ASE transitions through a defined set
of states as streaming is set up and torn down.

**ASE State Machine**::

    Idle ──► Codec Configured ──► QoS Configured ──► Enabling ──► Streaming
                                                                      │
    Idle ◄── Releasing ◄──────── Disabling ◄─────────────────────────┘

**ASE Status notification** (state change)::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 20   #580 [hci0] 1.456003
          ATT: Handle Value Notification (0x1b) len 15
            Handle: 0x0088
              ASE ID: 0x01
              State: Codec Configured (0x01)
                Framing: Unframed PDUs supported (0x00)
                PHY: 0x02
                  LE 2M PHY (0x02)
                RTN: 2
                Max Transport Latency: 10
                Presentation Delay Min: 20000 us
                Presentation Delay Max: 40000 us
                Preferred Presentation Delay Min: 20000 us
                Preferred Presentation Delay Max: 40000 us
                Codec: LC3 (0x06)
                  Sampling Frequency: 48000 Hz
                  Frame Duration: 10 ms
                  Audio Channel Allocation: Front Left
                  Frame Length: 120

**ASE Control Point operations** drive state transitions. The client
writes to the ASE Control Point characteristic to issue commands::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 25   #582 [hci0] 1.518003
          ATT: Write Request (0x12) len 20
            Handle: 0x008b
              ASE Control Point: Config Codec (0x01)
                ASE ID: 0x01
                Target Latency: Low Latency (0x01)
                PHY: LE 2M PHY
                Codec: LC3 (0x06)
                  Sampling Frequency: 48000 Hz
                  Frame Duration: 10 ms
                  Audio Channel Allocation: Front Left
                  Frame Length: 120

ASE Control Point commands:

.. list-table::
   :header-rows: 1
   :widths: 10 25 65

   * - Opcode
     - Command
     - Purpose
   * - 0x01
     - Config Codec
     - Select codec and parameters (Idle → Codec Configured)
   * - 0x02
     - Config QoS
     - Set CIG/CIS IDs and QoS params (Codec Configured → QoS Configured)
   * - 0x03
     - Enable
     - Start ASE with metadata (QoS Configured → Enabling)
   * - 0x04
     - Receiver Start Ready
     - Signal receiver readiness (Enabling → Streaming, server-side)
   * - 0x05
     - Disable
     - Stop streaming (Streaming → Disabling)
   * - 0x06
     - Receiver Stop Ready
     - Signal receiver stopped
   * - 0x07
     - Update Metadata
     - Change metadata during streaming
   * - 0x08
     - Release
     - Tear down ASE (any → Releasing → Idle)

Bidirectional Streams (Source + Sink)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A device may expose multiple ASEs with different directions. In the
conversational (telephony) use case, the remote device typically has at
least one **Sink** ASE (receives audio, e.g., speaker) and one
**Source** ASE (sends audio, e.g., microphone). Both ASEs share the
same CIG and often the same CIS, using the bidirectional capability of
Connected Isochronous Streams.

**Direction indicators in btmon traces:**

- The ``Receiver Start Ready`` command is only sent for **Source**
  ASEs (ASEs that send audio toward the local device). The server
  issues this command to indicate it is ready to transmit.
- The ``Receiver Stop Ready`` command likewise applies to Source ASEs.
- **Sink** ASEs transition directly from Enabling to Streaming
  without ``Receiver Start Ready``.

**Typical bidirectional setup sequence** (two ASEs on one CIS)::

    Config Codec  ASE ID=1 (Sink)    → Codec Configured
    Config Codec  ASE ID=3 (Source)  → Codec Configured
    Config QoS    ASE ID=1           → QoS Configured (CIG=X, CIS=Y)
    Config QoS    ASE ID=3           → QoS Configured (CIG=X, CIS=Y)
    Enable        ASE ID=1           → Enabling → Streaming (immediate)
    Enable        ASE ID=3           → Enabling
    CIS Established (Success)
    Setup ISO Data Path  Input  (Host→Controller, for Sink)
    Setup ISO Data Path  Output (Controller→Host, for Source)
    Receiver Start Ready ASE ID=3   → Streaming

Both ASEs may reach Streaming at different times. The Sink ASE can
start receiving audio as soon as CIS is established, while the Source
ASE waits for the ``Receiver Start Ready`` handshake.

.. note::

   **This is normal behavior.** Seeing one Source ASE and one Sink
   ASE on the same connection is the standard bidirectional
   (conversational) configuration. It is **not** an error or
   misconfiguration. Both directions sharing a single CIS is
   efficient and expected.

**Multiple ASEs per direction** are also valid. For example, a stereo
headset may expose two Sink ASEs (left and right channels) and one
Source ASE (mono microphone), each with its own GATT handle for ASE
state notifications.

CIS Setup and Teardown
------------------------

After ASE QoS Configuration, the host creates Connected Isochronous
Streams (CIS) at the HCI level.

**CIG Parameters** (configure the CIS group)::

    < HCI Command: LE Set CIG Parameters (0x08|0x0062) plen 26  #590 [hci0] 1.624003
          CIG ID: 0x00
          Central to Peripheral SDU Interval: 10000 us
          Peripheral to Central SDU Interval: 10000 us
          SCA: 0x00
          Packing: Sequential (0x00)
          Framing: Unframed (0x00)
          Central to Peripheral Max Latency: 10 ms
          Peripheral to Central Max Latency: 10 ms
          Number of CIS: 1
          CIS ID: 0x00
          Central to Peripheral Max SDU: 120
          Peripheral to Central Max SDU: 0
          Central to Peripheral PHY: LE 2M PHY
          Peripheral to Central PHY: LE 2M PHY
          Central to Peripheral RTN: 2
          Peripheral to Central RTN: 2

    > HCI Event: Command Complete (0x0e) plen 8              #592 [hci0] 1.624556
          LE Set CIG Parameters (0x08|0x0062) ncmd 1
            Status: Success (0x00)
            CIG ID: 0x00
            Number of Handles: 1
            Connection Handle: 2064

**CIS Creation**::

    < HCI Command: LE Create CIS (0x08|0x0064) plen 9       #594 [hci0] 1.688003
          Number of CIS: 1
          CIS Handle: 2064
          ACL Handle: 2048

    > HCI Event: LE Meta Event (0x3e) plen 29                #596 [hci0] 1.756556
          LE CIS Established (0x19)
            Status: Success (0x00)
            Connection Handle: 2064
            CIG Sync Delay: 5000 us
            CIS Sync Delay: 5000 us
            Central to Peripheral Latency: 10000 us
            Peripheral to Central Latency: 10000 us
            Central to Peripheral PHY: LE 2M PHY
            Peripheral to Central PHY: LE 2M PHY
            NSE: 3
            Central to Peripheral BN: 1
            Peripheral to Central BN: 0
            Central to Peripheral FT: 2
            Peripheral to Central FT: 2
            Max PDU C to P: 120
            Max PDU P to C: 0
            ISO Interval: 10.00 msec (0x0008)

Note that the CIS Handle (2064) is different from the ACL Handle
(2048). CIS data packets use the CIS handle.

**ISO Data Path Setup**::

    < HCI Command: LE Setup ISO Data Path (0x08|0x006e) plen 13  #598 [hci0] 1.820003
          Handle: 2064
          Data Path Direction: Input (Host to Controller) (0x00)
          Data Path ID: HCI (0x00)
          Coding Format: LC3 (0x06)
          Company ID: 0x0000
          Vendor Codec ID: 0x0000
          Controller Delay: 0 us

After this, ISO data packets flow on the CIS handle::

    < ISO Data TS: Handle 2064 flags 0x02 dlen 124  #600 [hci0] 1.884003

Broadcast Audio (BIG)
----------------------

Broadcast Isochronous Streams use BIG (Broadcast Isochronous Group)
instead of CIS. The setup involves periodic advertising with BASE
(Broadcast Audio Source Endpoint) announcements.

**BASE announcement** (in periodic advertising data)::

    > HCI Event: LE Meta Event (0x3e) plen 80                #200 [hci0] 0.500003
          LE Periodic Advertising Report (0x0f)
            ...
            Service Data: Basic Audio Announcement (0x1851)
              Presentation Delay: 40000 us
              Number of Subgroups: 1
                Number of BIS: 2
                Codec: LC3 (0x06)
                  Sampling Frequency: 48000 Hz
                  Frame Duration: 10 ms
                  Frame Length: 120
                BIS #1
                  Audio Channel Allocation: Front Left
                BIS #2
                  Audio Channel Allocation: Front Right

**BIG creation** (source side)::

    < HCI Command: LE Create BIG (0x08|0x0068) plen 31      #210 [hci0] 0.600003
          BIG Handle: 0x00
          Advertising Handle: 0x01
          Number of BIS: 2
          SDU Interval: 10000 us
          Max SDU: 120
          Max Latency: 10 ms
          RTN: 2
          PHY: LE 2M PHY
          Packing: Sequential (0x00)
          Framing: Unframed (0x00)
          Encryption: Unencrypted (0x00)

**BIG sync** (receiver side)::

    < HCI Command: LE BIG Create Sync (0x08|0x006b) plen 15  #220 [hci0] 0.700003
          BIG Handle: 0x00
          Sync Handle: 0x0001
          Encryption: Unencrypted (0x00)
          Number of BIS: 2
          BIS: 0x01
          BIS: 0x02

BIG Sync Receiver Flow
~~~~~~~~~~~~~~~~~~~~~~

A receiver must complete a specific sequence of steps before it can
receive broadcast audio. The critical prerequisite chain is:

1. **Synchronize to periodic advertising** -- the receiver must first
   discover and sync to the broadcaster's periodic advertising train.
2. **Receive PA Reports with BASE** -- the periodic advertising data
   contains the BASE (Broadcast Audio Source Endpoint) structure
   describing the broadcast's codec configuration.
3. **Receive BIG Info Advertising Report** -- this event tells the
   receiver that a BIG exists on the periodic advertising train and
   provides its parameters (number of BIS, encryption, SDU interval,
   etc.). **This is the critical gate**: without receiving BIG Info,
   the receiver cannot issue ``LE BIG Create Sync``.
4. **Issue LE BIG Create Sync** -- using the sync handle from step 1
   and parameters from step 3.
5. **Receive BIG Sync Established** -- the controller confirms sync
   with BIS connection handles.
6. **Setup ISO Data Path** -- configure the data path for each BIS.
7. **ISO Data flows** -- broadcast audio packets arrive.

If any step fails or is missing, the subsequent steps cannot proceed.
The most common failure pattern is that **BIG Info is never received**
(e.g., the periodic advertising data does not contain a BIG, or PA
sync was lost before BIG Info arrived), which means ``LE BIG Create
Sync`` is never sent.

Without PAST (Direct PA Sync)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When the receiver scans for and syncs to periodic advertising
directly (without assistance from a Broadcast Assistant):

**Step 1 -- Create PA sync**::

    < HCI Command: LE Periodic Advertising Create Sync (0x08|0x0044) plen 14  #100 [hci0] 0.100003
          Options: 0x0000
          SID: 0x01
          Adv Address Type: Public (0x00)
          Adv Address: XX:XX:XX:XX:XX:XX
          Skip: 0x0000
          Sync Timeout: 2000 msec (0x00c8)
          Sync CTE Type: 0x0000

**Step 2 -- PA Sync Established** (sync handle assigned)::

    > HCI Event: LE Meta Event (0x3e) plen 16                 #105 [hci0] 0.150003
          LE Periodic Advertising Sync Established (0x0e)
            Status: Success (0x00)
            Sync Handle: 0x0001
            Advertising SID: 0x01
            Advertiser Address Type: Public (0x00)
            Advertiser Address: XX:XX:XX:XX:XX:XX
            Advertiser PHY: LE 2M PHY (0x02)
            Periodic Advertising Interval: 10.000 msec (0x0008)
            Advertiser Clock Accuracy: 0x05

**Step 3 -- PA Reports** (contain BASE data)::

    > HCI Event: LE Meta Event (0x3e) plen 80                 #110 [hci0] 0.200003
          LE Periodic Advertising Report (0x0f)
            Sync Handle: 0x0001
            ...
            Service Data: Basic Audio Announcement (0x1851)

**Step 4 -- BIG Info Advertising Report** (critical gate)::

    > HCI Event: LE Meta Event (0x3e) plen 24                 #120 [hci0] 0.300003
          LE BIG Info Advertising Report (0x22)
            Sync Handle: 0x0001
            Number BIS: 2
            NSE: 4
            ISO Interval: 10.000 msec (0x0008)
            BN: 2
            PTO: 1
            IRC: 2
            Maximum PDU: 120
            SDU Interval: 10000 us
            Maximum SDU: 120
            PHY: LE 2M PHY (0x02)
            Framing: Unframed (0x00)
            Encryption: 0x00

This event is generated by the controller each time it receives a
periodic advertising packet that contains BIG Info. It provides all
parameters the receiver needs to decide whether to sync to the BIG.
Key fields:

- ``Number BIS`` -- how many BIS streams are available.
- ``SDU Interval`` and ``Maximum SDU`` -- audio frame timing and size.
- ``Encryption`` -- whether a Broadcast Code is required (0x01) or
  not (0x00). If encrypted, the receiver must supply the correct
  Broadcast Code in ``LE BIG Create Sync``.
- ``Sync Handle`` -- must match a currently active PA sync.

**Step 5 -- BIG Create Sync** (using sync handle + BIG Info)::

    < HCI Command: LE BIG Create Sync (0x08|0x006b) plen 15  #130 [hci0] 0.400003
          BIG Handle: 0x00
          BIG Sync Handle: 0x0001
          Encryption: Unencrypted (0x00)
          Broadcast Code: 00000000000000000000000000000000
          Maximum Number Subevents: 0x00
          Timeout: 2000 ms (0x00c8)
          Number of BIS: 2
          BIS: 0x01
          BIS: 0x02

**Step 6 -- BIG Sync Established**::

    > HCI Event: LE Meta Event (0x3e) plen 20                 #135 [hci0] 0.450003
          LE BIG Sync Established (0x1d)
            Status: Success (0x00)
            BIG Handle: 0x00
            Transport Latency: 10000 us
            NSE: 4
            BN: 2
            PTO: 1
            IRC: 2
            Maximum PDU: 120
            ISO Interval: 10.000 msec (0x0008)
            Connection Handle: 0x0010
            Connection Handle: 0x0011

On success, the controller assigns BIS connection handles (0x0010,
0x0011 above). A non-zero Status indicates failure -- common errors:

- ``0x3e`` (Connection Failed to be Established) -- BIG parameters
  do not match or the BIG is no longer present.
- ``0x3f`` (Limit Reached) -- controller resources exhausted.

**Step 7 -- Setup ISO Data Path** (for each BIS)::

    < HCI Command: LE Setup ISO Data Path (0x08|0x006e) plen 13  #140 [hci0] 0.500003
          Connection Handle: 0x0010
          Data Path Direction: Output (Host to Controller) (0x01)
          Data Path ID: HCI (0x00)

    < HCI Command: LE Setup ISO Data Path (0x08|0x006e) plen 13  #145 [hci0] 0.550003
          Connection Handle: 0x0011
          Data Path Direction: Output (Host to Controller) (0x01)
          Data Path ID: HCI (0x00)

**Step 8 -- ISO Data flows** on BIS handles::

    > ISO Data: Handle 0x0010 flags 0x02 dlen 124             #150 [hci0] 0.600003
    > ISO Data: Handle 0x0011 flags 0x02 dlen 124             #151 [hci0] 0.600003

With PAST (Periodic Advertising Sync Transfer)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When a Broadcast Assistant (e.g., a phone) helps a Scan Delegator
(e.g., a hearing aid) sync to a broadcast, it can transfer the PA
sync via PAST over an existing ACL connection. This avoids the
delegator having to scan for and sync to the PA train itself.

The BASS (Broadcast Audio Scan Service) protocol coordinates this:

1. The assistant writes an **Add Source** operation to the delegator's
   BASS control point with ``PA Sync`` set to ``0x01``
   (Synchronize via PAST).
2. The delegator prepares to receive the transfer by setting PAST
   parameters.
3. The assistant transfers its PA sync to the delegator.
4. The delegator receives the PAST event with a sync handle.
5. From here, the flow continues as in the non-PAST case (PA Reports
   → BIG Info → BIG Create Sync → etc.).

**BASS Add Source** (assistant writes to delegator, seen in ATT)::

    < ACL Data TX: Handle 64 flags 0x00 dlen 27               #300 [hci0] 1.000003
          ATT: Write Command (0x52) len 22
            Handle: 0x0025
              Data: 04...
              Opcode: Add Source (0x04)
                Advertiser Address Type: Public (0x00)
                Advertiser Address: XX:XX:XX:XX:XX:XX
                Advertising SID: 0x01
                PA Sync: Synchronize to PA - PAST (0x01)
                PA Interval: 0x0008
                Number of Subgroups: 1
                  BIS Sync: 0x00000003
                  Metadata Length: 0

PA Sync values in the Add Source operation:

- ``0x00`` -- Do not synchronize to PA
- ``0x01`` -- Synchronize to PA, PAST available
- ``0x02`` -- Synchronize to PA, PAST not available (delegator
  must scan and sync directly)

**PAST Parameters** (delegator prepares to receive transfer)::

    < HCI Command: LE Periodic Advertising Sync Transfer Parameters (0x08|0x005c) plen 8  #310 [hci0] 1.100003
          Connection handle: 64
          Mode: Enabled with report events enabled (0x02)
          Skip: 0x00
          Sync timeout: 2000 msec (0x00c8)
          Sync CTE Type: 0x0000

**PAST Transfer** (assistant sends its PA sync)::

    < HCI Command: LE Periodic Advertising Sync Transfer (0x08|0x005a) plen 6  #320 [hci0] 1.200003
          Connection handle: 64
          Service data: 0x0001
          Sync handle: 1

**PAST Received** (delegator gets the sync handle)::

    > HCI Event: LE Meta Event (0x3e) plen 19                 #325 [hci0] 1.250003
          LE Periodic Advertising Sync Transfer Received (0x18)
            Status: Success (0x00)
            Handle: 64
            Connection handle: 64
            Service data: 0x0001
            Sync handle: 1
            SID: 0x01
            Address type: Public (0x00)
            Address: XX:XX:XX:XX:XX:XX
            PHY: LE 2M PHY (0x02)
            Periodic advertising Interval: 10.000
            Clock Accuracy: 0x05

On success, the delegator now has a PA sync (``Sync handle: 1``) and
will begin receiving PA Reports and BIG Info events, continuing from
step 3 of the non-PAST flow above.

.. note::

   **Race condition**: The PAST Parameters command must be sent
   **before** the assistant sends the PAST Transfer. In BlueZ, the
   PA sync state in BASS is set after probing completes to avoid
   the remote sending PAST before the kernel has enabled PAST
   Parameters on the HCI level.

BIG Sync Teardown
^^^^^^^^^^^^^^^^^

**Receiver-initiated teardown** -- the receiver terminates its BIG
sync::

    < HCI Command: LE BIG Terminate Sync (0x08|0x006c) plen 1  #500 [hci0] 5.000003
          BIG Handle: 0x00

    > HCI Event: Command Complete (0x0e) plen 5               #501 [hci0] 5.001003
          LE BIG Terminate Sync (0x08|0x006c) ncmd 1
            Status: Success (0x00)
            BIG Handle: 0x00

**Broadcaster-initiated teardown** -- the broadcaster terminates its
BIG, and the receiver gets a BIG Sync Lost event::

    > HCI Event: LE Meta Event (0x3e) plen 2                  #510 [hci0] 6.000003
          LE BIG Sync Lost (0x1e)
            BIG Handle: 0x00
            Reason: Connection Terminated By Local Host (0x16)

The ``Reason`` field indicates why sync was lost:

- ``0x08`` (Connection Timeout) -- BIG packets not received within
  the sync timeout.
- ``0x13`` (Remote User Terminated Connection) -- broadcaster stopped
  the BIG intentionally.
- ``0x16`` (Connection Terminated By Local Host) -- local controller
  terminated.
- ``0x3e`` (Connection Failed to be Established) -- could not
  establish sync initially.

**Source-side BIG termination** (broadcaster tears down)::

    < HCI Command: LE Terminate BIG (0x08|0x006a) plen 2      #520 [hci0] 7.000003
          BIG Handle: 0x00
          Reason: Connection Terminated By Local Host (0x16)

    > HCI Event: LE Meta Event (0x3e) plen 2                  #521 [hci0] 7.001003
          LE BIG Terminate (0x1c)
            BIG Handle: 0x00
            Reason: Connection Terminated By Local Host (0x16)

BIG Sync Failure Diagnosis
^^^^^^^^^^^^^^^^^^^^^^^^^^

When analyzing a trace where BIG sync fails, check the following in
order:

1. **Is PA sync established?** -- Look for ``LE Periodic Advertising
   Sync Established`` with ``Status: Success``. If missing, the
   receiver never synced to the PA train.
2. **Are PA Reports arriving?** -- Look for ``LE Periodic Advertising
   Report`` events. If absent after PA sync, the PA train may have
   been lost.
3. **Is BIG Info received?** -- Look for ``LE BIG Info Advertising
   Report``. **If this event never appears, the BIG does not exist
   on this PA train**, or the broadcaster has not yet started it.
   Without BIG Info, ``LE BIG Create Sync`` cannot be sent.
4. **Is BIG Create Sync sent?** -- If BIG Info was received but
   ``LE BIG Create Sync`` was never sent, the host-side logic failed
   to act on the BIG Info (e.g., mismatched codec, encryption
   mismatch, application-level issue).
5. **Does BIG Sync Established succeed?** -- Check the ``Status``
   field. A non-zero status means the controller could not sync to
   the BIG.
6. **Is ISO Data Path set up?** -- Look for ``LE Setup ISO Data Path``
   for each BIS handle from BIG Sync Established.
7. **Is ISO Data flowing?** -- Look for ``ISO Data`` packets on the
   BIS handles.

Automating LE Audio Analysis
------------------------------

**Identify LE Audio activity**::

    grep -n "ASE Control Point\|ASE ID\|State:.*Codec Configured\|State:.*QoS Configured\|State:.*Enabling\|State:.*Streaming\|State:.*Releasing" output.txt

**Track ASE state transitions** for a specific ASE::

    grep -n "ASE ID:" output.txt

Then examine the ``State:`` line following each ASE ID match.

**Check codec configuration**::

    grep -n "Codec: LC3\|Sampling Frequency:\|Frame Duration:\|Frame Length:\|Audio Channel" output.txt

**Verify CIS establishment**::

    grep -n "Set CIG Parameters\|Create CIS\|CIS Established\|Setup ISO Data Path" output.txt

**Detect CIS failures** -- check the Status field after
``CIS Established``::

    grep -n "CIS Established" output.txt

Then examine the following line for ``Status:``.

**Detect broadcast audio**::

    grep -n "Basic Audio Announcement\|Create BIG\|BIG Complete\|BIG Create Sync\|BIG Sync\|BIG Info\|BIG Terminate\|BIG Sync Lost" output.txt

**Trace BIG Sync receiver flow** -- verify each prerequisite step::

    grep -n "Periodic Advertising Create Sync\|Periodic Advertising Sync Established\|BIG Info Advertising Report\|BIG Create Sync\|BIG Sync Established\|BIG Sync Lost\|BIG Terminate" output.txt

**Detect PAST-based sync** -- check for Periodic Advertising Sync
Transfer::

    grep -n "Sync Transfer Parameters\|Sync Transfer (0x08\|PAST Received\|PA Sync:.*PAST\|Add Source" output.txt

**Check BIG Info arrival** -- the critical gate for BIG sync. If this
is absent, the receiver has no BIG to sync to::

    grep -n "BIG Info Advertising Report" output.txt

**Full LE Audio diagnosis pattern**:

*Unicast (CIS) flow:*

1. Find PACS reads -- verify codec compatibility between devices
2. Find ASE Control Point writes -- trace the Config Codec → Config
   QoS → Enable sequence
3. Find ASE state notifications -- verify each transition succeeds
4. Find CIG Parameters and CIS creation -- verify HCI-level setup
5. Find ``CIS Established`` -- check Status for success
6. Find ``Setup ISO Data Path`` -- verify data path configuration
7. Find ISO Data packets -- confirm audio is flowing
8. On failure, check ASE Control Point notification responses for
   error codes (Response Code and Response Reason fields)

*Broadcast (BIG) receiver flow:*

1. Find ``Periodic Advertising Create Sync`` or ``PAST Received`` --
   how did PA sync start?
2. Find ``Periodic Advertising Sync Established`` or
   ``PAST Received`` with ``Status: Success`` -- is PA synced?
3. Find ``Periodic Advertising Report`` with
   ``Basic Audio Announcement`` -- is BASE data arriving?
4. Find ``BIG Info Advertising Report`` -- **critical**: does the BIG
   exist? If missing, the BIG cannot be synced.
5. Find ``BIG Create Sync`` -- did the host request BIG sync?
6. Find ``BIG Sync Established`` -- check ``Status`` for success.
7. Find ``Setup ISO Data Path`` for each BIS handle.
8. Find ``ISO Data`` on BIS handles -- confirm audio is flowing.
9. On failure, check for ``BIG Sync Lost`` and examine ``Reason``.

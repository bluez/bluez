.. This file is included by btmon.rst.

CHANNEL SOUNDING PROTOCOL FLOW
===============================

Channel Sounding (CS) enables precise distance measurement between two
Bluetooth LE devices. It uses dedicated HCI commands and events to
configure and execute measurement procedures that exchange tones and
timing packets on multiple channels. btmon fully decodes all CS
operations including step-level result data.

CS uses two roles: the **Initiator** sends CS packets first in each
step, and the **Reflector** responds. Both devices must support CS
(feature bits 46--48 in the LE feature set).

Capability Exchange
--------------------

Before any CS activity, both devices must learn each other's CS
capabilities. The local controller's capabilities are read once,
and the remote device's capabilities are fetched over the air.

**Read local CS capabilities**::

    < HCI Command: LE CS Read Local Supported Capabilities (0x08|0x0089) plen 0  #100 [hci0]

    > HCI Event: Command Complete (0x0e) plen 42                 #101 [hci0]
          LE CS Read Local Supported Capabilities (0x08|0x0089) ncmd 1
            Status: Success (0x00)
            Num Config Supported: 4
            Max Consecutive Procedures Supported: 255
            Num Antennas Supported: 2
            Max Antenna Paths Supported: 4
            Roles Supported: 0x03
              Initiator
              Reflector
            Modes Supported: 0x03
            RTT Capability: 0x03
            RTT AA Only N: 10
            RTT Sounding N: 10
            RTT Random Payload N: 10
            CS Sync PHYs Supported: 0x02
              LE 2M
            T_IP1 Times Supported: 0x0005
              10 us
              30 us
            T_IP2 Times Supported: 0x0005
              10 us
              30 us
            T_FCS Times Supported: 0x0009
              15 us
              50 us
            T_PM Times Supported: 0x0003
              10 us
              20 us

Key capability fields:

- **Roles Supported** -- Bitmask: bit 0 = Initiator, bit 1 = Reflector.
  A device must support at least one role.
- **Modes Supported** -- Bitmask of CS measurement modes the controller
  can perform (Mode 1 = RTT, Mode 2 = PBR tone, Mode 3 = both).
- **CS Sync PHYs** -- Physical layers available for CS sync exchange.
  ``LE 2M`` is the most common.
- **Num Antennas / Max Antenna Paths** -- Determines multi-antenna
  Phase-Based Ranging capability.
- **T_IP / T_FCS / T_PM times** -- Timing parameters the controller
  supports for inter-step and tone durations.

**Read remote CS capabilities** (over the air via LL)::

    < HCI Command: LE CS Read Remote Supported Capabilities (0x08|0x008a) plen 2  #110 [hci0]
          Handle: 2048

    > HCI Event: Command Status (0x0f) plen 4                   #111 [hci0]
          LE CS Read Remote Supported Capabilities (0x08|0x008a) ncmd 1
            Status: Success (0x00)

    > HCI Event: LE Meta Event (0x3e) plen 42                   #115 [hci0]
          LE CS Read Remote Supported Capabilities Complete (0x2c)
            Status: Success (0x00)
            Handle: 2048
            Num Config Supported: 4
            Max Consecutive Procedures Supported: 128
            Num Antennas Supported: 1
            Max Antenna Paths Supported: 1
            Roles Supported: 0x03
              Initiator
              Reflector
            Modes Supported: 0x03
            ...

This is an asynchronous command -- the controller sends Command Status
immediately, then the completion event arrives after the LL exchange.
If this fails with a non-zero status, the remote device may not support
CS or the connection may have dropped.

Cached capabilities can be written directly instead of reading over the
air, using ``LE CS Write Cached Remote Supported Capabilities``.

Security Enable
----------------

CS security must be enabled on the connection before creating
configurations. This performs a CS security start procedure over
the LL to exchange nonces::

    < HCI Command: LE CS Security Enable (0x08|0x008c) plen 2   #120 [hci0]
          Handle: 2048

    > HCI Event: Command Status (0x0f) plen 4                   #121 [hci0]
          LE CS Security Enable (0x08|0x008c) ncmd 1
            Status: Success (0x00)

    > HCI Event: LE Meta Event (0x3e) plen 3                    #125 [hci0]
          LE CS Security Enable Complete (0x2e)
            Status: Success (0x00)
            Handle: 2048

Security Enable must complete successfully before configuration or
procedure commands. If this fails, the link may lack encryption or
the remote does not support CS security.

Default Settings
-----------------

Default settings configure which roles the local device is willing to
accept and the antenna/power preferences for this connection::

    < HCI Command: LE CS Set Default Settings (0x08|0x008d) plen 5  #130 [hci0]
          Handle: 2048
          Role Enable: 0x03
            Initiator
            Reflector
          CS Sync Antenna Selection: 0x01
          Max TX Power: 20

    > HCI Event: Command Complete (0x0e) plen 5                 #131 [hci0]
          LE CS Set Default Settings (0x08|0x008d) ncmd 1
            Status: Success (0x00)
            Handle: 2048

- **Role Enable** -- Bitmask of roles the device is willing to perform.
  Both sides typically enable both roles for flexibility.
- **CS Sync Antenna Selection** -- Preferred antenna for CS sync
  exchange.
- **Max TX Power** -- Upper bound on transmit power for CS procedures
  (dBm, signed).

FAE Table Exchange
-------------------

The Frequency Actuation Error (FAE) table contains per-channel
calibration data that improves distance accuracy. Like capabilities,
it can be read from the remote or written from a cache.

**Read remote FAE table**::

    < HCI Command: LE CS Read Remote FAE Table (0x08|0x008e) plen 2  #135 [hci0]
          Handle: 2048

    > HCI Event: Command Status (0x0f) plen 4                   #136 [hci0]
          LE CS Read Remote FAE Table (0x08|0x008e) ncmd 1
            Status: Success (0x00)

    > HCI Event: LE Meta Event (0x3e) plen 75                   #140 [hci0]
          LE CS Read Remote FAE Table Complete (0x2d)
            Status: Success (0x00)
            Handle: 2048

The FAE table is 72 bytes (one byte per channel). Values are signed
offsets in 0.5 ppm units. A value of ``0x7f`` means the channel is
unused or not measured.

Configuration
--------------

A CS configuration defines the measurement parameters: mode, role,
channel map, and step counts. Up to 4 configurations can exist
simultaneously per connection (``config_id`` 0--3).

**Create a CS configuration**::

    < HCI Command: LE CS Create Config (0x08|0x0090) plen 20    #150 [hci0]
          Handle: 2048
          Config ID: 0
          Create Context: 0x00
          Main Mode Type: 0x01
          Sub Mode Type: 0xff
          Min Main Mode Steps: 2
          Max Main Mode Steps: 5
          Main Mode Repetition: 0
          Mode 0 Steps: 3
          Role: Initiator (0x00)
          RTT Type: 0x01
          CS Sync PHY: LE 2M (0x01)
          Channel Map: ffffffffff7f0000000000000000
          Channel Map Repetition: 1
          Channel Selection Type: 0x00
          Ch3c Shape: 0x00
          Ch3c Jump: 0x00

    > HCI Event: Command Status (0x0f) plen 4                   #151 [hci0]
          LE CS Create Config (0x08|0x0090) ncmd 1
            Status: Success (0x00)

    > HCI Event: LE Meta Event (0x3e) plen 30                   #155 [hci0]
          LE CS Config Complete (0x2f)
            Status: Success (0x00)
            Handle: 2048
            Config ID: 0
            Action: 0x00
            Main Mode Type: 0x01
            Sub Mode Type: 0xff
            Min Main Mode Steps: 2
            Max Main Mode Steps: 5
            Main Mode Repetition: 0
            Mode 0 Steps: 3
            Role: Initiator (0x00)
            RTT Type: 0x01
            CS Sync PHY: LE 2M (0x01)
            Channel Map: ffffffffff7f0000000000000000
            Channel Map Repetition: 1
            Channel Selection Type: 0x00
            Ch3c Shape: 0x00
            Ch3c Jump: 0x00
            T_IP1 Time: 30 us
            T_IP2 Time: 30 us
            T_FCS Time: 50 us
            T_PM Time: 10 us

Key configuration fields:

- **Main Mode Type** -- The primary CS measurement mode:
  ``0x01`` = Mode 1 (RTT only), ``0x02`` = Mode 2 (PBR/tone only),
  ``0x03`` = Mode 3 (RTT + PBR combined).
- **Sub Mode Type** -- Secondary mode interleaved with main mode.
  ``0xff`` = no sub mode.
- **Mode 0 Steps** -- Number of frequency calibration (sync) steps per
  subevent. Mode 0 is always present for frequency offset compensation.
- **Main/Min/Max Mode Steps** -- Controls how many measurement steps
  are performed per subevent.
- **Role** -- ``0x00`` = Initiator, ``0x01`` = Reflector. This is the
  local device's role in this configuration.
- **RTT Type** -- Round-trip time measurement variant (AA only, sounding
  sequence, random sequence).
- **Channel Map** -- 10-byte bitmask of channels available for CS.
  Must have at least 15 channels enabled.
- **T_IP1/T_IP2/T_FCS/T_PM** -- Timing parameters selected by the
  controller from the intersection of both devices' capabilities.
  Reported in the Config Complete event.

The Config Complete event confirms the negotiated parameters. The
controller may adjust timing values based on both devices' capabilities.

**Remove a CS configuration**::

    < HCI Command: LE CS Remove Config (0x08|0x0091) plen 3     #160 [hci0]
          Handle: 2048
          Config ID: 0

    > HCI Event: Command Status (0x0f) plen 4                   #161 [hci0]
          LE CS Remove Config (0x08|0x0091) ncmd 1
            Status: Success (0x00)

Procedure Parameters
---------------------

Before enabling a procedure, its scheduling and antenna parameters
are configured::

    < HCI Command: LE CS Set Procedure Parameters (0x08|0x0093) plen 16  #170 [hci0]
          Handle: 2048
          Config ID: 0
          Max Procedure Len: 200
          Min Procedure Interval: 10
          Max Procedure Interval: 20
          Max Procedure Count: 0
          Min Subevent Len: 5000 us
          Max Subevent Len: 10000 us
          Tone Antenna Config Selection: 0x01
          PHY: LE 2M (0x02)
          TX Power Delta: 0
          Preferred Peer Antenna: 0x01
          SNR Control Initiator: 0x00
          SNR Control Reflector: 0x00

    > HCI Event: Command Complete (0x0e) plen 5                 #171 [hci0]
          LE CS Set Procedure Parameters (0x08|0x0093) ncmd 1
            Status: Success (0x00)
            Handle: 2048

- **Max Procedure Len** -- Maximum duration of a single CS procedure
  in units of 0.625 ms.
- **Procedure Interval** -- Spacing between repeated procedures (in
  connection events).
- **Max Procedure Count** -- ``0`` means indefinite repetition until
  explicitly disabled.
- **Subevent Len** -- Duration bounds for each subevent within a
  procedure (in microseconds, 24-bit).
- **Tone Antenna Config Selection** -- Which antenna pattern to use
  for tone exchange.
- **SNR Control** -- Signal-to-noise ratio requirements for Initiator
  and Reflector.

Procedure Enable / Disable
----------------------------

Once configuration and parameters are set, the CS procedure is started
and stopped with enable/disable commands.

**Enable a CS procedure**::

    < HCI Command: LE CS Procedure Enable (0x08|0x0094) plen 4  #180 [hci0]
          Handle: 2048
          Config ID: 0
          Enable: 0x01

    > HCI Event: Command Status (0x0f) plen 4                   #181 [hci0]
          LE CS Procedure Enable (0x08|0x0094) ncmd 1
            Status: Success (0x00)

    > HCI Event: LE Meta Event (0x3e) plen 20                   #185 [hci0]
          LE CS Procedure Enable Complete (0x30)
            Status: Success (0x00)
            Handle: 2048
            Config ID: 0
            State: 0x01
            Tone Antenna Config Selection: 0x01
            Selected TX Power: 12
            Subevent Len: 5000 us
            Subevents Per Event: 2
            Subevent Interval: 3750
            Event Interval: 10
            Procedure Interval: 10
            Procedure Count: 100
            Max Procedure Len: 200

The Procedure Enable Complete event confirms the actual scheduling
parameters chosen by the controller. Important fields:

- **State** -- ``0x01`` = procedure enabled, ``0x00`` = disabled.
- **Subevents Per Event** -- How many subevents fit in each connection
  event.
- **Procedure Count** -- Actual number of procedures that will be
  executed (may differ from the requested maximum).

**Disable a CS procedure**::

    < HCI Command: LE CS Procedure Enable (0x08|0x0094) plen 4  #300 [hci0]
          Handle: 2048
          Config ID: 0
          Enable: 0x00

    > HCI Event: Command Status (0x0f) plen 4                   #301 [hci0]
          LE CS Procedure Enable (0x08|0x0094) ncmd 1
            Status: Success (0x00)

    > HCI Event: LE Meta Event (0x3e) plen 20                   #305 [hci0]
          LE CS Procedure Enable Complete (0x30)
            Status: Success (0x00)
            Handle: 2048
            Config ID: 0
            State: 0x00
            ...

Channel Classification
-----------------------

The host can restrict which channels CS uses by marking noisy channels
as unused::

    < HCI Command: LE CS Set Channel Classification (0x08|0x0092) plen 10  #145 [hci0]
          Channel Map: ffffffffff7f0000000000

    > HCI Event: Command Complete (0x0e) plen 1                 #146 [hci0]
          LE CS Set Channel Classification (0x08|0x0092) ncmd 1
            Status: Success (0x00)

The channel map is a 10-byte (80-bit) bitmask. Bit N = 1 means channel
N is available for CS. At least 15 channels must remain enabled or the
procedure will abort.

Subevent Results
-----------------

While a CS procedure is running, the controller reports measurement
results via subevent result events. Each subevent contains multiple
steps, and each step contains mode-specific measurement data.

**Subevent Result**::

    > HCI Event: LE Meta Event (0x3e) plen 50                   #200 [hci0]
          LE CS Subevent Result (0x31)
            Handle: 2048
            Config ID: 0
            Start ACL Conn Event Counter: 1200
            Procedure Counter: 0
            Frequency Compensation: 0x0000
            Reference Power Level: -20
            Procedure Done Status: Partial results (0x01)
            Subevent Done Status: All results complete (0x00)
            Abort Reason: 0x00
            Num Antenna Paths: 1
            Num Steps Reported: 8
            Step Data:
              Mode: 0  Channel: 10  Length: 5
                Packet Quality: 0x00
                Packet RSSI: -45
                Packet Antenna: 0
                Measured Freq Offset: 150
              Mode: 1  Channel: 20  Length: 6
                Packet Quality: 0x00
                Packet NADM: Attack is extremely unlikely (0x00)
                Packet RSSI: -42
                ToA/ToD: 1234
                Packet Antenna: 0
              Mode: 2  Channel: 30  Length: 5
                Antenna Permutation Index: 0
                  PCT[0]: I=1024, Q=-512
                  Tone Quality: High (0x00)
              ...

Result events can be split across multiple events when data is large:

**Subevent Result Continue** (continuation fragment)::

    > HCI Event: LE Meta Event (0x3e) plen 40                   #202 [hci0]
          LE CS Subevent Result Continue (0x32)
            Handle: 2048
            Config ID: 0
            Procedure Done Status: Partial results (0x01)
            Subevent Done Status: All results complete (0x00)
            Abort Reason: 0x00
            Num Antenna Paths: 1
            Num Steps Reported: 4
            Step Data:
              ...

CS Step Modes
--------------

Each CS subevent consists of steps executed on different channels. Each
step operates in one of four modes:

**Mode 0 -- Frequency Calibration (CS Sync)**

Mode 0 steps are always present at the start of each subevent. They
exchange a known CS sync sequence to calibrate frequency offsets
between the two devices.

Fields reported:

- **Packet Quality** -- ``0x00`` = CS Access Address matched,
  ``0x01`` = bit errors detected, ``0x02`` = not found.
- **Packet RSSI** -- Received signal strength (signed, dBm).
- **Packet Antenna** -- Antenna index used.
- **Measured Freq Offset** -- Frequency offset in 0.01 ppm units
  (15-bit value). Only present when data length is 5.

**Mode 1 -- Round-Trip Time (RTT)**

Mode 1 measures the time-of-arrival and time-of-departure to compute
round-trip delay for distance estimation.

Fields reported:

- **Packet Quality** -- Same as Mode 0.
- **Packet NADM** -- Normalized Attack Detector Metric, indicates
  likelihood that the RTT measurement has been tampered with:

  - ``0x00`` = attack extremely unlikely
  - ``0x01`` = attack very unlikely
  - ``0x02`` = attack unlikely
  - ``0x03`` = attack possible
  - ``0x04`` = attack likely
  - ``0x05`` = attack very likely
  - ``0x06`` = attack extremely likely
  - ``0xff`` = unknown

- **ToA/ToD** -- Time-of-Arrival minus Time-of-Departure difference
  (signed 16-bit). ``0x8000`` = measurement not available.
- **PCT1/PCT2** -- Phase Correction Terms (I/Q, 12 bits each). Present
  only with certain RTT types.

**Mode 2 -- Phase-Based Ranging (PBR / Tone Exchange)**

Mode 2 exchanges tones for high-precision phase measurement. Multiple
antenna paths can be measured simultaneously.

Fields reported:

- **Antenna Permutation Index** -- Identifies the antenna switching
  pattern used.
- **PCT** (per antenna path) -- Phase Correction Term with I component
  (bits 0--11) and Q component (bits 12--23).
- **Tone Quality Indicator** -- Low nibble:

  - ``0x00`` = high quality
  - ``0x01`` = medium quality
  - ``0x02`` = low quality
  - ``0x03`` = not available

  High nibble (tone extension slot):

  - ``0x00`` = not a tone extension slot
  - ``0x01`` = tone extension slot, tone not expected
  - ``0x02`` = tone extension slot, tone expected

**Mode 3 -- Combined RTT + Tone**

Mode 3 combines Mode 1 and Mode 2 in a single step. The initial fields
match Mode 1 (quality, NADM, RSSI, ToA/ToD, antenna), followed by
Mode 2 tone data.

Result Status Fields
---------------------

Each subevent result event contains status fields that indicate whether
the procedure and subevent completed normally.

**Procedure Done Status**:

- ``0x00`` -- All results complete for this CS procedure
- ``0x01`` -- Partial results, more events will follow
- ``0x0f`` -- All subsequent procedures aborted

**Subevent Done Status**:

- ``0x00`` -- All results complete for this subevent
- ``0x01`` -- Partial results, continuation event will follow
- ``0x0f`` -- Current subevent aborted

**Abort Reason** (packed byte):

Low nibble (procedure abort reason):

- ``0x00`` -- No abort
- ``0x01`` -- Aborted by local Host or remote request
- ``0x02`` -- Channel map has fewer than 15 channels
- ``0x03`` -- Channel map update instant has passed
- ``0x0f`` -- Unspecified reason

High nibble (subevent abort reason):

- ``0x00`` -- No abort
- ``0x01`` -- Aborted by local Host or remote request
- ``0x02`` -- No CS_SYNC (Mode 0) received
- ``0x03`` -- Scheduling conflict or limited resources
- ``0x0f`` -- Unspecified reason

Typical CS Setup Sequence
--------------------------

A complete CS distance measurement session follows this order::

    1. LE CS Read Local Supported Capabilities
    2. LE CS Read Remote Supported Capabilities
           ──► LE CS Read Remote Supported Capabilities Complete
    3. LE CS Security Enable
           ──► LE CS Security Enable Complete
    4. LE CS Set Default Settings
    5. LE CS Read Remote FAE Table          (optional)
           ──► LE CS Read Remote FAE Table Complete
    6. LE CS Set Channel Classification     (optional)
    7. LE CS Create Config
           ──► LE CS Config Complete
    8. LE CS Set Procedure Parameters
    9. LE CS Procedure Enable (enable=1)
           ──► LE CS Procedure Enable Complete
          ... LE CS Subevent Result (repeated)
          ... LE CS Subevent Result Continue (if fragmented)
   10. LE CS Procedure Enable (enable=0)
           ──► LE CS Procedure Enable Complete (state=0)
   11. LE CS Remove Config                  (optional, cleanup)

Steps 1--4 are one-time setup per connection. Steps 7--10 can be
repeated with different configurations or parameters.

CS Test Mode
-------------

CS Test mode allows the controller to run CS procedures without a
remote device, for manufacturing and validation purposes::

    < HCI Command: LE CS Test (0x08|0x0095) plen 34             #400 [hci0]
          Main Mode Type: 0x01
          Sub Mode Type: 0xff
          Main Mode Repetition: 0
          Mode 0 Steps: 3
          Role: Initiator (0x00)
          RTT Type: 0x01
          CS Sync PHY: LE 2M (0x01)
          CS Sync Antenna Selection: 0x01
          Subevent Len: 5000 us
          Subevent Interval: 0
          Max Num Subevents: 1
          Transmit Power Level: 10
          T_IP1 Time: 30 us
          T_IP2 Time: 30 us
          T_FCS Time: 50 us
          T_PM Time: 10 us
          T_SW Time: 0 us
          Tone Antenna Config Selection: 0x01
          SNR Control Initiator: 0x00
          SNR Control Reflector: 0x00
          DRBG Nonce: 0x0000
          Channel Map Repetition: 1
          Override Config: 0x0000

    > HCI Event: Command Complete (0x0e) plen 5                 #401 [hci0]
          LE CS Test (0x08|0x0095) ncmd 1
            Status: Success (0x00)

Results arrive as normal ``LE CS Subevent Result`` events. The test
is terminated with::

    < HCI Command: LE CS Test End (0x08|0x0096) plen 0          #450 [hci0]

    > HCI Event: LE Meta Event (0x3e) plen 1                    #451 [hci0]
          LE CS Test End Complete (0x33)
            Status: Success (0x00)

Common Issues
--------------

**Security Enable fails**
  The connection must be encrypted before CS Security Enable. Check
  that SMP pairing and LE Encrypt have completed. Also verify both
  devices advertise CS support in their LE feature set.

**Config Complete with error**
  The controller may reject a configuration if the requested parameters
  are incompatible with the intersection of both devices' capabilities.
  Check that main mode, PHY, and timing parameters fall within both
  devices' supported ranges.

**Channel map too small**
  CS requires at least 15 channels. If channel classification or
  interference eliminates too many channels, the procedure aborts
  with abort reason ``0x02`` (low nibble).

**No Mode 0 sync received**
  Subevent abort reason ``0x02`` (high nibble) means the Initiator's
  Mode 0 sync packet was not received by the Reflector (or vice versa).
  This indicates an RF issue, scheduling miss, or device out of range.

**Procedure aborted by host**
  Abort reason ``0x01`` in either nibble means the local host or
  remote device requested termination, typically via Procedure Enable
  with enable=0.

**ToA/ToD not available (0x8000)**
  The controller could not compute a valid time measurement for this
  step. Common with weak signals or when the CS Access Address was
  not detected (packet quality = 0x02).

RANGING SERVICE (RAS) / RANGING PROFILE (RAP)
==============================================

The Ranging Service (RAS) is a GATT service that transfers CS
measurement data between devices at the application layer. It
complements the HCI-level CS procedure by providing a standardized
way to exchange, acknowledge, and retrieve ranging results over ATT.
The Ranging Profile (RAP) defines how a device discovers and interacts
with RAS on a remote device.

btmon decodes all RAS characteristics automatically when it sees
ATT operations on the RAS UUIDs.

RAS Service UUID: ``0x185B``

RAS Characteristics
--------------------

.. list-table::
   :header-rows: 1
   :widths: 30 10 20 40

   * - Characteristic
     - UUID
     - Properties
     - Description
   * - RAS Features
     - 0x2C14
     - Read
     - Bitmask of supported RAS capabilities
   * - RAS Real-time Ranging Data
     - 0x2C15
     - Notify, Indicate
     - Streaming ranging results as they are produced
   * - RAS On-demand Ranging Data
     - 0x2C16
     - Notify, Indicate
     - Ranging results retrieved on request
   * - RAS Control Point
     - 0x2C17
     - Write Without Response, Indicate
     - Command interface for data retrieval and filtering
   * - RAS Ranging Data Ready
     - 0x2C18
     - Read, Notify, Indicate
     - Signals that a new ranging dataset is available
   * - RAS Ranging Data Overwritten
     - 0x2C19
     - Read, Notify, Indicate
     - Signals that a stored dataset was overwritten

All characteristics except RAS Features use Client Characteristic
Configuration (CCC) descriptors to enable notifications/indications.
The typical GATT attribute layout uses 18 handles total.

RAS Features
-------------

The RAS Features characteristic is a 4-byte bitmask read by the
client to discover the server's capabilities::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 11               #200 [hci0]
          ATT: Read Response (0x0b) len 4
            Handle: 0x0003
              Features: 0x0000000f
                Real-time Ranging Data (0x00000001)
                Retrieve Lost Ranging Data Segments (0x00000002)
                Abort Operation (0x00000004)
                Filter Ranging Data (0x00000008)

Feature bits:

- **Bit 0** -- Real-time Ranging Data: the server can stream results
  via the Real-time Ranging Data characteristic as CS procedures run.
- **Bit 1** -- Retrieve Lost Ranging Data Segments: the client can
  request retransmission of missing data segments.
- **Bit 2** -- Abort Operation: the client can cancel an in-progress
  data transfer.
- **Bit 3** -- Filter Ranging Data: the client can configure which
  fields are included in ranging data notifications.

RAS Ranging Data Ready
-----------------------

When a CS procedure completes and results are stored, the server
notifies the client that data is available for retrieval::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 9                #250 [hci0]
          ATT: Handle Value Notification (0x1b) len 2
            Handle: 0x000e
              Counter: 42

The counter value identifies the specific ranging dataset. The client
uses this counter in subsequent Control Point commands to request or
acknowledge the data.

RAS Ranging Data Overwritten
------------------------------

If the server's buffer is full and older results are discarded, this
characteristic notifies the client::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 9                #260 [hci0]
          ATT: Handle Value Notification (0x1b) len 2
            Handle: 0x0011
              Overwritten Count: 38

This tells the client that ranging data with counter value 38 (and
possibly earlier) has been overwritten and can no longer be retrieved.

RAS Control Point
------------------

The RAS Control Point is the command interface for managing ranging
data transfers. The client writes commands, and the server responds
via indications on the same characteristic.

**Opcodes:**

.. list-table::
   :header-rows: 1
   :widths: 10 35 55

   * - Opcode
     - Command
     - Description
   * - 0x00
     - Get Ranging Data
     - Request on-demand transfer of a specific dataset
   * - 0x01
     - ACK Ranging Data
     - Acknowledge receipt of a dataset
   * - 0x02
     - Retrieve Lost Ranging Data Segments
     - Re-request specific missing segments
   * - 0x03
     - Abort Operation
     - Cancel an in-progress data transfer
   * - 0x04
     - Set Filter
     - Configure which data fields are included

**Get Ranging Data** -- requests transfer of a stored dataset::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 10               #270 [hci0]
          ATT: Write Command (0x52) len 3
            Handle: 0x000b
              Opcode: Get Ranging Data (0x00)
              Ranging Counter: 0x002a

After this command, the server sends the data as a sequence of
notifications on the On-demand Ranging Data characteristic (0x2C16).

**ACK Ranging Data** -- confirms the client received a complete
dataset, allowing the server to free the buffer::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 10               #290 [hci0]
          ATT: Write Command (0x52) len 3
            Handle: 0x000b
              Opcode: ACK Ranging Data (0x01)
              Ranging Counter: 0x002a

**Retrieve Lost Ranging Data Segments** -- requests retransmission
of specific segments that were missed or corrupted::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 12               #295 [hci0]
          ATT: Write Command (0x52) len 5
            Handle: 0x000b
              Opcode: Retrieve Lost Ranging Data Segments (0x02)
              Ranging Counter: 0x002a
              First Segment Index: 3
              Last Segment Index: 5

A Last Segment Index of ``0xFF`` means "all remaining segments from
the first index onward."

**Abort Operation** -- cancels any in-progress data transfer::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 8                #298 [hci0]
          ATT: Write Command (0x52) len 1
            Handle: 0x000b
              Opcode: Abort Operation (0x03)

**Set Filter** -- configures which fields to include in ranging
data notifications::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 10               #265 [hci0]
          ATT: Write Command (0x52) len 3
            Handle: 0x000b
              Opcode: Set Filter (0x04)
              Filter Configuration: 0x0001
                Mode: 1
                Filter Bit Mask: 0x0000

The filter configuration is a 16-bit value: bits [1:0] select the
filter mode, and bits [15:2] provide a field bitmask.

Ranging Data Format
--------------------

Both Real-time (0x2C15) and On-demand (0x2C16) Ranging Data
characteristics use the same segmented data format. Large datasets
are split across multiple ATT notifications.

**Segmentation Header** (1 byte, present in every notification)::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 30               #275 [hci0]
          ATT: Handle Value Notification (0x1b) len 25
            Handle: 0x0005
              Segmentation Header: 0x01
                First Segment: True
                Last Segment: False
                Segment Index: 0
              Ranging Data Body:
                Ranging Counter: 0x02a
                Configuration ID: 0
                Selected TX Power: 12 dBm
                Antenna Paths Mask: 0x03
                  Antenna Path 1 (0x01)
                  Antenna Path 2 (0x02)
                Subevent #0:
                  Start ACL Connection Event: 1200
                  Frequency Compensation: 150 (0.01 ppm)
                  Ranging Done Status: Partial results (0x1)
                  Subevent Done Status: All results complete (0x0)
                  Ranging Abort Reason: No abort (0x0)
                  Subevent Abort Reason: No abort (0x0)
                  Reference Power Level: -20 dBm
                  Number of Steps Reported: 8
              Remaining Ranging Data Segment: ...

Segmentation header fields:

- **First Segment** (bit 0) -- ``True`` for the first notification of
  a dataset. Only the first segment contains the Ranging Header.
- **Last Segment** (bit 1) -- ``True`` for the final notification.
  When both bits are set, the entire dataset fits in one notification.
- **Segment Index** (bits [7:2]) -- Sequential index for reassembly.

**Ranging Header** (4 bytes, only in first segment):

- **Ranging Counter** (bits [11:0]) -- Matches the counter from the
  Data Ready notification; identifies the CS procedure instance.
- **Configuration ID** (bits [15:12]) -- The CS configuration ID
  (0--3) used for this measurement.
- **Selected TX Power** (1 byte, signed) -- Actual transmit power
  used, in dBm.
- **Antenna Paths Mask** (1 byte) -- Bitmask indicating which antenna
  paths have data: bit 0 = path 1, bit 1 = path 2, etc.

**Subevent Header** (per subevent within the ranging data):

- **Start ACL Connection Event** -- The ACL connection event counter
  at which this CS subevent started.
- **Frequency Compensation** -- Measured frequency offset in 0.01 ppm
  units (signed 16-bit).
- **Ranging Done Status** -- Same codes as HCI subevent results:
  ``0x0`` = complete, ``0x1`` = partial, ``0xF`` = aborted.
- **Subevent Done Status** -- ``0x0`` = complete, ``0xF`` = aborted.
- **Ranging/Subevent Abort Reason** -- Same abort reason codes as HCI:
  ``0x0`` = no abort, ``0x1`` = host/remote request,
  ``0x2`` = channel map / no sync, ``0x3`` = scheduling,
  ``0xF`` = unspecified.
- **Reference Power Level** -- RSSI reference in dBm (signed).
- **Number of Steps Reported** -- Count of CS step results that follow.

The step data following the subevent header uses the same mode-specific
format as HCI CS Subevent Result events (Mode 0--3), described in the
`CS Step Modes`_ section above.

Continuation segments contain only the Segmentation Header followed
by raw ranging data bytes that are reassembled with the previous
segments.

Typical RAS Data Flow
----------------------

A complete RAS session for on-demand data retrieval::

    1. Client discovers RAS (UUID 0x185B) via GATT primary service discovery
    2. Client reads RAS Features (0x2C14) to learn capabilities
    3. Client enables CCC notifications on:
         - RAS Ranging Data Ready (0x2C18)
         - RAS Ranging Data Overwritten (0x2C19)
         - RAS On-demand Ranging Data (0x2C16) or
           RAS Real-time Ranging Data (0x2C15)
    4. CS procedure runs (HCI level)
    5. Server notifies Ranging Data Ready with counter=N
    6. Client writes Control Point: Get Ranging Data (counter=N)
    7. Server sends On-demand Ranging Data notifications (segmented)
    8. Client writes Control Point: ACK Ranging Data (counter=N)

For real-time streaming, step 6 is skipped -- the server pushes
data on the Real-time Ranging Data characteristic (0x2C15) as each
CS subevent completes, using the same segmented format.

If segments are lost (e.g., due to ATT MTU limitations or missed
notifications), the client uses Retrieve Lost Ranging Data Segments
to request retransmission of specific segment indices.

RAS Common Issues
------------------

**Features read returns 0x00000000**
  The server does not support any optional RAS features. Only basic
  on-demand data retrieval via Control Point is available.

**Ranging Data Ready not received**
  Check that CCC notifications are enabled on handle 0x2C18. Also
  verify the CS procedure actually completed -- if the procedure was
  aborted, no Data Ready notification is sent.

**Segmentation reassembly errors**
  Verify that Segment Index values are sequential and that the First
  Segment flag is set on the initial notification. A missing segment
  triggers the Retrieve Lost Segments mechanism if the server supports
  it (Features bit 1).

**Data Overwritten before retrieval**
  The server has limited buffer space. If the client does not retrieve
  and ACK data promptly, older datasets are overwritten. The Data
  Overwritten notification indicates the counter value of the lost data.

**Control Point write rejected**
  The connection must be encrypted. RAS Control Point requires write
  permission with encryption (``WRITE_ENCRYPT``). Verify that SMP
  pairing has completed.

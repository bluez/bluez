.. This file is included by btmon-classic-audio.rst.

A2DP: Advanced Audio Distribution
-----------------------------------

A2DP uses AVDTP (Audio/Video Distribution Transport Protocol) over
L2CAP to negotiate codec parameters and stream high-quality audio.
btmon fully decodes AVDTP signaling, codec capabilities, and AVRCP
remote control messages.

AVDTP Signaling Channel
~~~~~~~~~~~~~~~~~~~~~~~~

A2DP begins with an L2CAP connection on PSM 25 (0x0019). The first
L2CAP connection on this PSM carries AVDTP signaling; a second
connection on the same PSM carries media transport data::

    < ACL Data TX: Handle 1 flags 0x00 dlen 12
          L2CAP: Connection Request (0x02) ident 1 len 4
            PSM: 25 (0x0019)
            Source CID: 64

    > ACL Data RX: Handle 1 flags 0x02 dlen 16
          L2CAP: Connection Response (0x03) ident 1 len 8
            Destination CID: 64
            Source CID: 64
            Result: Connection successful (0x0000)
            Status: No further information available (0x0000)

After L2CAP configuration completes, AVDTP signaling begins on this
channel.

Stream Endpoint Discovery
~~~~~~~~~~~~~~~~~~~~~~~~~~

The initiator discovers available Stream Endpoints (SEPs) on the
remote device::

    < ACL Data TX: Handle 1 flags 0x00 dlen 6
          Channel: 64 len 2 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Discover (0x01) Command (0x00) type 0x00 label 0 nosp 0

    > ACL Data RX: Handle 1 flags 0x02 dlen 10
          Channel: 64 len 6 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Discover (0x01) Response Accept (0x02) type 0x00 label 0 nosp 0
              ACP SEID: 1
                Media Type: Audio (0x00)
                SEP Type: SNK (0x01)
                In use: No

Each SEP has a SEID (Stream Endpoint Identifier), media type, and
role (Source or Sink). ``In use: Yes`` means the endpoint is already
streaming.

Codec Capability Discovery
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After discovering SEIDs, the initiator queries each endpoint's
capabilities::

    < ACL Data TX: Handle 1 flags 0x00 dlen 7
          Channel: 64 len 3 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Get All Capabilities (0x0c) Command (0x00) type 0x00 label 1 nosp 0
              ACP SEID: 1

    > ACL Data RX: Handle 1 flags 0x02 dlen 30
          Channel: 64 len 26 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Get All Capabilities (0x0c) Response Accept (0x02) type 0x00 label 1 nosp 0
              Service Category: Media Transport (0x01)
              Service Category: Media Codec (0x07)
                Media Type: Audio (0x00)
                Media Codec: SBC (0x00)
                  Frequency: 0xf0
                    16000
                    32000
                    44100
                    48000
                  Channel Mode: 0x0f
                    Mono
                    Dual Channel
                    Stereo
                    Joint Stereo
                  Block Length: 0xf0
                    4
                    8
                    12
                    16
                  Subbands: 0x0c
                    4
                    8
                  Allocation Method: 0x03
                    SNR
                    Loudness
                  Minimum Bitpool: 2
                  Maximum Bitpool: 53
              Service Category: Content Protection (0x04)
                Content Protection Type: SCMS-T (0x0002)
              Service Category: Delay Reporting (0x08)

Capability responses list all supported values as bitmasks. Key
service categories:

- **Media Transport** (0x01) -- Always present, indicates the endpoint
  supports a media transport channel
- **Media Codec** (0x07) -- Codec type and supported parameters
- **Content Protection** (0x04) -- Copy protection (SCMS-T or DTCP)
- **Delay Reporting** (0x08) -- Endpoint supports delay reporting

Supported Codecs
~~~~~~~~~~~~~~~~~

btmon decodes several A2DP codecs. Each has a different parameter
format.

**SBC** (mandatory A2DP codec)::

    Media Codec: SBC (0x00)
      Frequency: 44100 (0x20)
      Channel Mode: Joint Stereo (0x01)
      Block Length: 16 (0x10)
      Subbands: 8 (0x04)
      Allocation Method: Loudness (0x01)
      Minimum Bitpool: 2
      Maximum Bitpool: 53

**AAC** (MPEG-2,4)::

    Media Codec: MPEG-2,4 AAC (0x02)
      Object Type: MPEG-4 AAC LC (0x40)
      Frequency: 44100 (0x0100)
      Channels: 2 (0x04)
      Bitrate: 256000bps
      VBR: No

**aptX** (Qualcomm, vendor-specific)::

    Media Codec: Non-A2DP (0xff)
      Vendor ID: Qualcomm Technologies International, Ltd. (APT) (0x0000004f)
      Vendor Specific Codec ID: aptX (0x0001)
        Frequency: 44100 (0x20)
        Channel Mode: Stereo (0x02)

**aptX HD** (Qualcomm, vendor-specific)::

    Media Codec: Non-A2DP (0xff)
      Vendor ID: Qualcomm Technologies, Inc. (0x000000d7)
      Vendor Specific Codec ID: aptX HD (0x0024)
        Frequency: 44100 (0x20)
        Channel Mode: Stereo (0x02)

**LDAC** (Sony, vendor-specific)::

    Media Codec: Non-A2DP (0xff)
      Vendor ID: Sony Corporation (0x0000012d)
      Vendor Specific Codec ID: LDAC (0x00aa)

Vendor codecs appear as ``Non-A2DP (0xff)`` with decoded Vendor ID
and Codec ID. Capability responses list all supported values as
bitmasks; configuration responses show the single selected value.

Stream Configuration
~~~~~~~~~~~~~~~~~~~~~

After selecting a codec and parameters, the initiator sends Set
Configuration::

    < ACL Data TX: Handle 1 flags 0x00 dlen 20
          Channel: 64 len 16 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Set Configuration (0x03) Command (0x00) type 0x00 label 2 nosp 0
              ACP SEID: 1
              INT SEID: 1
              Service Category: Media Transport (0x01)
              Service Category: Media Codec (0x07)
                Media Type: Audio (0x00)
                Media Codec: SBC (0x00)
                  Frequency: 44100 (0x20)
                  Channel Mode: Joint Stereo (0x01)
                  Block Length: 16 (0x10)
                  Subbands: 8 (0x04)
                  Allocation Method: Loudness (0x01)
                  Minimum Bitpool: 2
                  Maximum Bitpool: 53

    > ACL Data RX: Handle 1 flags 0x02 dlen 6
          Channel: 64 len 2 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Set Configuration (0x03) Response Accept (0x02) type 0x00 label 2 nosp 0

Configuration responses show single selected values instead of
bitmask lists. ``ACP SEID`` is the remote endpoint, ``INT SEID`` is
the local endpoint.

If configuration is rejected::

    > ACL Data RX: Handle 1 flags 0x02 dlen 8
          Channel: 64 len 4 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Set Configuration (0x03) Response Reject (0x03) type 0x00 label 2 nosp 0
              Service Category: Media Codec (0x07)
              Error code: Unsupported Configuration (0x29)

Common AVDTP error codes:

.. list-table::
   :header-rows: 1
   :widths: 10 30 60

   * - Code
     - Name
     - Meaning
   * - 0x01
     - Bad Header Format
     - Malformed AVDTP header
   * - 0x11
     - Bad ACP SEID
     - Unknown endpoint ID
   * - 0x12
     - SEP In Use
     - Endpoint already streaming
   * - 0x13
     - SEP Not In Use
     - Endpoint not configured
   * - 0x29
     - Unsupported Configuration
     - Requested parameters not supported
   * - 0x31
     - Bad State
     - Command not valid in current state

Open and Start
~~~~~~~~~~~~~~~

After configuration, the stream is opened and then started::

    < ACL Data TX: Handle 1 flags 0x00 dlen 7
          Channel: 64 len 3 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Open (0x06) Command (0x00) type 0x00 label 3 nosp 0
              ACP SEID: 1

    > ACL Data RX: Handle 1 flags 0x02 dlen 6
          Channel: 64 len 2 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Open (0x06) Response Accept (0x02) type 0x00 label 3 nosp 0

After Open succeeds, a **second L2CAP connection** on PSM 25 is
established for the media transport channel. Then Start begins
streaming::

    < ACL Data TX: Handle 1 flags 0x00 dlen 7
          Channel: 64 len 3 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Start (0x07) Command (0x00) type 0x00 label 4 nosp 0
              ACP SEID: 1

    > ACL Data RX: Handle 1 flags 0x02 dlen 6
          Channel: 64 len 2 [PSM 25 mode Basic (0x00)] {chan 0}
            AVDTP: Start (0x07) Response Accept (0x02) type 0x00 label 4 nosp 0

Media Data
~~~~~~~~~~~

After Start, encoded audio flows on the media transport channel
(second L2CAP connection on PSM 25). btmon does **not** decode media
packet contents by default -- media data is suppressed. Only the
L2CAP channel header is visible when the ``--show-a2dp-stream``
filter is enabled, with the payload shown as a raw hex dump.

The AVDTP state machine visible in the trace:

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - State
     - Triggered By
     - Description
   * - Idle
     - Initial / Abort response
     - No stream configured
   * - Configured
     - Set Configuration accept
     - Codec and parameters selected
   * - Open
     - Open accept / Suspend accept
     - Transport channel ready, not streaming
   * - Streaming
     - Start accept
     - Audio data flowing
   * - Closing
     - Close command sent
     - Tearing down stream
   * - Aborting
     - Abort command sent
     - Forced teardown

Suspend, Close, and Abort
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Suspend** pauses streaming without tearing down the transport::

    AVDTP: Suspend (0x09) Command (0x00) type 0x00 label 5 nosp 0
      ACP SEID: 1
    AVDTP: Suspend (0x09) Response Accept (0x02) type 0x00 label 5 nosp 0

**Close** tears down the stream (returns to Idle)::

    AVDTP: Close (0x08) Command (0x00) type 0x00 label 6 nosp 0
      ACP SEID: 1
    AVDTP: Close (0x08) Response Accept (0x02) type 0x00 label 6 nosp 0

**Abort** forces immediate teardown::

    AVDTP: Abort (0x0a) Command (0x00) type 0x00 label 7 nosp 0
      ACP SEID: 1
    AVDTP: Abort (0x0a) Response Accept (0x02) type 0x00 label 7 nosp 0

Delay Reporting
~~~~~~~~~~~~~~~~

When the sink supports delay reporting, it sends a Delay Report to
inform the source of its rendering delay::

    AVDTP: Delay Report (0x0d) Command (0x00) type 0x00 label 8 nosp 0
      ACP SEID: 1
      Delay: 15.0ms
    AVDTP: Delay Report (0x0d) Response Accept (0x02) type 0x00 label 8 nosp 0

AVRCP Remote Control
~~~~~~~~~~~~~~~~~~~~~

AVRCP (Audio/Video Remote Control Profile) uses L2CAP PSM 23
(control) and PSM 27 (browsing). btmon decodes AVCTP framing and
AVRCP PDUs.

**Volume control**::

    < ACL Data TX: Handle 1 flags 0x00 dlen 17
          Channel: 66 len 13 [PSM 23 mode Basic (0x00)] {chan 2}
            AVCTP Control: Response: type 0x00 label 0 PID 0x110e
              AV/C: Accepted: address 0x48 opcode 0x00
                Subunit: Panel
                Opcode: Vendor Dependent
                Company ID: 0x001958
                  AVRCP: SetAbsoluteVolume pt Single len 0x0001
                    Volume: 50.39% (64/127)

**Playback status**::

    AVRCP: GetPlayStatus pt Single len 0x0009
      SongLength: 0x00038270 (230000 milliseconds)
      SongPosition: 0x00000000 (0 milliseconds)
      PlayStatus: 0x01 (PLAYING)

**Track metadata** (GetElementAttributes response)::

    AVRCP: GetElementAttributes pt Single len 0x0050
      AttributeCount: 0x02
      Attribute: 0x00000001 (Title)
      CharsetID: 0x006a (UTF-8)
      AttributeValueLength: 0x000c
      AttributeValue: My Song Name
      Attribute: 0x00000002 (Artist)
      CharsetID: 0x006a (UTF-8)
      AttributeValueLength: 0x000b
      AttributeValue: The Artist

**Passthrough commands** (play, pause, skip)::

    AVCTP Control: Command: type 0x00 label 1 PID 0x110e
      AV/C: Control: address 0x48 opcode 0x7c
        Subunit: Panel
        Opcode: Passthrough
        Operation: 0x44 (PLAY Pressed)
        Length: 0x00

**Event notifications** (volume change, track change)::

    AVRCP: RegisterNotification pt Single len 0x0005
      EventID: 0x0d (EVENT_VOLUME_CHANGED)
      Volume: 50.39% (64/127)

Automating A2DP Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Identify A2DP activity**::

    grep -n "AVDTP:\|Media Codec:" output.txt

**Track AVDTP state transitions**::

    grep -n "AVDTP:.*Command\|AVDTP:.*Response" output.txt

**Check codec negotiation** (what was selected)::

    grep -n "Set Configuration\|Media Codec:" output.txt

**Verify stream is flowing** -- look for Start accept followed by
media data::

    grep -n "AVDTP: Start\|PSM 25.*chan 1" output.txt

**Detect codec mismatch** -- look for Set Configuration reject::

    grep -n "Response Reject\|Error code:" output.txt

**Track AVRCP volume and playback**::

    grep -n "SetAbsoluteVolume\|Volume:\|GetPlayStatus\|PlayStatus:" output.txt

**Full A2DP diagnosis pattern**:

1. Find L2CAP Connection Request for PSM 25 -- confirms AVDTP channel
   setup
2. Find Discover response -- shows available endpoints and whether any
   are already in use
3. Find Get All Capabilities response -- verify codec support overlap
4. Find Set Configuration -- verify agreed codec and parameters
5. Find Open and Start -- confirm stream setup succeeded
6. Find second L2CAP connection on PSM 25 -- media transport channel
7. On failure, check for Response Reject with error code
8. If audio cuts out, look for Suspend or Close, or check for ACL
   disconnection

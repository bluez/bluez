.. This file is included by btmon.rst.

ADVERTISING AND SCANNING
==========================

btmon decodes advertising data structures automatically. Advertising
and scan response data appears in HCI LE advertising report events
and in advertising command parameters.

Advertising Reports
--------------------

When the controller reports received advertisements::

    > HCI Event: LE Meta Event (0x3e) plen 43              #120 [hci0] 0.500003
          LE Extended Advertising Report (0x0d)
            Event type: 0x0013
              Props: 0x0013
                Connectable
                Scannable
                Complete
            Address type: Random (0x01)
            Address: 00:11:22:33:44:55
            Primary PHY: LE 1M
            Secondary PHY: LE 2M
            SID: 0x01
            TX power: 0 dBm
            RSSI: -55 dBm (0xc9)
            Data length: 18

The advertising data (AD) structures within the report are decoded
as typed fields:

**Common AD types btmon decodes**:

.. list-table::
   :header-rows: 1
   :widths: 10 30 60

   * - AD Type
     - Name
     - Example in btmon output
   * - 0x01
     - Flags
     - ``Flags: 0x06`` with decoded bits (LE General Discoverable,
       BR/EDR Not Supported)
   * - 0x02/0x03
     - Incomplete/Complete 16-bit UUIDs
     - ``16-bit Service UUIDs (complete): 2 entries``
       followed by UUID list
   * - 0x06/0x07
     - Incomplete/Complete 128-bit UUIDs
     - ``128-bit Service UUIDs (complete): 1 entry``
   * - 0x08/0x09
     - Shortened/Complete Local Name
     - ``Name (complete): MyDevice``
   * - 0x0a
     - TX Power Level
     - ``TX power: 4 dBm``
   * - 0x16
     - Service Data (16-bit UUID)
     - ``Service Data (UUID 0x184e): ...`` with protocol-specific
       decoding
   * - 0xff
     - Manufacturer Specific Data
     - ``Company: Apple, Inc. (76)`` followed by hex data

**Typical advertising report**::

    > HCI Event: LE Meta Event (0x3e) plen 38              #120 [hci0] 0.500003
          LE Extended Advertising Report (0x0d)
            Address: 00:11:22:33:44:55
            RSSI: -62 dBm (0xc2)
            Flags: 0x06
              LE General Discoverable Mode
              BR/EDR Not Supported
            Name (complete): LE-Audio-Left
            16-bit Service UUIDs (complete): 3 entries
              Published Audio Capabilities (0x1850)
              Audio Stream Control (0x184e)
              Common Audio (0x1853)
            Service Data (UUID 0x1852): 01a2b3
            Appearance: Earbud (0x0941)

Extended Advertising
---------------------

Modern controllers use extended advertising commands and events.
The setup sequence in btmon::

    < HCI Command: LE Set Extended Adv Parameters (0x08|0x0036) plen 25  #50 [hci0] 0.100003
          Handle: 0x01
          Properties: 0x0000
          Min advertising interval: 160.000 msec (0x0100)
          Max advertising interval: 160.000 msec (0x0100)
          Channel map: 37, 38, 39 (0x07)
          Own address type: Random (0x01)
          Peer address type: Public (0x00)
          PHY: LE 1M, LE 2M
          SID: 0x01
          TX power: 7 dBm

    < HCI Command: LE Set Extended Adv Data (0x08|0x0037) plen 35  #52 [hci0] 0.101003
          Handle: 0x01
          Operation: Complete extended advertising data (0x01)
          Fragment preference: No fragmentation (0x01)

Periodic Advertising (LE Audio)
--------------------------------

LE Audio broadcast sources use periodic advertising to transmit
BASE announcements containing codec configuration::

    > HCI Event: LE Meta Event (0x3e) plen 80              #200 [hci0] 0.500003
          LE Periodic Advertising Report (0x0f)
            Sync handle: 0x0001
            TX power: 0 dBm
            RSSI: -45 dBm
            CTE Type: No CTE (0xff)
            Data status: Complete (0x00)
            Data length: 60
            Service Data: Basic Audio Announcement (0x1851)
              Presentation Delay: 40000 us
              Number of Subgroups: 1
                Codec: LC3 (0x06)
                  Sampling Frequency: 48000 Hz
                  Frame Duration: 10 ms
                  Frame Length: 120

Automating Advertising Analysis
---------------------------------

**Find all advertising reports** (devices seen)::

    grep -n "Advertising Report\|Address:.*RSSI:" output.txt

**Extract device names**::

    grep -n "Name (complete):\|Name (short):" output.txt

**Find LE Audio devices** (by service UUIDs in advertising)::

    grep -n "Audio Stream Control\|Published Audio Capabilities\|Common Audio\|Basic Audio Announcement\|Broadcast Audio" output.txt

**Track advertising setup** (local device configuring advertising)::

    grep -n "Set Extended Adv\|Set Advertising\|Set Scan Response\|Adv Enable" output.txt

**Find periodic advertising** (broadcast audio)::

    grep -n "Periodic Advertising\|PA Sync\|PA Report\|Basic Audio Announcement\|Broadcast.*Announcement" output.txt

**Identify devices by appearance**::

    grep -n "Appearance:" output.txt

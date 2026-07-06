================
bluetoothctl-cs
================

--------------------------
Channel Sounding Submenu
--------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: June 2026
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [cs.commands]

This submenu controls Bluetooth Channel Sounding (CS) distance measurement
using the **org.bluez.ChannelSounding1(5)** D-Bus interface. It allows
starting and stopping measurements and inspecting the current parameter
state and active session identifier.

CS parameters can be overridden on any **start** call using inline
``param=value`` arguments. Overrides are applied to the local parameter
state before the measurement is started, so **show** reflects them
immediately after.


Channel Sounding Commands
=========================

start
-----

Sets one or more CS parameters and starts a distance measurement on the
connected device. All configuration is sent to the daemon in a single
**StartMeasurement** call. On success the device path is printed to
the console. Multiple simultaneous sessions across different devices are
supported; each is tracked independently.

Calling **start** on a device that already has an active measurement
returns an error without starting a second session on the same device.

Positional arguments are optional and must appear before any
``param=value`` pairs:

- ``duration_secs`` — auto-stop timeout in seconds; ``0`` (default) means
  no timeout.

Any additional argument of the form ``param=value`` overrides the named
parameter for this call and for all subsequent calls. Array-valued
parameters (``channel_map``, ``min_sub_event_len``, ``max_sub_event_len``)
use colon-separated hex bytes with no ``0x`` prefix.

:Usage: **> start [dev_addr [duration_secs]] [param=value ...]**
:Uses: **org.bluez.ChannelSounding1(5)** method **StartMeasurement**
:[dev_addr]: Bluetooth address of the target device (optional; uses the
             only available CS-capable device when omitted)
:[duration_secs]: Seconds before auto-stop (optional, default 0 = no timeout)
:[param=value]: One or more ``param=value`` overrides (optional)

**Settable parameters:**

.. list-table::
   :header-rows: 1
   :widths: 35 15 50

   * - Parameter
     - Default
     - Description
   * - ``role``
     - ``0x03``
     - ``0x01`` Initiator, ``0x02`` Reflector, ``0x03`` Both
   * - ``cs_sync_ant_sel``
     - ``0xFF``
     - CS sync antenna selection (0xFE/0xFF reserved)
   * - ``max_tx_power``
     - ``20``
     - Max TX power in dBm (signed, range −127 to +20)
   * - ``config_id``
     - ``0``
     - CS configuration identifier
   * - ``main_mode_type``
     - ``1``
     - ``1`` Mode 1 (RTT), ``2`` Mode 2 (PBR), ``3`` Both
   * - ``sub_mode_type``
     - ``0xFF``
     - Sub-mode within main mode; ``0xFF`` = unused
   * - ``main_mode_min_steps``
     - ``2``
     - Min CS main mode steps per subevent
   * - ``main_mode_max_steps``
     - ``3``
     - Max CS main mode steps per subevent
   * - ``main_mode_repetition``
     - ``1``
     - Times main mode steps are repeated in a subevent
   * - ``mode0_steps``
     - ``2``
     - CS Mode 0 steps at the beginning of each subevent
   * - ``rtt_types``
     - ``0``
     - RTT measurement types bitmask
   * - ``cs_sync_phy``
     - ``0x01``
     - PHY for CS sync: ``0x01`` LE 1M, ``0x02`` LE 2M
   * - ``channel_map``
     - ``FC:FF:7F:FC:FF:FF:FF:FF:FF:1F``
     - 10-byte channel map bitmap (colon-separated hex)
   * - ``channel_map_repetition``
     - ``1``
     - Consecutive repetitions of the channel map
   * - ``channel_selection_type``
     - ``0``
     - CS channel selection algorithm
   * - ``channel_shape``
     - ``0``
     - Shape used in channel selection algorithm
   * - ``channel_jump``
     - ``2``
     - Channel jump size
   * - ``companion_signal_enable``
     - ``0``
     - ``1`` to transmit companion signal, ``0`` to disable
   * - ``max_procedure_duration``
     - ``1600``
     - Maximum duration of one CS measurement procedure
   * - ``min_period_between_procedures``
     - ``30``
     - Minimum time between consecutive procedures
   * - ``max_period_between_procedures``
     - ``150``
     - Maximum time between consecutive procedures
   * - ``max_procedure_count``
     - ``0``
     - Max number of procedures; ``0`` = no limit
   * - ``min_sub_event_len``
     - ``00:20:00``
     - Min CS subevent length, 3-byte LE (colon-separated hex)
   * - ``max_sub_event_len``
     - ``03:20:00``
     - Max CS subevent length, 3-byte LE (colon-separated hex)
   * - ``tone_antenna_config_selection``
     - ``0x07``
     - Antenna config for CS tone exchanges
   * - ``phy``
     - ``0x01``
     - PHY for CS procedures: ``0x01`` LE 1M, ``0x02`` LE 2M
   * - ``tx_power_delta``
     - ``0x80``
     - Remote vs local TX power delta; ``0x80`` = not applicable
   * - ``preferred_peer_antenna``
     - ``0x03``
     - Preferred antenna for the peer device
   * - ``snr_control_initiator``
     - ``0xFF``
     - SNR control for initiator; ``0xFF`` = no preference
   * - ``snr_control_reflector``
     - ``0xFF``
     - SNR control for reflector; ``0xFF`` = no preference

:Example Start with all defaults, no timeout:
	| **> start**
:Example Start on a specific device:
	| **> start AA:BB:CC:DD:EE:FF**
:Example Start on a specific device with 10-second auto-stop:
	| **> start AA:BB:CC:DD:EE:FF 10**
:Example Start with 10-second auto-stop (single device, address omitted):
	| **> start 0 10**
:Example Start with no timeout, explicit:
	| **> start**
:Example Start with 5-minute auto-stop:
	| **> start AA:BB:CC:DD:EE:FF 300**
:Example Start as Initiator only:
	| **> start role=0x01**
:Example Start as Reflector only:
	| **> start role=0x02**
:Example Start as both Initiator and Reflector:
	| **> start role=0x03**
:Example Start with Mode 2 (PBR) main mode:
	| **> start main_mode_type=2**
:Example Start with both RTT and PBR modes:
	| **> start main_mode_type=3**
:Example Start with LE 2M PHY for CS procedures:
	| **> start phy=0x02**
:Example Start with LE 2M PHY for both CS sync and procedures:
	| **> start cs_sync_phy=0x02 phy=0x02**
:Example Start with reduced TX power (10 dBm):
	| **> start max_tx_power=10**
:Example Start with companion signal enabled:
	| **> start companion_signal_enable=1**
:Example Start with a procedure limit of 100:
	| **> start max_procedure_count=100**
:Example Start with high SNR preference on both roles:
	| **> start snr_control_initiator=0x01 snr_control_reflector=0x01**
:Example Start with custom channel map (all enabled):
	| **> start channel_map=FF:FF:FF:FF:FF:FF:FF:FF:FF:FF**
:Example Start Initiator, Mode 2, LE 2M, 30-second timeout:
	| **> start AA:BB:CC:DD:EE:FF 30 role=0x01 main_mode_type=2 phy=0x02 cs_sync_phy=0x02**
:Example Start both roles, Mode 1, no limit, custom step counts:
	| **> start role=0x03 main_mode_type=1 main_mode_min_steps=4 main_mode_max_steps=8**
:Example Start on a device, Reflector, 60-second timeout:
	| **> start AA:BB:CC:DD:EE:FF 60 role=0x02**

defset
------

Sets the CS default settings (``role``, ``cs_sync_ant_sel``,
``max_tx_power``) on the connected device without starting a
measurement. This is required for the Reflector role: a Reflector
never calls **start** because it waits passively for the remote
Initiator, so **defset** is the only way to push these settings to
the daemon before the remote side initiates the procedure.

Any ``param=value`` arguments update the local parameter state and
are immediately sent to the daemon via **SetDefaultSettings**.
Omitting all arguments sends the current local values unchanged.

:Usage: **> defset [param=value ...]**
:Uses: **org.bluez.ChannelSounding1(5)** method **SetDefaultSettings**
:[param=value]: One or more of ``role``, ``cs_sync_ant_sel``,
               ``max_tx_power`` (optional)
:Example Configure as Reflector:
	| **> defset role=0x02**
:Example Configure as Both with reduced TX power:
	| **> defset role=0x03 max_tx_power=10**
:Example Apply current local values without changing them:
	| **> defset**

stop
----

Stops an active CS distance measurement. When only one measurement is
running the device address may be omitted. When multiple measurements
are active the address is required to identify which one to stop.

:Usage: **> stop [dev_addr]**
:Uses: **org.bluez.ChannelSounding1(5)** method **StopMeasurement**
:[dev_addr]: Bluetooth address of the device to stop (optional when
             only one session is active; required otherwise)
:Example Stop the only active measurement:
	| **> stop**
:Example Stop a specific device when multiple are active:
	| **> stop AA:BB:CC:DD:EE:FF**
:Example Stop a second device:
	| **> stop 11:22:33:44:55:66**

show
----

Displays all active measurements (device path for each) and the full
set of CS parameter values that will be used on the next **start** call.
When no measurements are active, ``none`` is shown.

The parameter output is divided into three sections:

- **Default Settings** — role, CS sync antenna selection, max TX power.
- **CS Config Params** — per-procedure configuration fields including
  mode type, step counts, PHY, and channel map.
- **CS Frequency Params** — procedure scheduling fields including
  duration, period, subevent lengths, and SNR control.

:Usage: **> show**
:Example Show active session and all CS parameters:
	| **> show**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

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

Each CS parameter has its own **cs.<param>** set command (see the
**CS Parameter Commands** section below). Overrides are applied to
the local parameter state immediately, so **show** reflects them
right away; **start** always uses whatever values are currently set.


Channel Sounding Commands
=========================

start
-----

Starts a distance measurement on the connected device using the
currently set CS parameters (see the **cs.<param>** commands below).
All configuration is sent to the daemon in a single **StartMeasurement**
call. On success the device path is printed to the console. Multiple
simultaneous sessions across different devices are supported; each is
tracked independently.

Calling **start** on a device that already has an active measurement
returns an error without starting a second session on the same device.

For Initiator role (or Both), the mandatory parameters are the
positional ``dev_addr`` and ``duration_secs``; every ``cs.<param>``
command below is optional configuration with a usable default.

If ``role`` is set to Reflector (``0x02``, via **cs.role**), **start**
does not begin measuring distance: a Reflector never initiates a CS
procedure. It only pushes the current parameters to the daemon and
arms the device to respond once the remote Initiator starts one; the
call still succeeds. When the remote side starts or stops a procedure,
the console prints ``Measurement started``/``Measurement stopped`` for
that device — use **show** or watch the ``Active`` property to see
the same transition. In this role the only parameters that are
required or have any effect are ``role``, ``sync_ant_sel`` and
``max_tx_power``; every other **cs.<param>** command below is
accepted but unused.

Positional arguments are optional:

- ``dev_addr`` — Bluetooth address of the target device; uses the only
  available CS-capable device when omitted.
- ``duration_secs`` — auto-stop timeout in seconds; ``0`` (default) means
  no timeout.

:Usage: **> start [dev_addr] [duration_secs]**
:Uses: **org.bluez.ChannelSounding1(5)** method **StartMeasurement**
:[dev_addr]: Bluetooth address of the target device (optional; uses the
             only available CS-capable device when omitted)
:[duration_secs]: Seconds before auto-stop (optional, default 0 = no timeout)

:Example Start with all defaults, no timeout:
	| **> start**
:Example Start on a specific device:
	| **> start AA:BB:CC:DD:EE:FF**
:Example Start on a specific device with 10-second auto-stop:
	| **> start AA:BB:CC:DD:EE:FF 10**
:Example Start with 10-second auto-stop (single device, address omitted):
	| **> start 0 10**
:Example Start with 5-minute auto-stop:
	| **> start AA:BB:CC:DD:EE:FF 300**

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

CS Parameter Commands
======================

Each CS parameter is set with its own command, of the form
``cs.<param> <value>``. Entering a param command with no value shows
its current setting. Overrides apply to the local parameter state
immediately, so **show** reflects them right away; **start** always
uses whatever values are currently set. Array-valued parameters
(``channel_map``, ``min_sub_event_len``, ``max_sub_event_len``) take
colon-separated hex bytes with no ``0x`` prefix.

:Usage: **> <param> [value]**

role
----

Get/set the CS role.

:Usage: **> role [0x01|0x02|0x03]**
:[0x01|0x02|0x03]: ``0x01`` Initiator, ``0x02`` Reflector, ``0x03`` Both
                   (optional, shows current if omitted; default ``0x03``)
:Example Show current role:
	| **> role**
:Example Set role to Initiator only:
	| **> role 0x01**
:Example Set role to Reflector only (does not measure):
	| **> role 0x02**
:Example Set role to both Initiator and Reflector:
	| **> role 0x03**

sync_ant_sel
------------

Get/set the CS sync antenna selection.

:Usage: **> sync_ant_sel [value]**
:[value]: CS sync antenna selection; ``0xFE``/``0xFF`` reserved
          (optional, shows current if omitted; default ``0xFF``)
:Example Show current antenna selection:
	| **> sync_ant_sel**
:Example Select antenna 1:
	| **> sync_ant_sel 0x01**

max_tx_power
------------

Get/set the maximum TX power.

:Usage: **> max_tx_power [dBm]**
:[dBm]: Max TX power in dBm, signed (optional, shows current if
        omitted; range −127 to +20; default ``20``)
:Example Show current max TX power:
	| **> max_tx_power**
:Example Reduce max TX power to 10 dBm:
	| **> max_tx_power 10**

config_id
---------

Get/set the CS configuration identifier.

:Usage: **> config_id [value]**
:[value]: CS configuration identifier (optional, shows current if
          omitted; default ``0``)
:Example Show current config id:
	| **> config_id**
:Example Set config id to 1:
	| **> config_id 1**

main_mode_type
--------------

Get/set the CS main mode type.

:Usage: **> main_mode_type [1|2|3]**
:[1|2|3]: ``1`` Mode 1 (RTT), ``2`` Mode 2 (PBR), ``3`` Both (optional,
          shows current if omitted; default ``1``)
:Example Show current main mode type:
	| **> main_mode_type**
:Example Set main mode to Mode 2 (PBR):
	| **> main_mode_type 2**
:Example Set main mode to both RTT and PBR:
	| **> main_mode_type 3**

sub_mode_type
-------------

Get/set the CS sub-mode type within the main mode.

:Usage: **> sub_mode_type [value]**
:[value]: Sub-mode within main mode; ``0xFF`` = unused (optional,
          shows current if omitted; default ``0xFF``)
:Example Show current sub-mode type:
	| **> sub_mode_type**
:Example Set sub-mode type to 0x01:
	| **> sub_mode_type 0x01**

main_mode_min_steps
--------------------

Get/set the minimum CS main mode steps per subevent.

:Usage: **> main_mode_min_steps [value]**
:[value]: Min CS main mode steps per subevent (optional, shows
          current if omitted; default ``2``)
:Example Show current value:
	| **> main_mode_min_steps**
:Example Set minimum steps to 4:
	| **> main_mode_min_steps 4**

main_mode_max_steps
--------------------

Get/set the maximum CS main mode steps per subevent.

:Usage: **> main_mode_max_steps [value]**
:[value]: Max CS main mode steps per subevent (optional, shows
          current if omitted; default ``3``)
:Example Show current value:
	| **> main_mode_max_steps**
:Example Set maximum steps to 8:
	| **> main_mode_max_steps 8**

main_mode_repetition
---------------------

Get/set how many times main mode steps are repeated in a subevent.

:Usage: **> main_mode_repetition [value]**
:[value]: Repetition count (optional, shows current if omitted;
          default ``1``)
:Example Show current value:
	| **> main_mode_repetition**
:Example Repeat main mode steps twice:
	| **> main_mode_repetition 2**

mode0_steps
-----------

Get/set the number of CS Mode 0 steps at the beginning of each
subevent.

:Usage: **> mode0_steps [value]**
:[value]: CS Mode 0 step count (optional, shows current if omitted;
          default ``2``)
:Example Show current value:
	| **> mode0_steps**
:Example Set Mode 0 steps to 3:
	| **> mode0_steps 3**

rtt_types
---------

Get/set the RTT measurement types bitmask.

:Usage: **> rtt_types [value]**
:[value]: RTT measurement types bitmask (optional, shows current if
          omitted; default ``0``)
:Example Show current value:
	| **> rtt_types**
:Example Set RTT types bitmask:
	| **> rtt_types 0x01**

sync_phy
--------

Get/set the PHY used for CS sync.

:Usage: **> sync_phy [0x01|0x02]**
:[0x01|0x02]: ``0x01`` LE 1M, ``0x02`` LE 2M (optional, shows current
              if omitted; default ``0x01``)
:Example Show current sync PHY:
	| **> sync_phy**
:Example Set CS sync PHY to LE 2M:
	| **> sync_phy 0x02**

channel_map
-----------

Get/set the 10-byte CS channel map bitmap.

:Usage: **> channel_map [b0:b1:...:b9]**
:[b0:b1:...:b9]: 10 colon-separated hex bytes (optional, shows current
                 if omitted; default ``FC:FF:7F:FC:FF:FF:FF:FF:FF:1F``)
:Example Show current channel map:
	| **> channel_map**
:Example Set a custom channel map (all enabled):
	| **> channel_map FF:FF:FF:FF:FF:FF:FF:FF:FF:FF**

channel_map_repetition
-----------------------

Get/set the number of consecutive repetitions of the channel map.

:Usage: **> channel_map_repetition [value]**
:[value]: Repetition count (optional, shows current if omitted;
          default ``1``)
:Example Show current value:
	| **> channel_map_repetition**
:Example Repeat the channel map 3 times:
	| **> channel_map_repetition 3**

channel_selection_type
-----------------------

Get/set the CS channel selection algorithm.

:Usage: **> channel_selection_type [value]**
:[value]: Channel selection algorithm (optional, shows current if
          omitted; default ``0``)
:Example Show current value:
	| **> channel_selection_type**
:Example Select algorithm 1:
	| **> channel_selection_type 1**

channel_shape
-------------

Get/set the shape used in the channel selection algorithm.

:Usage: **> channel_shape [value]**
:[value]: Channel shape (optional, shows current if omitted; default
          ``0``)
:Example Show current value:
	| **> channel_shape**
:Example Set channel shape to 1:
	| **> channel_shape 1**

channel_jump
------------

Get/set the channel jump size.

:Usage: **> channel_jump [value]**
:[value]: Channel jump size (optional, shows current if omitted;
          default ``2``)
:Example Show current value:
	| **> channel_jump**
:Example Set channel jump to 4:
	| **> channel_jump 4**

companion_signal_enable
------------------------

Get/set whether the companion signal is transmitted.

:Usage: **> companion_signal_enable [0|1]**
:[0|1]: ``1`` to transmit companion signal, ``0`` to disable (optional,
        shows current if omitted; default ``0``)
:Example Show current value:
	| **> companion_signal_enable**
:Example Enable the companion signal:
	| **> companion_signal_enable 1**

max_procedure_duration
-----------------------

Get/set the maximum duration of one CS measurement procedure.

:Usage: **> max_procedure_duration [value]**
:[value]: Maximum procedure duration (optional, shows current if
          omitted; default ``1600``)
:Example Show current value:
	| **> max_procedure_duration**
:Example Set max procedure duration to 800:
	| **> max_procedure_duration 800**

min_period_between_procedures
-------------------------------

Get/set the minimum time between consecutive procedures.

:Usage: **> min_period_between_procedures [value]**
:[value]: Minimum period (optional, shows current if omitted; default
          ``30``)
:Example Show current value:
	| **> min_period_between_procedures**
:Example Set minimum period to 50:
	| **> min_period_between_procedures 50**

max_period_between_procedures
-------------------------------

Get/set the maximum time between consecutive procedures.

:Usage: **> max_period_between_procedures [value]**
:[value]: Maximum period (optional, shows current if omitted; default
          ``150``)
:Example Show current value:
	| **> max_period_between_procedures**
:Example Set maximum period to 200:
	| **> max_period_between_procedures 200**

max_procedure_count
--------------------

Get/set the maximum number of procedures.

:Usage: **> max_procedure_count [value]**
:[value]: Max procedure count; ``0`` = no limit (optional, shows
          current if omitted; default ``0``)
:Example Show current value:
	| **> max_procedure_count**
:Example Limit the procedure count to 100:
	| **> max_procedure_count 100**

min_sub_event_len
------------------

Get/set the minimum CS subevent length.

:Usage: **> min_sub_event_len [b0:b1:b2]**
:[b0:b1:b2]: 3-byte LE value, colon-separated hex (optional, shows
             current if omitted; default ``00:20:00``)
:Example Show current value:
	| **> min_sub_event_len**
:Example Set minimum subevent length:
	| **> min_sub_event_len 00:10:00**

max_sub_event_len
------------------

Get/set the maximum CS subevent length.

:Usage: **> max_sub_event_len [b0:b1:b2]**
:[b0:b1:b2]: 3-byte LE value, colon-separated hex (optional, shows
             current if omitted; default ``03:20:00``)
:Example Show current value:
	| **> max_sub_event_len**
:Example Set maximum subevent length:
	| **> max_sub_event_len 04:20:00**

tone_antenna_config_selection
-------------------------------

Get/set the antenna configuration for CS tone exchanges.

:Usage: **> tone_antenna_config_selection [value]**
:[value]: Antenna config selection (optional, shows current if
          omitted; default ``0x07``)
:Example Show current value:
	| **> tone_antenna_config_selection**
:Example Set antenna config to 0x01:
	| **> tone_antenna_config_selection 0x01**

phy
---

Get/set the PHY used for CS procedures.

:Usage: **> phy [0x01|0x02]**
:[0x01|0x02]: ``0x01`` LE 1M, ``0x02`` LE 2M (optional, shows current
              if omitted; default ``0x01``)
:Example Show current procedure PHY:
	| **> phy**
:Example Set CS procedure PHY to LE 2M:
	| **> phy 0x02**

tx_power_delta
--------------

Get/set the remote vs local TX power delta.

:Usage: **> tx_power_delta [value]**
:[value]: TX power delta; ``0x80`` = not applicable (optional, shows
          current if omitted; default ``0x80``)
:Example Show current value:
	| **> tx_power_delta**
:Example Set TX power delta to 0x05:
	| **> tx_power_delta 0x05**

preferred_peer_antenna
-----------------------

Get/set the preferred antenna for the peer device.

:Usage: **> preferred_peer_antenna [value]**
:[value]: Preferred peer antenna (optional, shows current if omitted;
          default ``0x03``)
:Example Show current value:
	| **> preferred_peer_antenna**
:Example Prefer antenna 1 on the peer:
	| **> preferred_peer_antenna 0x01**

snr_control_initiator
----------------------

Get/set the SNR control for the initiator.

:Usage: **> snr_control_initiator [value]**
:[value]: SNR control; ``0xFF`` = no preference (optional, shows
          current if omitted; default ``0xFF``)
:Example Show current value:
	| **> snr_control_initiator**
:Example Prefer high SNR on the initiator:
	| **> snr_control_initiator 0x01**

snr_control_reflector
----------------------

Get/set the SNR control for the reflector.

:Usage: **> snr_control_reflector [value]**
:[value]: SNR control; ``0xFF`` = no preference (optional, shows
          current if omitted; default ``0xFF``)
:Example Show current value:
	| **> snr_control_reflector**
:Example Prefer high SNR on the reflector:
	| **> snr_control_reflector 0x01**
:Example Prefer high SNR on both roles:
	| **> snr_control_initiator 0x01**
	| **> snr_control_reflector 0x01**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

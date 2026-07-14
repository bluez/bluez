==========================
org.bluez.ChannelSounding1
==========================

----------------------------------------------
BlueZ D-Bus Channel Sounding API documentation
----------------------------------------------

:Version: BlueZ
:Date: June 2026
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.ChannelSounding1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX
:Used by:	**bluetoothctl(1)**, **bluetoothctl-cs(1)**

Methods
-------

void StartMeasurement(dict params)
``````````````````````````````````

Starts a Channel Sounding distance measurement procedure on the connected
device. All configuration is supplied in a single ``a{sv}`` dictionary.
Any key that is omitted retains its current value in the daemon.

The device to measure is identified by the D-Bus object path on which
this method is called
(``[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX``).
Only one measurement per device object may be active at a time. Calling
**StartMeasurement** while a session is already active returns
``org.bluez.Error.InProgress``.

Supported dictionary keys:

:uint32 duration_secs (Default: 0):

	Duration in seconds before the measurement is stopped
	automatically. A value of 0 disables the automatic timeout.

:byte role (Default: 0x03):

	CS role to use for the measurement.

	Possible values:

	:0x01: Initiator
	:0x02: Reflector
	:0x03: Both (Initiator and Reflector)

:byte cs_sync_ant_sel (Default: 0xFF):

	CS sync antenna selection. Values 0xFE and 0xFF are reserved
	by the Bluetooth specification.

:byte max_tx_power (Default: 0x14):

	Maximum TX power in dBm, treated as a signed value. Valid
	range is -127 to +20 dBm.

:byte config_id:

	CS configuration identifier.

:byte main_mode_type:

	Main CS mode used in the procedure.

:byte sub_mode_type:

	Sub-mode within the main mode. Set to 0xFF when unused.

:byte main_mode_min_steps:

	Minimum number of CS main mode steps per CS subevent.

:byte main_mode_max_steps:

	Maximum number of CS main mode steps per CS subevent.

:byte main_mode_repetition:

	Number of times the main mode steps are repeated in a
	subevent.

:byte mode0_steps:

	Number of CS Mode 0 steps at the beginning of each subevent.

:byte rtt_types:

	Round Trip Time measurement types for the configuration.

:byte cs_sync_phy:

	PHY used for CS sync packets.

	Possible values:

	:0x01: LE 1M PHY
	:0x02: LE 2M PHY

:array{byte} channel_map:

	10-byte channel map bitmap. Must be exactly 10 bytes.

:byte channel_map_repetition:

	Number of consecutive repetitions of the channel map.

:byte channel_selection_type:

	Algorithm used for CS channel selection.

:byte channel_shape:

	Shape used in the channel selection algorithm.

:byte channel_jump:

	Channel jump size used in the channel selection algorithm.

:byte companion_signal_enable:

	Set to 1 to transmit a companion signal alongside the CS
	tone, 0 to disable.

:uint16 max_procedure_duration:

	Maximum duration of a single CS measurement procedure.

:uint16 min_period_between_procedures:

	Minimum time between consecutive CS measurement procedures.

:uint16 max_period_between_procedures:

	Maximum time between consecutive CS measurement procedures.

:uint16 max_procedure_count:

	Maximum number of CS measurement procedures to run.
	A value of 0 means no limit.

:array{byte} min_sub_event_len:

	Minimum CS subevent length as a 3-byte little-endian value.
	Must be exactly 3 bytes.

:array{byte} max_sub_event_len:

	Maximum CS subevent length as a 3-byte little-endian value.
	Must be exactly 3 bytes.

:byte tone_antenna_config_selection:

	Antenna configuration used for CS tone exchanges.

:byte phy:

	PHY used during CS procedures.

	Possible values:

	:0x01: LE 1M PHY
	:0x02: LE 2M PHY

:byte tx_power_delta:

	Difference between remote and local TX power during CS
	procedures. 0x80 indicates not applicable.

:byte preferred_peer_antenna:

	Preferred antenna to be used by the peer device.

:byte snr_control_initiator:

	SNR control setting for the initiator role.
	0xFF indicates no preference.

:byte snr_control_reflector:

	SNR control setting for the reflector role.
	0xFF indicates no preference.

Possible errors:

:org.bluez.Error.InProgress:
:org.bluez.Error.InvalidArgs:
:org.freedesktop.DBus.Error.Failed:

Examples:

:bluetoothctl set role then start:
	| [cs] > start AA:BB:CC:DD:EE:FF role=0x01 main_mode_type=2
:bluetoothctl start with defaults:
	| [cs] > start [dev_addr [duration_secs]]

void SetDefaultSettings(dict params)
`````````````````````````````````````

Sets the CS default settings for this device without starting a
measurement. This method is intended for the Reflector role, where
the device waits passively for the remote Initiator to begin the
procedure and therefore never calls **StartMeasurement**. It allows
the application to configure ``role``, ``cs_sync_ant_sel``, and
``max_tx_power`` ahead of time so they are in effect when the
controller processes the remote CS configuration.
Need this to set default settings in Reflector role.

Supported dictionary keys:

:byte role (Default: 0x03):

	CS role to use for the measurement.

	Possible values:

	:0x01: Initiator
	:0x02: Reflector
	:0x03: Both (Initiator and Reflector)

:byte cs_sync_ant_sel (Default: 0xFF):

	CS sync antenna selection. Values 0xFE and 0xFF are reserved
	by the Bluetooth specification.

:byte max_tx_power (Default: 0x14):

	Maximum TX power in dBm, treated as a signed value. Valid
	range is -127 to +20 dBm.

Possible errors:

:org.bluez.Error.InvalidArgs:
:org.freedesktop.DBus.Error.Failed:

Examples:

:bluetoothctl configure as Reflector:
	| [cs] > defset role=0x02

void StopMeasurement(void)
``````````````````````````

Stops the active Channel Sounding distance measurement on this device.
The device is identified by the D-Bus object path on which this method
is called — no session identifier is required.

Raises ``org.bluez.Error.NotConnected`` if no measurement is active.

Possible errors:

:org.bluez.Error.NotConnected:
:org.freedesktop.DBus.Error.Failed:

In **bluetoothctl(1)**, the device address argument may be omitted only
when a single measurement is active; it is required when multiple
measurements are active.

Examples:

:bluetoothctl stop the only active measurement:
	| [cs] > stop
:bluetoothctl stop a specific device when multiple are active:
	| [cs] > stop AA:BB:CC:DD:EE:FF

Properties
----------

boolean Active [readonly]
`````````````````````````

Indicates whether a CS distance measurement procedure is currently
active on this device.

Set to ``true`` when a procedure starts — either because the local
Initiator called **StartMeasurement** successfully, or because the
remote Initiator enabled a CS procedure on the local Reflector.

Set to ``false`` when the procedure stops for any reason: the local
application called **StopMeasurement**, the measurement duration timer
expired, or the ACL connection was dropped.

This property emits ``PropertiesChanged`` on every transition so that
clients can track measurement state without polling.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

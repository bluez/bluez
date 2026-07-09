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

When ``role`` is Reflector (``0x02``), this method does not start a CS
distance measurement: a Reflector never initiates a procedure locally,
so it cannot start one via this call. Instead, all given configuration
is applied and stored so the controller is ready to respond once a
remote Initiator begins a procedure, and the method returns success
without arming a local measurement session. The ``Active`` property
only transitions to ``true`` when a remote-initiated procedure
actually starts, which may happen well after this method returns (or
not at all, if the remote never initiates one).

For Initiator role (or Both), ``duration_secs`` and the device object
path are the parameters that matter to start a measurement; every
other key below is optional configuration with a usable default. For
Reflector role, only ``role``, ``cs_sync_ant_sel`` and ``max_tx_power``
are required or have any effect — the remaining keys are accepted but
otherwise unused, since no local procedure is armed.

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
	| [cs] > role 0x01
	| [cs] > main_mode_type 2
	| [cs] > start AA:BB:CC:DD:EE:FF
:bluetoothctl start with defaults:
	| [cs] > start [dev_addr [duration_secs]]
:bluetoothctl configure as Reflector (applies settings, does not start a measurement):
	| [cs] > role 0x02
	| [cs] > start

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

Signals
-------

void ProcedureData(dict data)
``````````````````````````````

Emitted when a Channel Sounding measurement procedure completes on this
device, carrying the raw CS procedure results as reported by the
controller. Consumers such as an external ranging estimation daemon
subscribe to this signal to compute distance estimates.

:dict data:

	:int32 procedureCounter:

		Procedure counter value from the controller.

	:int32 procedureSequence:

		Sequence number of this procedure.

	:byte initiatorSelectedTxPower:

		TX power selected by the Initiator, treated as a signed
		value.

	:byte reflectorSelectedTxPower:

		TX power selected by the Reflector, treated as a signed
		value.

	:uint32 initiatorSubeventCount:

		Number of subevent results reported by the Initiator.

	:array{dict} initiatorSubeventResults:

		Present only when ``initiatorSubeventCount`` is greater
		than 0. One entry per Initiator subevent, each with the
		fields described in `Subevent Result`_ below.

	:byte initiatorProcedureAbortReason:

		Reason the Initiator's procedure was aborted, 0 if not
		aborted.

	:uint32 reflectorSubeventCount:

		Number of subevent results reported by the Reflector.

	:array{dict} reflectorSubeventResults:

		Present only when ``reflectorSubeventCount`` is greater
		than 0. One entry per Reflector subevent, each with the
		fields described in `Subevent Result`_ below.

	:byte reflectorProcedureAbortReason:

		Reason the Reflector's procedure was aborted, 0 if not
		aborted.

	:dict procedureEnableConfig:

		:byte toneAntennaConfigSelection:

			Antenna configuration used for CS tone exchanges.

		:uint32 subeventLenUs:

			Subevent length in microseconds.

		:byte subeventsPerEvent:

			Number of subevents per event.

		:uint32 subeventInterval:

			Interval between subevents.

		:uint32 eventInterval:

			Interval between events.

		:uint32 procedureInterval:

			Interval between procedures.

		:uint32 procedureCount:

			Number of procedures configured.

		:uint32 maxProcedureLen:

			Maximum procedure length.

	:dict csConfigParam:

		:byte modeType:

			Main CS mode used in the procedure.

		:byte subModeType:

			Sub-mode within the main mode.

		:byte rttType:

			Round Trip Time measurement type.

		:array{byte} channelMap:

			10-byte channel map bitmap.

		:byte minMainModeSteps:
		:byte maxMainModeSteps:
		:byte mainModeRepetition:
		:byte mode0Steps:

		:byte role:

			CS role in effect for the procedure (Initiator,
			Reflector, or Both).

		:byte csSyncPhyType:

			PHY used for CS sync packets.

		:byte channelSelectionType:
		:byte ch3cShapeType:
		:byte ch3cJump:
		:byte channelMapRepetition:
		:byte tIp1TimeUs:
		:byte tIp2TimeUs:
		:byte tFcsTimeUs:
		:byte tPmTimeUs:
		:byte tSwTimeUsSupportedByLocal:
		:byte tSwTimeUsSupportedByRemote:

		:uint32 bleConnInterval:

			BLE connection interval in effect during the
			procedure.

Subevent Result
~~~~~~~~~~~~~~~~

Each element of ``initiatorSubeventResults`` and
``reflectorSubeventResults`` is a dict with the following fields:

:int32 startAclConnEvtCounter:

	ACL connection event counter at the start of the subevent.

:int32 freqComp:

	Frequency compensation value.

:byte refPwrLvl:

	Reference power level, treated as a signed value.

:byte numAntPaths:

	Number of antenna paths used.

:byte subeventAbortReason:

	Reason the subevent was aborted, 0 if not aborted.

:uint64 timestampNanos:

	Timestamp of the subevent result, in nanoseconds.

:uint32 numSteps:

	Number of steps reported in this subevent.

:array{dict} stepData:

	One entry per step. Each entry has:

	:byte stepMode:

		CS step mode (0-3).

	:byte stepChannel:

		Channel used for the step.

	:dict modeZeroData:

		Present when ``stepMode`` is 0.

		:byte packetQuality:
		:byte packetRssiDbm:
		:byte packetAntenna:

		:int32 initiatorMeasuredFreqOffset:

			Frequency offset measured by the Initiator.

	:dict modeOneData:

		Present when ``stepMode`` is 1.

		:byte packetQuality:
		:byte packetNadm:
		:byte packetRssiDbm:

		:int32 toaTodInitiator:

			Time of Arrival / Time of Departure at the
			Initiator.

		:int32 todToaReflector:

			Time of Departure / Time of Arrival at the
			Reflector.

		:byte packetAntenna:

		:array{int32} packetPct1:

			In-phase/quadrature sample pair, as
			``[i_sample, q_sample]``.

		:array{int32} packetPct2:

			In-phase/quadrature sample pair, as
			``[i_sample, q_sample]``.

	:dict modeTwoData:

		Present when ``stepMode`` is 2.

		:byte antennaPermutationIndex:

		:array{int32} tonePctIQSamples:

			Interleaved in-phase/quadrature tone samples, as
			``[i_sample, q_sample, ...]`` — one pair per
			antenna path.

		:array{byte} toneQualityIndicators:

			One quality indicator byte per antenna path.

	:dict modeThreeData:

		Present when ``stepMode`` is 3. Contains the combined
		fields of both **modeOneData** and **modeTwoData**.

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

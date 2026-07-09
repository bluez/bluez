==================================
org.bluez.ChannelSoundingRanging1
==================================

------------------------------------------------------
BlueZ D-Bus Channel Sounding Ranging API documentation
------------------------------------------------------

:Version: BlueZ
:Date: July 2026
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.ChannelSoundingRanging1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX
:Used by:	**bluetoothctl(1)**, **bluetoothctl-cs(1)**

This interface reports distance estimates derived from Channel Sounding
measurement data. It is emitted by an external ranging estimation daemon
(**cs-range-daemon**) which subscribes to the ``ProcedureData`` signal on
**org.bluez.ChannelSounding1** for every device object, feeds the parsed
CS procedure data into a distance-estimation library, and re-publishes
the resulting estimate as **RangeEstimate** on the same device object
path. It carries no methods or properties of its own.

Signals
-------

void RangeEstimate(double distance_m, byte confidence)
````````````````````````````````````````````````````````

Emitted whenever a new distance estimate has been computed for the
device identified by the object path on which the signal is raised.

:double distance_m:

	Estimated distance to the remote device, in meters.

:byte confidence:

	Confidence level of the estimate, expressed as a percentage
	(0-100).

Clients that started a Channel Sounding measurement via
**org.bluez.ChannelSounding1.StartMeasurement** and wish to receive
range estimates should watch for this signal on the same device object
path.

Examples:

:bluetoothctl distance output while a measurement is active:
	| [CS] Distance: 1.234 m  Confidence: 87%

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

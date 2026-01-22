============================
org.bluez.ThermometerWatcher
============================

--------------------------------------------------------
BlueZ D-Bus Health Thermometer Watcher API documentation
--------------------------------------------------------

:Version: BlueZ
:Date: July 2011
:Author: Santiago Carot-Nemesio <sancane@gmail.com>
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	unique name
:Interface:	org.bluez.ThermometerWatcher1
:Object path:	freely definable

Methods
-------

void MeasurementReceived(dict measurement)
``````````````````````````````````````````

This callback gets called when a measurement has been
scanned in the thermometer.

Possible measurement values:

:int16 Exponent:
:int32 Mantissa:

	Exponent and Mantissa values as extracted from float value defined by
	IEEE-11073-20601.

	Measurement value is calculated as
	(Mantissa) * (10^Exponent)

	For special cases Exponent is
	set to 0 and Mantissa is set to
	one of following values:

.. csv-table::
        :header: "Value", "Description"
        :widths: auto

        +(2^23 - 1), NaN (invalid or missing data)
        -(2^23), NRes
        +(2^23 - 2), +Infinity
        -(2^23 - 2), -Infinity

:string Unit:

	Possible values: "celsius" or
			"fahrenheit"

:uint64 Time (optional):

	Time of measurement, if
	supported by device.
	Expressed in seconds since epoch.

:string Type (optional):

	Only present if measurement type
	is known.

	Possible values: "armpit", "body",
		"ear", "finger", "intestines",
		"mouth", "rectum", "toe",
		"tympanum"

:string Measurement:

	Possible values: "final" or "intermediate"


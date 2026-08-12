======================
org.bluez.CSDistance1
======================

-----------------------------------------
BlueZ D-Bus CSDistance API documentation
-----------------------------------------

:Version: BlueZ
:Date: July 2026
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.CSDistance1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX

Properties
----------

double DistanceMeters [readonly]
`````````````````````````````````

Estimated distance to the remote device, in meters, as last computed
from Channel Sounding measurement data.

Providers from **org.bluez.CSDistanceProvider(5)** compute
this value from the raw procedure data reported via the **ProcedureData**
signal on **org.bluez.ChannelSounding1(5)**, and report it back to
**bluetoothd(8)** for reflection here.

This property emits ``PropertiesChanged`` whenever a new estimate is
reported.

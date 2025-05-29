=========================
org.bluez.BatteryProvider
=========================

---------------------------------------------
BlueZ D-Bus BatteryProvider API documentation
---------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	<client D-Bus address>
:Interface:	org.bluez.BatteryProvider1
:Object path:	{provider_root}/{unique battery object path}

Properties
----------

Objects provided on this interface contain the same properties as
**org.bluez.Battery(5)** interface. Additionally, this interface needs to have
the Device property indicating the object path of the device this battery
provides.

object Device [readonly]
````````````````````````

The object path of the device that has this battery.

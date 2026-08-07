=========================================
org.bluez.ChannelSoundingDistanceProvider
=========================================

-------------------------------------------------------------
BlueZ D-Bus ChannelSoundingDistanceProvider API documentation
-------------------------------------------------------------

:Version: BlueZ
:Date: July 2026
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	<client D-Bus address>
:Interface:	org.bluez.ChannelSoundingDistanceProvider1
:Object path:	{provider_root}/{unique distance object path}

Properties
----------

Objects provided on this interface contain the same properties as
**org.bluez.ChannelSounding1(5)** interface. Additionally, this interface
needs to have the Device property indicating the object path of the
device this distance estimate provides.

object Device [readonly]
````````````````````````

The object path of the device that this distance estimate applies to.

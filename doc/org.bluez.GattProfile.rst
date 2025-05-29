=====================
org.bluez.GattProfile
=====================

-----------------------------------------
BlueZ D-Bus GattProfile API documentation
-----------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

Local profile (GATT client) instance. By registering this type of object
an application effectively indicates support for a specific GATT profile
and requests automatic connections to be established to devices
supporting it.

Interface
=========

:Service:	<application dependent>
:Interface:	org.bluez.GattProfile1
:Object path:	<application dependent>

Methods
-------

void Release()
``````````````

This method gets called when **bluetoothd(8)** unregisters the profile. The
profile can use it to do cleanup tasks.

There is no need to unregister the profile, because when this method gets called
it has already been unregistered.

Properties
----------

array{string} UUIDs [read-only]
```````````````````````````````

128-bit GATT service UUIDs to auto connect.

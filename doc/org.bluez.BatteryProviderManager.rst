================================
org.bluez.BatteryProviderManager
================================

----------------------------------------------------
BlueZ D-Bus BatteryProviderManager API documentation
----------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
============

A battery provider starts by registering itself as a battery provider with the
**RegisterBatteryProvider()** method passing an object path as the provider ID.
Then, it can start exposing **org.bluez.BatteryProvider(5)** objects having the
path starting with the given provider ID. It can also remove objects at any
time.
The objects and their properties exposed by battery providers will be reflected
on **org.bluez.Battery(5)** interface.

**bluetoothd(8)** will stop monitoring these exposed and removed objects after
UnregisterBatteryProvider is called for that provider ID.

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.BatteryProviderManager1
:Object path:	/org/bluez/{hci0,hci1,...}

Methods
-------

void RegisterBatteryProvider(object provider)
`````````````````````````````````````````````

Registers a battery provider. A registered battery provider can then expose
objects with **org.bluez.BatteryProvider(5)** interface.

void UnregisterBatteryProvider(object provider)
```````````````````````````````````````````````

Unregisters a battery provider previously registered with
**RegisterBatteryProvider()**. After unregistration, the
**org.bluez.BatteryProvider(5)** objects provided by this client are ignored by
**bluetoothd(8)**.

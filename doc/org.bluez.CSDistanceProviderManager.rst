====================================
org.bluez.CSDistanceProviderManager
====================================

--------------------------------------------------------
BlueZ D-Bus CSDistanceProviderManager API documentation
--------------------------------------------------------

:Version: BlueZ
:Date: July 2026
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

A Channel Sounding distance provider starts by registering itself as a
distance provider with the **RegisterDistanceProvider()** method passing
an object path as the provider ID. Then, it can start exposing
**org.bluez.CSDistanceProvider(5)** objects having the path
starting with the given provider ID. It can also remove objects at any
time.
The objects and their properties exposed by distance providers will be
reflected on the matching **org.bluez.CSDistance1(5)**
interface.

**bluetoothd(8)** will stop monitoring these exposed and removed objects
after UnregisterDistanceProvider is called for that provider ID.

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.CSDistanceProviderManager1
:Object path:	/org/bluez/{hci0,hci1,...}

Methods
-------

void RegisterDistanceProvider(object provider)
``````````````````````````````````````````````

Registers a distance provider. A registered distance provider can then
expose objects with **org.bluez.CSDistanceProvider(5)**
interface.

void UnregisterDistanceProvider(object provider)
````````````````````````````````````````````````

Unregisters a distance provider previously registered with
**RegisterDistanceProvider()**. After unregistration, the
**org.bluez.CSDistanceProvider(5)** objects provided by this
client are ignored by **bluetoothd(8)**.

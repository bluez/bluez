===========================
org.bluez.RangingProvider1
===========================

-----------------------------------------------
BlueZ D-Bus RangingProvider API documentation
-----------------------------------------------

:Version: BlueZ
:Date: August 2026
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	<client D-Bus address>
:Interface:	org.bluez.RangingProvider1
:Object path:	{provider_root}/{unique ranging object path}

Properties
----------

object Device [readonly]
```````````````````````````

The object path of the device that this distance estimate applies to.

uint32 Distance [readonly, optional]
````````````````````````````````````

Estimated distance to the device identified by **Device**, in
millimeters. May be absent when the object is first exposed and set
once the provider has computed an initial estimate; **bluetoothd(8)**
watches for it via ``PropertiesChanged``.

Error handling
==============

This interface has no methods; it is implemented by the ranging daemon
and consumed by **bluetoothd(8)** via **org.freedesktop.DBus.ObjectManager**
and property-change watches, so there is no D-Bus method call to return
an error from. Instead, **bluetoothd(8)** validates each exposed object
and silently ignores (logging a warning) any that fail validation:

- An object path outside the provider's registered root path is
  ignored.
- An object missing the **Device** property, or whose **Device**
  property is not an object path, is ignored.
- An object whose **Device** does not match an existing, non-temporary
  device is ignored.
- A **Distance** value (initial or updated) that is not a uint32 is
  ignored; the previously reported value, if any, is left unchanged.
- If the provider has already exposed a **RangingProvider** object
  for a given device (e.g. a stale or duplicate object), any further
  object it exposes for that same device is ignored — each device may
  only be represented by one **RangingProvider** object at a time.
  Note that only one provider may be registered per adapter at all
  (see **org.bluez.RangingProviderManager1(5)**), so this situation can
  only arise from the same provider re-exposing a device, not from a
  second, distinct provider racing for it.

Removing an ignored object, or fixing it and re-adding it, is treated
the same as any other **InterfacesAdded**/**InterfacesRemoved** event.

Overview
========

A ranging daemon exposes one **RangingProvider** object per device it
is tracking, under the root path it registered with
**org.bluez.RangingProviderManager1(5)**::

    Ranging daemon                                     bluetoothd
         |                                                    |
         | export {provider_root}/dev_XX (RangingProvider)    |
         | { Device: <device path> }                          |
         |--------------------------------------------------->|
         |                                                    | reflects a
         |                                                    | Ranging object
         |                                                    | on the device path
         |                                                    |
         | Distance = D                                       |
         | PropertiesChanged("Distance", D)                   |
         |--------------------------------------------------->|
         |                                                    | updates
         |                                                    | Ranging.Distance
         |                                                    | and notifies clients
         |                                                    | (see org.bluez.Ranging1(5))

Removing the object (or disconnecting from D-Bus) causes
**bluetoothd(8)** to remove the matching **org.bluez.Ranging1(5)**
interface from the device.

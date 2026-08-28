======================================
org.bluez.RangingProviderManager1
======================================

------------------------------------------------------
BlueZ D-Bus RangingProviderManager API documentation
------------------------------------------------------

:Version: BlueZ
:Date: August 2026
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

A ranging provider starts by registering itself with the
**RegisterRangingProvider()** method, passing an object path as the
provider ID. Then, it can start exposing **org.bluez.RangingProvider1(5)**
objects having a path starting with the given provider ID. It can also
remove objects at any time.
The objects and their properties exposed by ranging providers will be
reflected on the matching **org.bluez.Ranging1(5)** interface.

**bluetoothd(8)** will stop monitoring these exposed and removed objects
after **UnregisterRangingProvider()** is called for that provider ID.

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.RangingProviderManager1
:Object path:	/org/bluez/{hci0,hci1,...}

Methods
-------

void RegisterRangingProvider(object provider)
`````````````````````````````````````````````````

Registers a ranging provider. A registered ranging provider can then
expose objects with **org.bluez.RangingProvider1(5)** interface.

Only one ranging provider may be registered per adapter at a time: the
object path above is per-adapter, so a provider registered on hci0 does
not block registration on hci1. If a provider is already registered on
that adapter, this call fails with **org.bluez.Error.AlreadyExists**,
regardless of which client registered first.

Possible errors:

- org.bluez.Error.InvalidArguments
- org.bluez.Error.AlreadyExists
- org.bluez.Error.Failed

void UnregisterRangingProvider(object provider)
```````````````````````````````````````````````````

Unregisters a ranging provider previously registered with
**RegisterRangingProvider()**. After unregistration, the
**org.bluez.RangingProvider1(5)** objects provided by this client are
ignored by **bluetoothd(8)**.

Fails if no provider is registered at the given path, or if the caller
is not the D-Bus client that registered it.

Possible errors:

- org.bluez.Error.InvalidArguments
- org.bluez.Error.DoesNotExist

Overview
========

::

    Ranging daemon                                 bluetoothd
         |                                               |
         | RegisterRangingProvider(provider_root)        |
         |---------------------------------------------->|
         |                    (ok)                       |
         |<----------------------------------------------|
         |                                               |
         |   ... expose/update RangingProvider objects   |
         |       under provider_root (see                |
         |       org.bluez.RangingProvider1(5)) ...      |
         |                                               |
         | UnregisterRangingProvider(provider_root)      |
         |---------------------------------------------->|
         |                    (ok)                       |
         |<----------------------------------------------|

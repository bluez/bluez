==================
org.bluez.Ranging1
==================

--------------------------------------
BlueZ D-Bus Ranging API documentation
--------------------------------------

:Version: BlueZ
:Date: August 2026
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Ranging1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX

Properties
----------

uint32 Distance [readonly]
``````````````````````````

Estimated distance to the remote device, in millimeters, as last
reported by a ranging provider.

Providers implementing **org.bluez.RangingProvider1(5)**, registered via
**org.bluez.RangingProviderManager1(5)**, compute this value and report
it back to **bluetoothd(8)** for reflection here. For Channel Sounding
based ranging, a provider derives the distance from the raw procedure
data reported via the **ProcedureData** signal on
**org.bluez.ChannelSounding1(5)**, but this interface itself carries no
assumption about the underlying ranging technology.

This property emits ``PropertiesChanged`` whenever a new estimate is
reported.

This property does not exist until a ranging provider has reported at
least one estimate for this device; reading it before then (e.g. via
**org.freedesktop.DBus.Properties.Get**) fails with
**org.freedesktop.DBus.Error.UnknownProperty**, and it is omitted from
**GetAll**/**GetManagedObjects** results. Once a provider unregisters
or stops providing ranging for this device, this whole
**Ranging** interface — and therefore the **Distance** property — is
removed (**InterfacesRemoved**); it does not linger with a stale value.

Overview
========

**Ranging** is the read side of a three-party pattern ::

    Ranging daemon -- RangingProvider --> BlueZ -- Ranging --> Desktop clients
                       (registered via RangingProviderManager)

Sequence for a single distance update, once a provider is registered
(see **org.bluez.RangingProviderManager1(5)**) and has exposed a
**org.bluez.RangingProvider1(5)** object for the device (see
**org.bluez.RangingProvider1(5)**)::

    Ranging daemon                    bluetoothd                  Desktop client
         |                                 |                             |
         | Distance = D on its             |                             |
         | RangingProvider object          |                             |
         |                                 |                             |
         | PropertiesChanged(              |                             |
         |   RangingProvider,              |                             |
         |   "Distance", D)                |                             |
         |-------------------------------->|                             |
         |                                 | updates Ranging on the      |
         |                                 | device path with D          |
         |                                 |                             |
         |                                 | PropertiesChanged(          |
         |                                 |   Ranging,                  |
         |                                 |   "Distance", D)            |
         |                                 |---------------------------->|

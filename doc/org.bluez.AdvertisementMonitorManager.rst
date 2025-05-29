=====================================
org.bluez.AdvertisementMonitorManager
=====================================

---------------------------------------------------------
BlueZ D-Bus AdvertisementMonitorManager API documentation
---------------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.AdvertisementMonitorManager1 [experimental]
:Object path:	/org/bluez/{hci0,hci1,...}

Methods
-------

void RegisterMonitor(object application)
````````````````````````````````````````

Registers the root path of a hierarchy of advertisement monitors implementing
**org.bluez.AdvertisementMonitor(5)**.

The application object path together with the D-Bus ystem bus connection ID
define the identification of the application registering advertisement monitors.

Once a root path is registered by a client via this method, the client can
freely expose/unexpose advertisement monitors without re-registering the root
path again.

After use, the client should call **UnregisterMonitor()** method to invalidate
the advertisement monitors.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.AlreadyExists:
:org.bluez.Error.Failed:

void UnregisterMonitor(object application)
``````````````````````````````````````````

Unregisters a hierarchy of advertisement monitors that has been previously
registered with **RegisterMonitor()**. The object path parameter must match the
same value that has been used on registration.

Upon unregistration, the advertisement monitor(s) should expect to receive
**Release()** method as the signal that the advertisement monitor(s) has been
deactivated.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.DoesNotExist:

Properties
----------

array{string} SupportedMonitorTypes [read-only]
```````````````````````````````````````````````

This lists the supported types of advertisement monitors. An application
should check this before instantiate and expose an object of
**org.bluez.AdvertisementMonitor(5)**.

Possible values:

:"or_patterns":

	Patterns with logic OR applied. With this type, property **Patterns**
	must exist and has at least one pattern.

array{string} SupportedFeatures [read-only]
```````````````````````````````````````````

This lists the features of advertisement monitoring supported by
**bluetoothd(8)**.

Possible values:

:"controller-patterns":

	If the controller is capable of performing advertisement monitoring by
	patterns, **bluetoothd(8)** would offload the patterns to the controller
	to reduce power consumption.

===========================
org.bluez.AdminPolicyStatus
===========================

-----------------------------------------------
BlueZ D-Bus AdminPolicyStatus API documentation
-----------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
===========

Interface AdminPolicyStatus1 provides readonly properties to indicate the
current values of admin policy affecting the Adapter and Device objects.

Interface
=========

Adapter
-------

:Service:	org.bluez
:Interface:	org.bluez.AdminPolicyStatus1 [experimental]
:Object path:	[variable prefix]/{hci0,hci1,...}

Device
------

:Service:	org.bluez
:Interface:	org.bluez.AdminPolicyStatus1 [experimental]
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}

Properties
----------

array{string} ServiceAllowList [readonly, adapter-only]
```````````````````````````````````````````````````````

Current value of service allow list.

bool IsAffectedByPolicy [readonly, device-only]
```````````````````````````````````````````````

Indicate if there is any auto-connect profile in this device is not allowed by
admin policy.

========================
org.bluez.AdminPolicySet
========================

--------------------------------------------
BlueZ D-Bus AdminPolicySet API documentation
--------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Description
============

This API provides methods to control the behavior of **bluetoothd(8)** as an
administrator.

Interface AdminPolicySet1 provides methods to set policies. Once the policy is
set successfully, it will affect all clients and stay persistently even after
restarting **bluetoothd(8)**. The only way to clear it is to overwrite the
policy with the same method.

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.AdminPolicySet1 [experimental]
:Object path:	[variable prefix]/{hci0,hci1,...}

Methods
-------

void SetServiceAllowList(array{string} UUIDs)
`````````````````````````````````````````````

Sets the service allowlist by specifying service UUIDs.

When called, **bluetoothd(8)** will block incoming and outgoing connections to
the service not in UUIDs for all of the clients.

Any subsequent calls to this method will supersede any previously set allowlist
values.  Calling this method with an empty array will allow any service UUIDs to
be used.

The default value is an empty array.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.Failed:

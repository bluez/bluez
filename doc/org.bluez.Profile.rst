=================
org.bluez.Profile
=================

-------------------------------------
BlueZ D-Bus Profile API documentation
-------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	unique name
:Interface:	org.bluez.Profile1
:Object path:	freely definable

Methods
-------

void Release() [noreply]
````````````````````````

This method gets called when **bluetoothd(8)** unregisters the profile.

A profile can use it to do cleanup tasks. There is no need to unregister the
profile, because when this method gets called it has already been unregistered.

void NewConnection(object device, fd, dict fd_properties)
`````````````````````````````````````````````````````````

This method gets called when a new service level connection has been made and
authorized.

Possible fd_properties values:

:uint16 Version [optional]:

	Profile version.

:uint16 Features [optional]:

	Profile features.

Possible errors:

:org.bluez.Error.Rejected:
:org.bluez.Error.Canceled:

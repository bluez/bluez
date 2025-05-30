==============================
org.bluez.obex.Synchronization
==============================

--------------------------------------------------
BlueZ D-Bus OBEX Synchronization API documentation
--------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.Synchronization1
:Object path:	[Session object path]

Methods
-------

void SetLocation(string location)
`````````````````````````````````

Sets the phonebook object store location for other operations. Should be called
before all the other operations.

Possible location:

:"int" ( "internal" which is default ):

	Store in the interval memory.

:"sim{#}":

	Store in sim card number #.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:

object, dict GetPhonebook(string targetfile)
````````````````````````````````````````````

Retrieves an entire Phonebook Object store from remote device, and stores it in
a local file.

If an empty target file is given, a name will be automatically calculated for
the temporary file.

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

object, dict PutPhonebook(string sourcefile)
````````````````````````````````````````````

Sends an entire Phonebook Object store to remote device.

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

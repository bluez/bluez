=========================
org.bluez.obex.ObjectPush
=========================

---------------------------------------------
BlueZ D-Bus OBEX ObjectPush API documentation
---------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.ObjectPush1
:Object path:	[Session object path]

Methods
-------

object, dict SendFile(string sourcefile)
````````````````````````````````````````

Sends local file to the remote device.

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

object, dict PullBusinessCard(string targetfile)
````````````````````````````````````````````````

Request the business card from a remote device and store it in the local file.

If an empty target file is given, a name will be automatically generated for the
temporary file.

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

object, dict ExchangeBusinessCards(string clientfile, string targetfile)
````````````````````````````````````````````````````````````````````````

Push the client's business card to the remote device and then retrieve the
remote business card and store it in a local file.

If an empty target file is given, a name will be automatically generated for the
temporary file.

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

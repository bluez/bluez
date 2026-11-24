===========================
org.bluez.obex.FileTransfer
===========================

-----------------------------------------------
BlueZ D-Bus OBEX FileTransfer API documentation
-----------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.FileTransfer1
:Object path:	[Session object path]

Methods
-------

void ChangeFolder(string folder)
````````````````````````````````

Changes the current folder of the remote device.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

void CreateFolder(string folder)
````````````````````````````````

Creates a new folder in the remote device.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

array{dict} ListFolder()
````````````````````````

Returns a dictionary containing information about the current folder content.

Possible return values:

:string Name:

	Object name in UTF-8 format.

:string Type:

	Either "folder" or "file".

:uint64 Size:

	Object size or number of items in folder.

:string Permission:

	Group, owner and other permission.

:uint64 Modified:

	Last change.

:uint64 Accessed:

	Last access.

:uint64 Created:

	Creation date.

Possible errors:

:org.bluez.obex.Error.Failed:

object, dict GetFile(string targetfile, string sourcefile)
``````````````````````````````````````````````````````````

Copies the contents of the source file (from remote device) to the target file
(on local filesystem).

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

object, dict PutFile(string sourcefile, string targetfile)
``````````````````````````````````````````````````````````

Copies the contents of the source file (from local filesystem) to the target
file (on remote device).

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

void CopyFile(string sourcefile, string targetfile)
```````````````````````````````````````````````````

Copies the contents from source file to target file on the remote device.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

void MoveFile(string sourcefile, string targetfile)
```````````````````````````````````````````````````

Moves a file within the remote device from source file to the target file.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

void Delete(string file)
````````````````````````

Deletes the specified file/folder.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

=====================
org.bluez.MediaFolder
=====================

-----------------------------------------
BlueZ D-Bus MediaFolder API documentation
-----------------------------------------

:Version: BlueZ
:Date: September 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	unique name (Target role)
		org.bluez (Controller role)
:Interface:	org.bluez.MediaFolder1
:Object path:	freely definable (Target role)
		[variable prefix]/{hci0,hci1,...}/dev_{BDRADDR}/player# (Controller role)

Methods
-------

object Search(string value, dict filter)
````````````````````````````````````````

Return a folder object containing the search result.

To list the items found use the folder object returned and pass to
**ChangeFolder**.

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

array{objects, properties} ListItems(dict filter)
`````````````````````````````````````````````````

Return a list of items found

Possible Errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void ChangeFolder(object folder)
````````````````````````````````

Change current folder.

Note: By changing folder the items of previous folder might be destroyed and
have to be listed again, the exception is NowPlaying folder which should be
always present while the player is active.

Possible Errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

Properties
----------

uint32 NumberOfItems [readonly]
```````````````````````````````

Number of items in the folder

string Name [readonly]
``````````````````````

Folder name:

Possible values:

:"/Filesystem/...":

	Filesystem scope

:"/NowPlaying/...":

	NowPlaying scope

Note: /NowPlaying folder might not be listed if player is stopped, folders
created by Search are virtual so once another Search is perform or the folder is
changed using ChangeFolder it will no longer be listed.

Filters
-------

:uint32 Start:

	Offset of the first item.

	Default value: 0

:uint32 End:

	Offset of the last item.

	Default value: NumbeOfItems

:array{string} Attributes:

	Item properties that should be included in the list.

	Possible Values:

		"title", "artist", "album", "genre", "number-of-tracks",
		"number", "duration"

		Default Value: All

===================
org.bluez.MediaItem
===================

---------------------------------------
BlueZ D-Bus MediaItem API documentation
---------------------------------------

:Version: BlueZ
:Date: September 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	unique name (Target role)
		org.bluez (Controller role)
:Interface:	org.bluez.MediaItem1
:Object path:	freely definable (Target role)
		[variable
		prefix]/{hci0,hci1,...}/dev_{BDRADDR}/player#/item# (Controller role)

Methods
-------

void Play()
```````````

Play item

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void AddtoNowPlaying()
``````````````````````

Add item to now playing list

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

Properties
----------

object Player [readonly]
````````````````````````

Player object path the item belongs to

string Name [readonly]
``````````````````````

Item displayable name

string Type [readonly]
``````````````````````

Item type

Possible values:

:"video":
:"audio":
:"folder":

string FolderType [readonly, optional]
``````````````````````````````````````

Folder type.

Available if property Type is "Folder"

Possible values:

:"mixed":
:"titles":
:"albums":
:"artists":

boolean Playable [readonly, optional]
`````````````````````````````````````

Indicates if the item can be played

Available if property Type is "folder"

dict Metadata [readonly]
````````````````````````

Item metadata.

Possible values:

:string Title:

	Item title name

	Available if property Type is "audio" or "video"

:string Artist:

	Item artist name

	Available if property Type is "audio" or "video"

:string Album:

	Item album name

	Available if property Type is "audio" or "video"

:string Genre:

	Item genre name

	Available if property Type is "audio" or "video"

:uint32 NumberOfTracks:

	Item album number of tracks in total

	Available if property Type is "audio" or "video"

:uint32 Number:

	Item album number

	Available if property Type is "audio" or "video"

:uint32 Duration:

	Item duration in milliseconds

	Available if property Type is "audio" or "video"

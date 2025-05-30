=====================
org.bluez.MediaPlayer
=====================

-----------------------------------------
BlueZ D-Bus MediaPlayer API documentation
-----------------------------------------

:Version: BlueZ
:Date: September 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez (Controller role)
:Interface:	org.bluez.MediaPlayer1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/player#

Methods
-------

void Play()
```````````

Resume playback.

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void Pause()
````````````

Pause playback.

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void Stop()
```````````

Stop playback.

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void Next()
```````````

Next item.

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void Previous()
```````````````

Previous item.

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void FastForward()
``````````````````

Fast forward playback, this action is only stopped when another method in this
interface is called.

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void Rewind()
`````````````

Rewind playback, this action is only stopped when another method in this
interface is called.

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void Press(byte avc_key)
````````````````````````

Press a specific key to send as passthrough command.

The key will be released automatically. Use Hold() instead if the intention is
to hold down the key.

Possible Errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void Hold(byte avc_key)
```````````````````````

Press and hold a specific key to send as passthrough command. It is the
responsibility of the caller to make sure that Release() is called after calling
this method.

The held key will also be released when any other method in this interface is
called.

Possible Errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void Release()
``````````````

Release the previously held key invoked using Hold().

Possible Errors:

:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

Properties
----------

string Equalizer [readwrite]
````````````````````````````

Indicates Player Equalizer setting.

Possible values:

:"off":
:"on":

string Repeat [readwrite]
`````````````````````````

Indicates Player Repeat setting.

Possible values:

:"off":
:"singletrack":
:"alltracks":
:"group":

string Shuffle [readwrite]
``````````````````````````

Indicates Player Suffle setting.

Possible values:

:"off":
:"alltracks":
:"group":

string Scan [readwrite]
```````````````````````

Indicates Player Scan setting.

Possible values:

:"off":
:"alltracks":
:"group":

string Status [readonly]
````````````````````````

Indicates Player Status setting.

Possible status:

:"playing":
:"stopped":
:"paused":
:"forward-seek":
:"reverse-seek":
:"error":

uint32 Position [readonly]
``````````````````````````

Playback position in milliseconds.

Changing the position may generate additional events that will be sent to the
remote device. When position is 0 it means the track is starting and when it's
greater than or equal to track's duration the track has ended.

Note that even if duration is not available in metadata it's possible to signal
its end by setting position to the maximum uint32 value.

dict Track [readonly]
`````````````````````

Track metadata.

Possible values:

:string Title:

	Track title name

:string Artist:

	Track artist name

:string Album:

	Track album name

:string Genre:

	Track genre name

:uint32 NumberOfTracks:

	Number of tracks in total

:uint32 TrackNumber:

	Track number

:uint32 Duration:

	Track duration in milliseconds

:string ImgHandle: [experimental]

	Track image handle, available and valid only during the lifetime of an
	OBEX BIP connection to the ObexPort.

object Device [readonly]
````````````````````````

Device object path.

string Name [readonly]
``````````````````````

Player name.

string Type [readonly]
``````````````````````

Player type.

Possible values:

:"Audio":
:"Video":
:"Audio Broadcasting":
:"Video Broadcasting":

string Subtype [readonly]
`````````````````````````

Player subtype.

Possible values:

:"Audio Book":
:"Podcast":

boolean Browsable [readonly]
````````````````````````````

If present indicates the player can be browsed using MediaFolder interface.

Possible values:

:True:

	Supported and active

:False:

	Supported but inactive

Note: If supported but inactive clients can enable it by using
**org.bluez.MediaFolder(5)** interface but it might interfere in the playback of
other players.

boolean Searchable [readonly]
`````````````````````````````

If present indicates the player can be searched using MediaFolder interface.

Possible values:

:True:

	Supported and active

:False:

	Supported but inactive

Note: If supported but inactive clients can enable it by using
**org.bluez.MediaFolder(5)** interface but it might interfere in the playback of
other players.

object Playlist
```````````````

Playlist object path.

uint16 ObexPort [readonly, experimental]
````````````````````````````````````````

If present indicates the player can get cover art using BIP over OBEX on this
PSM port.

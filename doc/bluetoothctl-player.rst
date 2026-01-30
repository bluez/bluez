===================
bluetoothctl-player
===================

--------------------
Media Player Submenu
--------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [player.commands]

This submenu controls media playback using the **org.bluez.MediaPlayer(5)**
interface.

Media Player Commands
=====================

list
----

List available players.

:Usage: **> list**
:Example Display all available media players (local and remote):
	| **> list**

show
----

Show player information.

:Usage: **> show [player]**
:Uses: **org.bluez.MediaPlayer(5)** properties
:[player]: Media player path or identifier (optional, shows currently selected player if omitted)
:Example Show information for currently selected player:
	| **> show**
:Example Show remote player information:
	| **> show /org/bluez/hci0/dev_00_11_22_33_44_55/player0**

select
------

Select default player.

:Usage: **> select <player>**
:<player>: Media player path or identifier to select as default
:Example Select remote Bluetooth media player:
	| **> select /org/bluez/hci0/dev_00_11_22_33_44_55/player0**

play
----

Start playback.

:Usage: **> play [item]**
:Uses: **org.bluez.MediaPlayer(5)** method **Play**
:[item]: Media item path to play (optional, starts playback of current item if omitted)
:Example Start playback on current player:
	| **> play**
:Example Play specific item from media browser:
	| **> play /org/bluez/item/1**
:Example Play named track item:
	| **> play /org/bluez/item/track_001**
:Example Play track from specific album folder:
	| **> play /org/bluez/item/album_rock/track_05**

pause
-----

Pause playback.

:Usage: **> pause**
:Uses: **org.bluez.MediaPlayer(5)** method **Pause**
:Example Pause current playback:
	| **> pause**

stop
----

Stop playback.

:Usage: **> stop**
:Uses: **org.bluez.MediaPlayer(5)** method **Stop**
:Example Stop current playback:
	| **> stop**

next
----

Jump to next item.

:Usage: **> next**
:Uses: **org.bluez.MediaPlayer(5)** method **Next**
:Example Skip to next track:
	| **> next**

previous
--------

Jump to previous item.

:Usage: **> previous**
:Uses: **org.bluez.MediaPlayer(5)** method **Previous**
:Example Go back to previous track:
	| **> previous**

fast-forward
------------

Fast forward playback.

:Usage: **> fast-forward**
:Uses: **org.bluez.MediaPlayer(5)** method **FastForward**
:Example Enable fast forward mode:
	| **> fast-forward**

rewind
------

Rewind playback.

:Usage: **> rewind**
:Uses: **org.bluez.MediaPlayer(5)** method **Rewind**
:Example Enable rewind mode:
	| **> rewind**

equalizer
---------

Enable/Disable equalizer.

:Usage: **> equalizer <on/off>**
:Uses: **org.bluez.MediaPlayer(5)** property **Equalizer**
:<on/off>: Enable (on) or disable (off) the equalizer
:Example Enable equalizer:
	| **> equalizer on**
:Example Disable equalizer:
	| **> equalizer off**

repeat
------

Set repeat mode.

:Usage: **> repeat <singletrack/alltrack/group/off>**
:Uses: **org.bluez.MediaPlayer(5)** property **Repeat**
:<singletrack/alltrack/group/off>: Set repeat mode - singletrack (current track), alltrack (all tracks), group (current group/album), or off (no repeat)
:Example Disable repeat mode:
	| **> repeat off**
:Example Repeat current track:
	| **> repeat singletrack**
:Example Repeat entire playlist/queue:
	| **> repeat alltrack**
:Example Repeat current group/album:
	| **> repeat group**

shuffle
-------

Set shuffle mode.

:Usage: **> shuffle <alltracks/group/off>**
:Uses: **org.bluez.MediaPlayer(5)** property **Shuffle**
:<alltracks/group/off>: Set shuffle mode - alltracks (shuffle all tracks), group (shuffle within current group), or off (no shuffle)
:Example Disable shuffle mode:
	| **> shuffle off**
:Example Shuffle all tracks in playlist:
	| **> shuffle alltracks**
:Example Shuffle tracks within current group:
	| **> shuffle group**

scan
----

Set scan mode.

:Usage: **> scan <alltracks/group/off>**
:Uses: **org.bluez.MediaPlayer(5)** property **Scan**
:<alltracks/group/off>: Set scan mode - alltracks (scan through all tracks), group (scan within current group), or off (no scan)
:Example Disable scan mode:
	| **> scan off**
:Example Scan through all tracks:
	| **> scan alltracks**
:Example Scan through current group only:
	| **> scan group**

change-folder
-------------

Change current folder.

:Usage: **> change-folder <item>**
:<item>: Folder path to navigate to, or ".." to go up one directory level
:Example Navigate to Albums folder:
	| **> change-folder /org/bluez/item/Albums**
:Example Navigate to Artists folder:
	| **> change-folder /org/bluez/item/Artists**
:Example Navigate to Playlists folder:
	| **> change-folder /org/bluez/item/Playlists**
:Example Go up one directory level:
	| **> change-folder ..**

list-items
----------

List items of current folder.

:Usage: **> list-items [start] [end]**
:[start]: Starting index for item list (optional, defaults to 0)
:[end]: Ending index for item list (optional, lists all items from start if omitted)
:Example List all items in current folder:
	| **> list-items**
:Example List first 10 items (0-10):
	| **> list-items 0 10**
:Example List items 5 through 15:
	| **> list-items 5 15**
:Example List items 10 through 20:
	| **> list-items 10 20**
:Example List first 50 items:
	| **> list-items 0 50**

search
------

Search items containing string.

:Usage: **> search <string>**
:<string>: Search term to find matching items (songs, albums, artists, etc.)
:Example Search for Beatles songs/albums:
	| **> search "The Beatles"**
:Example Search for items containing "rock":
	| **> search "rock"**
:Example Search for items from 2023:
	| **> search "2023"**
:Example Search for playlists:
	| **> search "playlist"**

queue
-----

Add item to playlist queue.

:Usage: **> queue <item>**
:<item>: Media item path to add to the playback queue
:Example Add specific track to queue:
	| **> queue /org/bluez/item/track_001**
:Example Add entire album to queue:
	| **> queue /org/bluez/item/album_rock**
:Example Add playlist to queue:
	| **> queue /org/bluez/item/playlist_favorites**

show-item
---------

Show item information.

:Usage: **> show-item <item>**
:<item>: Media item path to display detailed information for
:Example Show details of specific track:
	| **> show-item /org/bluez/item/track_001**
:Example Show details of album:
	| **> show-item /org/bluez/item/album_rock**
:Example Show details of artist:
	| **> show-item /org/bluez/item/artist_beatles**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

===================
bluetoothctl-player
===================

--------------------
Media Player Submenu
--------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [player.commands]

Media Player Commands
=====================

list
----

List available players.

:Usage: **# list**

show
----

Show player information.

:Usage: **# show [player]**

select
------

Select default player.

:Usage: **# select <player>**

play
----

Start playback.

:Usage: **# play [item]**

pause
-----

Pause playback.

:Usage: **# pause**

stop
----

Stop playback.

:Usage: **# stop**

next
----

Jump to next item.

:Usage: **# next**

previous
--------

Jump to previous item.

:Usage: **# previous**

fast-forward
------------

Fast forward playback.

:Usage: **# fast-forward**

rewind
------

Rewind playback.

:Usage: **# rewind**

equalizer
---------

Enable/Disable equalizer.

:Usage: **# equalizer <on/off>**

repeat
------

Set repeat mode.

:Usage: **# repeat <singletrack/alltrack/group/off>**

shuffle
-------

Set shuffle mode.

:Usage: **# shuffle <alltracks/group/off>**

scan
----

Set scan mode.

:Usage: **# scan <alltracks/group/off>**

change-folder
-------------

Change current folder.

:Usage: **# change-folder <item>**

list-items
----------

List items of current folder.

:Usage: **# list-items [start] [end]**

search
------

Search items containing string.

:Usage: **# search <string>**

queue
-----

Add item to playlist queue.

:Usage: **# queue <item>**

show-item
---------

Show item information.

:Usage: **# show-item <item>**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

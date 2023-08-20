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

**bluetoothctl** [**-a** *capability*] [**-e**] [**-m**] [**-t** *seconds*] [**-v**] [**-h**]

DESCRIPTION
===========

**bluetoothctl(1)** interactive bluetooth control tool. The tool works with Bluetooth Classic (BR/EDR) and Bluetooth Low Energy (LE) controllers.

OPTIONS
=======

-a capability, --agent capability        Register agent handler: <capability>
-e, --endpoints                  Register Media endpoints
-m, --monitor                    Enable monitor output
-t seconds, --timeout seconds    Timeout in seconds for non-interactive mode
-v, --version       Display version
-h, --help          Display help

Media Player Commands
=====================
   We divide bluetoothctl into main menu commands and submenu commands. The submenu commands control options 
   numbers for the commands can be hex (0x0F) or decimal (10)
   
list
----
List available players

:Usage: **# list**

show
----
Show player information

:Usage: **# show [player]**

select
------
Select default player

:Usage: **# select <player>**

play
----
Start playback

:Usage: **# play [item]**

pause
-----
Pause playback

:Usage: **# pause**

stop
----
Stop playback

:Usage: **# stop**

next
----
Jump to next item

:Usage: **# next**

previous
--------
Jump to previous item

:Usage: **# previous**

fast-forward
------------
Fast forward playback

:Usage: **# fast-forward**

rewind
------
Rewind playback

:Usage: **# rewind**

equalizer
---------
Enable/Disable equalizer

:Usage: **# equalizer <on/off>**

repeat
------
Set repeat mode

:Usage: **# repeat <singletrack/alltrack/group/off>**

shuffle
-------
Set shuffle mode

:Usage: **# shuffle <alltracks/group/off>**

scan
----
Set scan mode

:Usage: **# scan <alltracks/group/off>**

change-folder
-------------
Change current folder

:Usage: **# change-folder <item>**

list-items
----------
List items of current folder

:Usage: **# list-items [start] [end]**

search
------
Search items containing string

:Usage: **# search <string>**

queue
-----
Add item to playlist queue

:Usage: **# queue <item>**

show-item
---------
Show item information

:Usage: **# show-item <item>**

back
----
Return to main menu

:Usage: **# back**

version
-------
Display version

:Usage: **# version**

quit
----
Quit program

:Usage: **# quit**

exit
----
Quit program

:Usage: **# exit**

help
----
Display help about this program

:Usage: **# help**

export
------
Print environment variables

:Usage: **# export**


RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

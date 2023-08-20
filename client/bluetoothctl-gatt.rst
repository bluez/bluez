============
bluetoothctl
============

-------------------------
Generic Attribute Submenu
-------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [**-a** *capability*] [**-e**] [**-m**] [**-t** *seconds*] [**-v**] [**-h**]

OPTIONS
=======

-a capability, --agent capability        Register agent handler: <capability>
-e, --endpoints                  Register Media endpoints
-m, --monitor                    Enable monitor output
-t seconds, --timeout seconds    Timeout in seconds for non-interactive mode
-v, --version       Display version
-h, --help          Display help

COMMANDS
========
   We divide bluetoothctl into main menu commands and submenu commands. The submenu commands control options 
   numbers for the commands can be hex (0x0F) or decimal (10)
   


Generic Attribute Commands
==========================

list-attributes
---------------
List attributes

:Usage: **# list-attributes <attribute/UUID>**

select-attribute
----------------
Select attribute

:Usage: **# select-attribute <attribute/UUID>**

attribute-info
--------------
Select attribute

:Usage: **# attribute-info [attribute/UUID]**

read
----
Read attribute value

:Usage: **# read [offset]**

write
-----
Write attribute value

:Usage: **# write <data=xx xx ...> [offset] [type]**

acquire-write
-------------
Acquire Write file descriptor

:Usage: **# acquire-write**

release-write
-------------
Release Write file descriptor

:Usage: **# release-write**

acquire-notify
--------------
Acquire Notify file descriptor

:Usage: **# acquire-notify**

release-notify
--------------
Release Notify file descriptor

:Usage: **# release-notify**

notify
------
Notify attribute value

:Usage: **# notify <on/off>**

clone
-----
Clone a device or attribute

:Usage: **# clone [dev/attribute/UUID]**

register-application
--------------------
Register profile to connect

:Usage: **# register-application [UUID ...]**

unregister-application
----------------------
Unregister profile

:Usage: **# unregister-application**

register-service
----------------
Register application service.

:Usage: **# register-service <UUID> [handle]**

unregister-service
------------------
Unregister application service

:Usage: **# unregister-service <UUID/object>**

register-includes
-----------------
Register as Included service in.

:Usage: **#r egister-includes <UUID> [handle]**

unregister-includes
-------------------
Unregister Included service.

:Usage: **# unregister-includes <Service-UUID><Inc-UUID>**

register-characteristic
-----------------------
Register application characteristic

:Usage: **# register-characteristic <UUID> <Flags=read,write,notify...> [handle]**

unregister-characteristic
-------------------------
Unregister application characteristic

:Usage: **# unregister-characteristic <UUID/object>**

register-descriptor
-------------------
Register application descriptor

:Usage: **# register-descriptor <UUID> <Flags=read,write...> [handle]**

unregister-descriptor
---------------------
Unregister application descriptor

:Usage: **# unregister-descriptor <UUID/object>**

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

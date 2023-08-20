============
bluetoothctl
============

----------------
Endpoint Submenu
----------------

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

Endpoint Commands
=================
   We divide bluetoothctl into main menu commands and submenu commands. The submenu commands control options 
   numbers for the commands can be hex (0x0F) or decimal (10)
   
list
----
List available endpoints

:Usage: **# list [local]**

show
----
Endpoint information

:Usage: **# show <endpoint>**

register
--------
Register Endpoint

:Usage: **# register <UUID> <codec> [capabilities...]**

unregister
----------
Register Endpoint

:Usage: **# unregister <UUID/object>**

config
------
Configure Endpoint

:Usage: **# config <endpoint> <local endpoint> [preset]**

presets
-------
List available presets

:Usage: **# presets <UUID> [default]**

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

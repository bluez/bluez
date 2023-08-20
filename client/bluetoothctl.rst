============
bluetoothctl
============

------------------------------------
interactive bluetooth control tool
------------------------------------

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
The tool is menu driven but can be automated from the command line. Examples are given in the automation section. 

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
   We divide bluetoothctl into main menu commands and submenu commands. The submenu commands can be found at their own pages which are listed below.
   Submenu items can either be accessed with the menu option i.e. 'menu advertise' or directly from the main menu with dot notation i.e. 'advertise.tx-power on'


MAIN MENU COMMANDS
==================

menu advertise
--------------
Advertise Options Submenu

:Usage: **# menu advertise**

menu monitor
------------
Advertisement Monitor Options Submenu

:Usage: **# menu monitor**

menu scan
---------
Scan Options Submenu

:Usage: **# menu scan**

menu gatt
---------
Generic Attribute Submenu

:Usage: **# menu gatt**

menu admin
----------
Admin Policy Submenu

:Usage: **# menu admin**

menu player
-----------
Media Player Submenu

:Usage: **# menu player**

menu endpoint
-------------
Media Endpoint Submenu

:Usage: **# menu endpoint**

menu transport
--------------
Media Transport Submenu

:Usage: **# menu transport**

list
----
List available controllers

:Usage: **# list**

show
----
Controller information

:Usage: **# show [ctrl]**

select
------
Select default controller

:Usage: **# select <ctrl>**

devices
-------
List available devices, with an optional property as the filter

:Usage: **# devices [Paired/Bonded/Trusted/Connected]**

system-alias
------------
Set controller alias

:Usage: **# system-alias <name>**

reset-alias
-----------
Reset controller alias

:Usage: **# reset-alias**

power
-----
Set controller power
When the controller is powered off, the USB port the controller is attached to is put into a suspend state. When the controller is powered on the port is taken out of a suspend state and the controller is power cycled. Any firmware will be reloaded at this time.

:Usage: **# power <on/off>**

advertise
---------
Enable/disable advertising with given type
Will start advertising. If you exit the program advertising will be disabled. When advertising the controller should advertise with random address but may use its public address if it does not support the feature (address of the device)
A device can advertise if it initiated the connection to another advertising device.
When advertising the controller will always advertise with the connectable option.

:Usage: **# advertise <on/off/type>**

set-alias
---------
Set device alias

:Usage: **# set-alias <alias>**

scan
----
Scan for devices
  For LE, scanning is an important requirement before connecting or pairing. The purpose of scanning is to find devices 
  that are advertising with their discoverable flag set (either limited or general). Once you have found the address
  then you can connect or pair. Note the following when scanning:

  - When scanning the controller will use a random address that is not resolvable. A new random address is created every time scan on is used. 
  - When turning on scanning the device will start receiving advertising reports of what devices are advertising.
  - The filtering of duplicate advertising reports is enabled.
  - The scan interval and scan window are fixed at 11.250 msec. 
  - You do get advertising reports from nondiscoverable devices.
  - Scan reports have a finite time duration and will expire. If they expire you will need to scan again before connecting or pairing.

:Usage: **# scan <on/off/bredr/le>**

pair
----
Pair with device
This will pair with a device and then trust and connect to it. If the device is already paired this will first remove the pairing.
Pairing provides authentication or encryption. The command can either be used while the controller is in the connected or not connected state. 
If the controller is already connected then the pair command can be used without an arguments. If the controller is not connected, the pair 
command can be given the address of a device with an active scan report and it will initiate the connection before pairing. 
Before pairing the agent must be selected to choose the authentication mechanism.

:Usage: **# pair <dev>**

pairable
--------
Set controller pairable mode
This enables/disables pairing. If pairing is disabled then the controller will not accept any pairing requests.

:Usage: **# pairable <on/off>**

discoverable
------------
Set discoverable mode
This enables/disables discoverable mode. If discoverable is disabled then the controller will not respond to any scan requests.
In LE if discoverable if off the controller will just passively scan and not make scan requests to advertising devices. If on it will make the advertising requests.
It will use a random address if supported by the controller. The length of time "discoverable on" is valid is determined by discoverable-timeout

:Usage: **# discoverable <on/off>**

discoverable-timeout
--------------------
Set discoverable timeout
The time in seconds that "discoverable on" is valid.

:Usage: **# discoverable-timeout [value]**

agent
-----
Enable/disable agent with given capability
This chooses the local authentication mechanism of the controller. It is needed for pairing and allows you to choose the IO capabilities of the controller.
The valid agent capabilities are: DisplayOnly, DisplayYesNo, KeyboardDisplay, KeyboardOnly, NoInputNoOutput.

:Usage: **# agent <on/off/capability>**

default-agent
-------------
Set agent as the default one
After selecting the agent this will make it the default agent

:Usage: **# default-agent**

trust
-----
Trust device

:Usage: **# trust <dev>**

untrust
-------
Untrust device

:Usage: **# untrust <dev>**

block
-----
Block device

:Usage: **# block <dev>**

unblock
-------
Unblock device

:Usage: **# unblock <dev>**

remove
------
Remove device

:Usage: **# remove <dev>**

connect
-------
Connect device
This will initiate a connection to a device. If the device is not paired this will first pair and then trust and connect to it.
To connect with a device the controller must have an active scan report of the device it wants to connect to. The advertising report can be obtained either by using the scan command
otherwise the connect command will issue a HCI_LE_Set_Extended_Scan_Enable to find the device. If no advertising report is received before the timeout a le-connection-abort-by-local
error will be issued. In that case either try again to connect assuming the device is advertising.

:Usage: **# connect <dev>**

disconnect
----------
Disconnect device
For LE when disconnecting from an active connection the device address is not needed.

:Usage: **# disconnect <dev>**

info
----
Device information

:Usage: **# info <dev>**

menu
----
Menu option
This will allow you to access the submenu options directly from the main menu. The submenu options are listed below.

:Usage: **# menu <submenu>**

version
-------
Display version

:Usage: **# version**

quit
----
Quit program

:Usage: **# quit**

help
----
Display help

:Usage: **# help**

exit
----
Exit program

:Usage: **# exit**

export
------
Print environment variable

:Usage: **# export**


ADVERTISE OPTIONS SUBMENU COMMANDS
==================================
See bluetoothctl-advertise

ADVERTISEMENT MONITOR OPTIONS SUBMENU COMMANDS
==============================================
See bluetoothctl-monitor

SCAN OPTIONS OPTIONS SUBMENU COMMANDS
=====================================
See bluetoothctl-scan

GENERIC ATTRIBUTE SUBMENU COMMANDS
==================================
See bluetoothctl-gatt

ADMIN POLICY SUBMENU COMMANDS
=============================
See bluetoothctl-admin

MEDIA PLAYER SUBMENU COMMANDS
=============================
See bluetoothctl-player

MEDIA ENDPOINT SUBMENU COMMANDS
===============================
See bluetoothctl-endpoint

MEDIA TRANSPORT SUBMENU COMMANDS
================================
See bluetoothctl-transport

PAIRING
=======
| To pair scanning must first be turned on to get the devices advertising report.
|

AUTOMATION
==========
Two common ways to automate the tool are to use Here Docs or the program expect.
Using Here Docs to show information about the Bluetooth controller.

.. code:: bash

   bluetoothctl <<EOF
   list
   show
   EOF


RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

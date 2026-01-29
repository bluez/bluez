============
bluetoothctl
============

-----------------------------------
Bluetooth Control Command Line Tool
-----------------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: March 2024
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [**-a** *capability*] [**-e**] [**-m**] [**-t** *seconds*]
[**-v**] [**-h**]

DESCRIPTION
===========

**bluetoothctl(1)** interactive bluetooth control tool. The tool works with
Bluetooth Classic (BR/EDR) and Bluetooth Low Energy (LE) controllers.

The tool is menu driven but can be automated from the command line.
Examples are given in the automation section.

OPTIONS
=======

-a capability, --agent capability        Register agent handler: <capability>
-e, --endpoints                  Register Media endpoints
-m, --monitor                    Enable monitor output
-t seconds, --timeout seconds    Timeout in seconds for non-interactive mode
-v, --version       Display version
-h, --help          Display help


Commands
========

list
----

List available controllers.

:Usage: **> list**
:Example Display all Bluetooth controllers available on the system:
	| **> list**

show
----

Controller information.

:Usage: **> show [ctrl]**
:[ctrl]: Bluetooth controller address
:Example Display information for currently selected controller:
	| **> show**
:Example Show information for controller 00:11:22:33:44:55:
	| **> show 00:11:22:33:44:55**

select
------

Select default controller.

:Usage: **> select <ctrl>**
:<ctrl>: Bluetooth controller address
:Example Select controller 00:11:22:33:44:55:
	| **> select 00:11:22:33:44:55**

devices
-------

List available devices, with an optional property as the filter.

:Usage: **> devices [Paired/Bonded/Trusted/Connected]**
:[Paired/Bonded/Trusted/Connected]: Filter to show only devices with specific property (optional)
:Example List all discovered devices:
	| **> devices**
:Example List only paired devices:
	| **> devices Paired**
:Example List only bonded devices:
	| **> devices Bonded**
:Example List only trusted devices:
	| **> devices Trusted**
:Example List only currently connected devices:
	| **> devices Connected**

system-alias
------------

Set controller alias.

:Usage: **> system-alias <name>**
:<name>: New alias name for the Bluetooth controller (required)
:Example Set controller alias with spaces (note quotes):
	| **> system-alias "My Desktop Bluetooth"**
:Example Set controller alias without spaces:
	| **> system-alias MyLaptop**
:Example Set controller alias with hyphens:
	| **> system-alias "Home-Office-PC"**

reset-alias
-----------

Reset controller alias.

:Usage: **> reset-alias**
:Example Reset controller alias to default (usually the hostname):
	| **> reset-alias**

power
-----

Set controller power.

When the controller is powered off, the USB port the controller is attached to
is put into a suspend state.

:Usage: **> power <on/off>**
:<on/off>: Power state - "on" to enable or "off" to disable the controller (required)
:Example Turn on the Bluetooth controller:
	| **> power on**
:Example Turn off the Bluetooth controller:
	| **> power off**

advertise
---------

Enable/disable advertising with given type.

When the controller advertises an LE device (peripheral) it will generate a
random address for its own privacy if the controller is capable of it, it will
use its public address if it does not support the feature (address of the
device).

A device can advertise if it initiated the connection to another advertising
device.

:Usage: **> advertise <on/off/type>**
:<on/off/type>: Advertising mode - "on", "off", "peripheral", or "broadcast" (required)
:Example Enable basic LE advertising:
	| **> advertise on**
:Example Disable LE advertising:
	| **> advertise off**
:Example Advertise as peripheral device:
	| **> advertise peripheral**
:Example Advertise as broadcast source:
	| **> advertise broadcast**

set-alias
---------

Set device alias.

:Usage: **> set-alias <alias>**
:<alias>: New alias name for the device (required)
:Example Set device alias with spaces (note quotes):
	| **> set-alias "My Headphones"**
:Example Set device alias without spaces:
	| **> set-alias MyMouse**
:Example Set device alias with hyphens:
	| **> set-alias "Kitchen-Speaker"**

scan
----

Scan for devices.

For LE, scanning is an important requirement before connecting or pairing.

The purpose of scanning is to find devices that are advertising with their
discoverable flag set (either limited or general). Once you have found the
address then you can connect or pair.

:Usage: **> scan <on/off/bredr/le>**
:<on/off/bredr/le>: Scan mode - "on", "off", "bredr" for Classic, or "le" for Low Energy (required)
:Example Start scanning for all device types (LE + Classic):
	| **> scan on**
:Example Stop scanning:
	| **> scan off**
:Example Scan for Low Energy devices only:
	| **> scan le**
:Example Scan for BR/EDR (Classic) devices only:
	| **> scan bredr**

pair
----

Pair with device.

This will pair with a device and then trust and connect to it. If the device is
already paired this will first remove the pairing.

The command can either be used while the controller is in the connected or not
connected state.

If the controller is already connected then the pair command can be used without
an arguments. If the controller is not connected, the pair command can be given
the address of a device with an active scan report and it will initiate the
connection before pairing.

Before pairing the agent must be selected to choose the authentication
mechanism.

:Usage: **> pair [dev]**
:[dev]: Device MAC address (XX:XX:XX:XX:XX:XX) (optional, uses current device if omitted)
:Example Pair with device using MAC address:
	| **> pair 00:11:22:33:44:55**
:Example Pair with another device:
	| **> pair AA:BB:CC:DD:EE:FF**
:Example Pair using device object path:
	| **> pair /org/bluez/hci0/dev_00_11_22_33_44_55**

pairable
--------

Set controller pairable mode.

This enables/disables pairing. If pairing is disabled then the controller will
not accept any pairing requests.

:Usage: **> pairable <on/off>**
:<on/off>: Pairable mode - "on" to accept or "off" to reject pairing requests (required)
:Example Enable pairing (accept pairing requests):
	| **> pairable on**
:Example Disable pairing (reject pairing requests):
	| **> pairable off**

discoverable
------------

Set discoverable mode.

This enables/disables discoverable mode. If discoverable is disabled then the
controller will not respond to any scan requests.

In LE if discoverable if off the controller will just passively scan and not
make scan requests to advertising devices. If on it will make the advertising
requests.

It will use a random address if supported by the controller. The length of time
"discoverable on" is valid is determined by discoverable-timeout command.

:Usage: **> discoverable <on/off>**
:<on/off>: Discoverable mode - "on" to be discoverable or "off" to be non-discoverable (required)
:Example Make controller discoverable to other devices:
	| **> discoverable on**
:Example Make controller non-discoverable:
	| **> discoverable off**

discoverable-timeout
--------------------

Set discoverable timeout.

The time in seconds that "discoverable on" is valid.

:Usage: **> discoverable-timeout [value]**
:[value]: Timeout duration in seconds for discoverable mode (0 for unlimited, optional)
:Example Show current discoverable timeout value:
	| **> discoverable-timeout**
:Example Set discoverable timeout to 30 seconds:
	| **> discoverable-timeout 30**
:Example Set discoverable timeout to 2 minutes:
	| **> discoverable-timeout 120**
:Example Set discoverable timeout to 5 minutes:
	| **> discoverable-timeout 300**
:Example Set unlimited discoverable timeout:
	| **> discoverable-timeout 0**

agent
-----

Enable/disable agent with given capability.

This chooses the local authentication mechanism of the controller. It is needed
for pairing and allows you to choose the IO capabilities of the controller.

The valid agent capabilities are: DisplayOnly, DisplayYesNo, KeyboardDisplay,
KeyboardOnly, NoInputNoOutput.

:Usage: **> agent <on/off/auto/capability>**
:<on/off/auto/capability>: Agent mode - "on", "off", "auto", or capability type (DisplayOnly, DisplayYesNo, KeyboardDisplay, KeyboardOnly, NoInputNoOutput) (required)
:Example Enable agent with default capability:
	| **> agent on**
:Example Disable agent:
	| **> agent off**
:Example Enable agent that can only display pairing codes:
	| **> agent DisplayOnly**
:Example Enable agent that can display codes and accept/reject:
	| **> agent DisplayYesNo**
:Example Enable agent that can display and input pairing codes:
	| **> agent KeyboardDisplay**
:Example Enable agent that can only input pairing codes:
	| **> agent KeyboardOnly**
:Example Enable agent with no input/output (JustWorks):
	| **> agent NoInputNoOutput**

default-agent
-------------

Set current agent as the default one.

After selecting the agent this will make it the default agent.

:Usage: **> default-agent**
:Example Set the current agent as default:
	| **> default-agent**

trust
-----

Trust device.

:Usage: **> trust [dev]**
:[dev]: Device MAC address (XX:XX:XX:XX:XX:XX) or object path (optional, uses current device if omitted)
:Example Trust device using MAC address:
	| **> trust 00:11:22:33:44:55**
:Example Trust another device:
	| **> trust AA:BB:CC:DD:EE:FF**
:Example Trust device using object path:
	| **> trust /org/bluez/hci0/dev_00_11_22_33_44_55**

untrust
-------

Untrust device.

:Usage: **> untrust [dev]**
:[dev]: Device MAC address (XX:XX:XX:XX:XX:XX) or object path (optional, uses current device if omitted)
:Example Remove trust from device using MAC address:
	| **> untrust 00:11:22:33:44:55**
:Example Remove trust from another device:
	| **> untrust AA:BB:CC:DD:EE:FF**
:Example Remove trust using object path:
	| **> untrust /org/bluez/hci0/dev_00_11_22_33_44_55**

block
-----

Block device.

:Usage: **> block [dev]**
:[dev]: Device MAC address (XX:XX:XX:XX:XX:XX) or object path (optional, uses current device if omitted)
:Example Block device using MAC address:
	| **> block 00:11:22:33:44:55**
:Example Block another device:
	| **> block AA:BB:CC:DD:EE:FF**
:Example Block device using object path:
	| **> block /org/bluez/hci0/dev_00_11_22_33_44_55**

unblock
-------
Unblock device

:Usage: **> unblock [dev]**
:[dev]: Device MAC address (XX:XX:XX:XX:XX:XX) or object path (optional, uses current device if omitted)
:Example Unblock device using MAC address:
	| **> unblock 00:11:22:33:44:55**
:Example Unblock another device:
	| **> unblock AA:BB:CC:DD:EE:FF**
:Example Unblock device using object path:
	| **> unblock /org/bluez/hci0/dev_00_11_22_33_44_55**

remove
------

Remove device.

:Usage: **> remove <dev>**
:<dev>: Device MAC address (XX:XX:XX:XX:XX:XX) or object path (required)
:Example Remove device using MAC address:
	| **> remove 00:11:22:33:44:55**
:Example Remove another device:
	| **> remove AA:BB:CC:DD:EE:FF**
:Example Remove device using object path:
	| **> remove /org/bluez/hci0/dev_00_11_22_33_44_55**

connect
-------

Connect device.

This will initiate a connection to a device.

By default this commands tries to connect all the profiles the remote device
supports and have been flagged as auto-connectable. In case when the UUID of
the remote service is given only that service will be connected. The UUID can
be either a short form (16-bit UUID) or a long form (128-bit UUID). There are
also some special values for well-known profiles like "a2dp-sink",
"a2dp-source", "hfp-hf", "hfp-ag", "ftp" or "spp".

To connect with an LE device the controller must have an active scan report of
the device it wants to connect to.

If no advertising report is received before the timeout a
le-connection-abort-by-local error will be issued. In that case either try
again to connect assuming the device is advertising.

:Usage: **> connect <dev> [uuid]**
:<dev>: Device MAC address (XX:XX:XX:XX:XX:XX) or object path (required)
:[uuid]: Specific service UUID to connect to (16-bit, 128-bit UUID, or profile name like "a2dp-sink", "hfp-hf", etc.) (optional)
:Example Connect to device (all supported profiles):
	| **> connect 1C:48:F9:9D:81:5C**
:Example Connect to HSP Headset profile:
	| **> connect 1C:48:F9:9D:81:5C hsp-hs**
:Example Connect to A2DP Sink profile:
	| **> connect 1C:48:F9:9D:81:5C a2dp-sink**
:Example Connect to A2DP Source profile:
	| **> connect 1C:48:F9:9D:81:5C a2dp-source**
:Example Connect to HFP Hands-Free profile:
	| **> connect 1C:48:F9:9D:81:5C hfp-hf**
:Example Connect to HFP Audio Gateway profile:
	| **> connect 1C:48:F9:9D:81:5C hfp-ag**
:Example Connect to File Transfer Profile:
	| **> connect 1C:48:F9:9D:81:5C ftp**
:Example Connect to Serial Port Profile:
	| **> connect 1C:48:F9:9D:81:5C spp**
:Example Connect using full 128-bit UUID (HSP):
	| **> connect 1C:48:F9:9D:81:5C 00001108-0000-1000-8000-00805f9b34fb**
:Example Connect using short 16-bit UUID (HSP):
	| **> connect 1C:48:F9:9D:81:5C 0x1108**
:Example Connect to A2DP profile using short UUID:
	| **> connect 1C:48:F9:9D:81:5C 0x110E**

disconnect
----------

Disconnect device.

By default this commands disconnects all profiles and then terminates the
connection. In case when the UUID of the remote service is given only that
service will be disconnected.

For LE when disconnecting from an active connection the device address is not
needed.

:Usage: **> disconnect [dev] [uuid]**
:[dev]: Device MAC address (XX:XX:XX:XX:XX:XX) or object path (optional, uses current device if omitted)
:[uuid]: Specific service UUID to disconnect from (16-bit, 128-bit UUID, or profile name) (optional)
:Example Disconnect all profiles and terminate connection:
	| **> disconnect 1C:48:F9:9D:81:5C**
:Example Disconnect only A2DP Sink profile:
	| **> disconnect 1C:48:F9:9D:81:5C a2dp-sink**
:Example Disconnect only HFP Hands-Free profile:
	| **> disconnect 1C:48:F9:9D:81:5C hfp-hf**
:Example Disconnect only Serial Port Profile:
	| **> disconnect 1C:48:F9:9D:81:5C spp**
:Example Disconnect A2DP profile using short UUID:
	| **> disconnect 1C:48:F9:9D:81:5C 0x110E**
:Example Disconnect HSP profile using full UUID:
	| **> disconnect 1C:48:F9:9D:81:5C 00001108-0000-1000-8000-00805f9b34fb**

info
----

Device information.

:Usage: **> info [dev/set]**
:[dev/set]: Device MAC address (XX:XX:XX:XX:XX:XX), object path, or DeviceSet (optional, uses current device if omitted)
:Example Show detailed information for device:
	| **> info 1C:48:F9:9D:81:5C**
:Example Show information for another device:
	| **> info 00:11:22:33:44:55**
:Example Show device info using object path:
	| **> info /org/bluez/hci0/dev_1C_48_F9_9D_81_5C**

bearer
------

Get/Set preferred bearer.

:Usage: **> bearer <dev> [last-seen/bredr/le]**
:<dev>: Device MAC address (XX:XX:XX:XX:XX:XX) or object path (required)
:[last-seen/bredr/le]: Preferred bearer type - "last-seen", "bredr" for Classic, or "le" for Low Energy (optional)
:Example get preferred bearer:
	| > bearer <addr>
        |    PreferredBearer: last-seen
:Example set preferred bearer to LE:
	| > bearer <addr> le
	| [CHG] Device <addr> PreferredBearer: le
	| Changing le succeeded
:Example set preferred bearer to BREDR:
	| > bearer <addr> bredr
	| [CHG] Device <addr> PreferredBearer: bredr
	| Changing bredr succeeded

Advertise Submenu
=================

See **bluetoothctl-advertise(1)**.

Monitor Submenu
===============

See **bluetoothctl-monitor(1)**

Scan Submenu
============

See **bluetoothctl-scan(1)**

Gatt Submenu
============

See **bluetoothctl-gatt(1)**

Admin Submenu
=============

See **bluetoothctl-admin(1)**

Player Submenu
==============

See **bluetoothctl-player(1)**

Endpoint Submenu
================

See **bluetoothctl-endpoint(1)**

Transport Submenu
=================

See **bluetoothctl-transport(1)**

Management Submenu
==================

See **bluetoothctl-mgmt(1)**

Assistant Submenu
==================

See **bluetoothctl-assistant(1)**

LE Submenu
==================

See **bluetoothctl-le(1)**

BREDR Submenu
==================

See **bluetoothctl-bredr(1)**

AUTOMATION
==========
Two common ways to automate the tool are to use Here Docs or the program expect.
Using Here Docs to show information about the Bluetooth controller.

.. code::

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

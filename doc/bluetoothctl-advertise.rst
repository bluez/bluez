======================
bluetoothctl-advertise
======================

-----------------
Advertise Submenu
-----------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [advertise.commands]

Advertise Options Commands
==========================

uuids
-----

Set/Get advertise uuids.

:Usage: **> uuids [uuid1 uuid2 ...]**
:[uuid1 uuid2 ...]: List of UUIDs to advertise (default: none)
:Example Show current advertised UUIDs:
	| **> uuids**
:Example Advertise custom 16-bit service UUID:
	| **> uuids 0x1234**
:Example Advertise custom 32-bit service UUID:
	| **> uuids 0x12345678**
:Example Advertise custom 128-bit service UUID:
	| **> uuids 90f95193-35de-4306-a6e9-699328f15059**
:Example Advertise Battery and Generic Attribute services:
	| **> uuids 0x180F 0x1801**
:Example Advertise Device Information, Battery, and HID services:
	| **> uuids 0x180A 0x180F 0x1812**
:Example Advertise Generic Access service:
	| **> uuids 0x1800**
:Example Advertise Environmental Sensing service:
	| **> uuids 0x181A**
:Example Advertise Pulse Oximeter service:
	| **> uuids 0x183B**
:Example Mix short and full UUID formats:
	| **> uuids 0x180F 12345678-1234-5678-9abc-123456789abc**

solicit
-------

Set/Get advertise solicit uuids.

:Usage: **> solicit [uuid1 uuid2 ...]**
:[uuid1 uuid2 ...]: List of UUIDs to advertise (default: none)
:Example Show current solicited service UUIDs:
	| **> solicit**
:Example Solicit Generic Access service:
	| **> solicit 0x1800**
:Example Solicit Device Information service:
	| **> solicit 0x180A**
:Example Solicit User Data service:
	| **> solicit 0x181C**
:Example Solicit Battery and Generic Attribute services:
	| **> solicit 0x180F 0x1801**
:Example Solicit Device Info, Environmental Sensing, and Pulse Oximeter:
	| **> solicit 0x180A 0x181A 0x183B**

service
-------

Set/Get advertise service data.

:Usage: **> service [uuid] [data=xx xx ...]**
:[uuid]: Service UUID
:[data=xx xx ...]: Service data
:Example Show current service data:
	| **> service**
:Example Set battery level to 100 (0x64):
	| **> service 0x180F 64**
:Example Set battery level to 50 (0x32):
	| **> service 0x180F 32**
:Example Set battery level to 0 (0x00):
	| **> service 0x180F 00**
:Example Set environmental data (temperature, humidity, pressure):
	| **> service 0x181A 20 15 C8 07**
:Example Set device information data:
	| **> service 0x180A 01 02 03 04**
:Example Set custom service data with 128-bit UUID:
	| **> service 12345678-1234-5678-9abc-123456789abc FF EE DD CC**

manufacturer
------------

Set/Get advertise manufacturer data.

Updating is in real time while advertising. This is currently limited to 25
bytes and will return an error message of "Too much data" if that maximum has
been exceeded. However, this does not check if the advertising payload length
maximum has been exceeded so you  may receive an error from bluetoothd that it
"Failed to register advertisement" which means you need to reduce your
manufacturer data length.

:Usage: **> manufacturer [id] [data=xx xx ...]**
:[id]: Manufacturer ID (default: 0x004C for Apple Inc.)
:[data=xx xx ...]: Manufacturer data
:Example Show current manufacturer data:
	| **> manufacturer**
:Example Set Apple Inc. manufacturer data:
	| **> manufacturer 0x004C 01 02 03 04**
:Example Set Apple manufacturer data with 8 bytes:
	| **> manufacturer 0x004C FF FE FD FC FB FA F9 F8**
:Example Set Microsoft Corp. manufacturer data:
	| **> manufacturer 0x0006 10 11 12 13**
:Example Set Samsung Electronics manufacturer data:
	| **> manufacturer 0x0075 AA BB CC DD EE**
:Example Set Google LLC manufacturer data:
	| **> manufacturer 0x00E0 01 23 45 67 89 AB CD EF**
:Example Set custom manufacturer ID with test data:
	| **> manufacturer 0xFFFF DE AD BE EF**

data
----

Set/Get advertise data.

This allows you to advertise data with a given type. You cannot use a registered
data type value {1} with  this command. For LE the advertising shows up in the
primary advertisements.

If you set only the type of the data without any data (data 0x0c) this will
cause a parse error when turning advertise on.

You can modify the advertising data while it is advertising.

To get the currently set data use the command data without any arguments.

:Usage: **> data [type] [data=xx xx ...]**
:[type]: Advertising data type
:[data=xx xx ...]: Advertising data (default: none)
:Example Show current advertising data:
	| **> data**
:Example Set slave connection interval range data:
	| **> data 0x0C 01 0x0F 13**
:Example Set complete local name to "Hello":
	| **> data 0x09 48 65 6C 6C 6F**
:Example Set shortened local name to "Test":
	| **> data 0x08 54 65 73 74**
:Example Set flags (LE General Discoverable + BR/EDR not supported):
	| **> data 0x01 06**
:Example Set appearance (keyboard, 0x0341):
	| **> data 0x19 41 03**
:Example Set TX power level to +4 dBm:
	| **> data 0x0A 04**
:Example Set TX power level to -4 dBm:
	| **> data 0x0A FC**
:Example Set URI "//google.com":
	| **> data 0x24 17 2F 2F 67 6F 6F 67 6C 65 2E 63 6F 6D**
:Example Set service data for Battery Service (UUID 0x180F, level 100):
	| **> data 0x16 0F 18 64**

sr-uuids
--------

Set/Get scan response uuids.

:Usage: **> sr-uuids [uuid1 uuid2 ...]**
:[uuid1 uuid2 ...]: List of UUIDs to advertise in scan response
:Example Show current scan response UUIDs:
	| **> sr-uuids**
:Example Set Generic Access in scan response:
	| **> sr-uuids 0x1800**
:Example Set Device Info and Battery services in scan response:
	| **> sr-uuids 0x180A 0x180F**
:Example Set custom UUID in scan response:
	| **> sr-uuids 12345678-1234-5678-9abc-123456789abc**

sr-solicit
----------

Set/Get scan response solicit uuids.

:Usage: **> sr-solicit [uuid1 uuid2 ...]**
:[uuid1 uuid2 ...]: List of UUIDs to advertise in scan response
:Example Show current scan response solicited UUIDs:
	| **> sr-solicit**
:Example Solicit Generic Attribute service in scan response:
	| **> sr-solicit 0x1801**

:Example Solicit Device Info and Environmental Sensing in scan response:
	| **> sr-solicit 0x180A 0x181A**

sr-service
----------

Set/Get scan response service data.

:Usage: **> sr-service [uuid] [data=xx xx ...]**
:[uuid]: Service UUID
:[data=xx xx ...]: Service data
:Example Show current scan response service data:
	| **> sr-service**
:Example Set battery level to 128 in scan response:
	| **> sr-service 0x180F 80**
:Example Set environmental data in scan response:
	| **> sr-service 0x181A 22 18 C0 05**
:Example Set device info "Hello" in scan response:
	| **> sr-service 0x180A 48 65 6C 6C 6F**

sr-manufacturer
---------------

Set/Get scan response manufacturer data.

:Usage: **> sr-manufacturer [id] [data=xx xx ...]**
:[id]: Manufacturer ID (default: 0x004C for Apple Inc.)
:[data=xx xx ...]: Manufacturer data
:Example Show current scan response manufacturer data:
	| **> sr-manufacturer**
:Example Set Apple manufacturer data in scan response:
	| **> sr-manufacturer 0x004C 05 06 07 08**
:Example Set Microsoft manufacturer data in scan response:
	| **> sr-manufacturer 0x0006 20 21 22 23**
:Example Set custom manufacturer data in scan response:
	| **> sr-manufacturer 0xFFFF CA FE BA BE**

sr-data
-------

Set/Get scan response data.

:Usage: **> sr-data [type] [data=xx xx ...]**
:[type]: Scan Response data type
:[data=xx xx ...]: Scan Response data
:Example Show current scan response data:
	| **> sr-data**
:Example Set complete local name "ScanResp" in scan response:
	| **> sr-data 0x09 53 63 61 6E 52 65 73 70**
:Example Set TX power level +8 dBm in scan response:
	| **> sr-data 0x0A 08**
:Example Set Battery service data (level 50) in scan response:
	| **> sr-data 0x16 0F 18 32**

discoverable
------------

Set/Get advertise discoverable.

For LE discoverable on will set the LE General Discoverable Mode flag to true in
the primary advertisement if on.

This feature can be changed during advertising, but will only trigger LE General
Discoverable Mode even if you had previously selected discoverable-timeout this
will be ignored.

Entering the command by itself will show the status of the setting

:Usage: **> discoverable [on/off]**
:[on/off]: Enable/Disable LE General Discoverable Mode
:Example Show current discoverable setting:
	| **> discoverable**
:Example Enable LE General Discoverable Mode:
	| **> discoverable on**
:Example Disable discoverable mode:
	| **> discoverable off**

discoverable-timeout
--------------------

Set/Get advertise discoverable timeout.

Using this feature in LE will cause the LE Limited Discoverable Mode flag to be
set in the primary advertisement and   The LE General Discoverable Mode flag
will not be set.

The LE Limited Discoverable Mode flag will automatically turn off after [seconds]
discoverable [on] must be set to use this feature.

Entering the command by itself will show the current value set.

:Usage: **> discoverable-timeout [seconds]**
:[seconds]: Timeout duration in seconds for LE Limited Discoverable Mode
:Example Show current discoverable timeout:
	| **> discoverable-timeout**
:Example Set LE Limited Discoverable for 30 seconds:
	| **> discoverable-timeout 30**
:Example Set LE Limited Discoverable for 2 minutes:
	| **> discoverable-timeout 120**
:Example Set LE Limited Discoverable for 5 minutes:
	| **> discoverable-timeout 300**
:Example Disable discoverable timeout (unlimited):
	| **> discoverable-timeout 0**

tx-power
--------

Show/Enable/Disable TX power to be advertised.

This sets the TX Power Level field in the advertising packet.

The value is in dBm and can be between -127 and 127.

When this feature is turned on the LE device will advertise its transmit power
in the primary advertisement.

This feature can be modified while advertising.

Entering the command by itself will show the current value set.

:Usage: **> tx-power [on/off]**
:[on/off]: Enable or disable TX power advertisement (optional, shows current if omitted)
:Example Show current TX power advertisement setting:
	| **> tx-power**
:Example Enable TX power advertisement with default power:
	| **> tx-power on**
:Example Disable TX power advertisement:
	| **> tx-power off**

name
----

Configure local name to be advertised.

Local name to be used in the advertising report.

If the string is too big to fit into the packet it will be truncated.

It will either advertise as a complete local name or if it has to be truncated
then a shortened local name.

:Usage: **> name [on/off/name]**
:[name]: Local name (optional, shows current if omitted)
:Example Show current advertised name setting:
	| **> name**
:Example Enable advertising the system hostname:
	| **> name on**
:Example Disable name advertisement:
	| **> name off**
:Example Advertise "My Device" as local name:
	| **> name "My Device"**
:Example Advertise "Smart Sensor" as local name:
	| **> name "Smart Sensor"**
:Example Advertise device with ID suffix:
	| **> name "BLE-Peripheral-001"**
:Example Advertise long name (will be truncated to fit):
	| **> name "0123456789abcdef0123456789abcdef"**
:Example Long descriptive name (automatically truncated):
	| **> name "This is a very long device name that will be truncated"**
:Example Name with special characters:
	| **> name "Device™"**
:Example Name with accented characters:
	| **> name "Tëst-Dëvicë"**

appearance
----------

Configure custom appearance to be advertised.

:Usage: **> appearance [on/off/value]**
:[value]: Appearance value (optional, shows current if omitted)
:Example Show current appearance setting:
	| **> appearance**
:Example Enable appearance advertisement with default value:
	| **> appearance on**
:Example Disable appearance advertisement:
	| **> appearance off**
:Example Set appearance to keyboard (0x03C1):
	| **> appearance 961**
:Example Set appearance to mouse (0x03C2):
	| **> appearance 962**
:Example Set appearance to joystick (0x03C3):
	| **> appearance 963**
:Example Set appearance to gamepad (0x03C4):
	| **> appearance 964**
:Example Set appearance to generic audio sink (0x0340):
	| **> appearance 832**
:Example Set appearance to speaker (0x0341):
	| **> appearance 833**
:Example Set appearance to microphone (0x0342):
	| **> appearance 834**
:Example Set appearance to headset (0x0343):
	| **> appearance 835**
:Example Set appearance to headphones (0x0344):
	| **> appearance 836**
:Example Set appearance to heart rate sensor (0x0540):
	| **> appearance 1344**
:Example Set appearance to thermometer (0x05C0):
	| **> appearance 1472**
:Example Set appearance to glucose meter (0x0640):
	| **> appearance 1600**
:Example Set appearance to generic phone (0x0040):
	| **> appearance 64**
:Example Set appearance to generic computer (0x0080):
	| **> appearance 128**
:Example Set appearance to generic watch (0x00C0):
	| **> appearance 192**

duration
--------

Set/Get advertise duration.

The Duration parameter configures the length of an Instance.

The value is in seconds.

A value of 0 indicates a default value is chosen for the Duration.

The default is 2 seconds.

If only one advertising Instance has been added, then the Duration value will be
ignored.

If multiple advertising Instances have been added, then the Duration value will
be used to determine the length of time each Instance is advertised for.

The Duration value is used to calculate the number of advertising events that
will be used to advertise each Instance.

The number of advertising events is calculated by dividing the Duration value by
the advertising interval.

The advertising interval is determined by the advertising parameters that are
set for each Instance. The advertising interval is the maximum of the
advertising intervals set for each Instance.

:Usage: **> duration [seconds]**
:[seconds]: Duration in seconds (optional, shows current if omitted)
:Example Show current advertising duration setting:
	| **> duration**
:Example Use default duration (2 seconds):
	| **> duration 0**
:Example Set duration to 1 second:
	| **> duration 1**
:Example Set duration to 5 seconds:
	| **> duration 5**
:Example Set duration to 10 seconds:
	| **> duration 10**
:Example Set duration to 30 seconds:
	| **> duration 30**
:Example Set duration to 1 minute:
	| **> duration 60**
:Example Set duration to 5 minutes:
	| **> duration 300**

timeout
-------

Set/Get advertise timeout.

:Usage: **> timeout [seconds]**
:[seconds]: Timeout in seconds (optional, shows current if omitted)
:Example Show current advertising timeout setting:
	| **> timeout**
:Example Unlimited advertising (no timeout):
	| **> timeout 0**
:Example Stop advertising after 30 seconds:
	| **> timeout 30**
:Example Stop advertising after 2 minutes:
	| **> timeout 120**
:Example Stop advertising after 1 hour:
	| **> timeout 3600**

secondary
---------

Set/Get advertise secondary channel.

:Usage: **> secondary [1M/2M/Coded]**
:[1M/2M/Coded]: Secondary channel (optional, shows current if omitted)
:Example Show current secondary channel setting:
	| **> secondary**
:Example Use LE 1M PHY for secondary advertising channel:
	| **> secondary 1M**
:Example Use LE 2M PHY for secondary advertising channel:
	| **> secondary 2M**
:Example Use LE Coded PHY for secondary advertising channel:
	| **> secondary Coded**

rsi
---

Show/Enable/Disable RSI to be advertised.

RSI (Resolvable Set Identifier) is used to advertise a resolvable identifier
for Coordinated Set Identification.

:Usage: **> rsi [on/off]**
:[on/off]: Enable or disable RSI advertisement (optional, shows current if omitted)
:Example Show current RSI setting:
	| **> rsi**
:Example Enable RSI advertisement:
	| **> rsi on**
:Example Disable RSI advertisement:
	| **> rsi off**

interval
--------

Set/Get advertise interval.

The Interval parameter configures the advertising interval of an Instance.

The value is in milliseconds.

A value of 0 indicates a default value is chosen for the Interval.

The default is 100 milliseconds.

The Interval value is used to calculate the number of advertising events that
will be used to advertise each Instance.

The number of advertising events is calculated by dividing the Duration value by
the advertising interval.

The advertising interval is determined by the advertising parameters that are
set for each Instance.

The advertising interval is the maximum of the advertising intervals set for
each Instance.

:Usage: **> interval [min] [max]**
:[min]: Minimum advertising interval in milliseconds (optional, shows current if omitted)
:[max]: Maximum advertising interval in milliseconds (optional, defaults to min value)
:Example Show current advertising interval setting:
	| **> interval**
:Example Set minimum advertising interval (20ms):
	| **> interval 20**
:Example Set advertising interval range (50-100ms):
	| **> interval 50 100**
:Example Set normal advertising interval (100ms):
	| **> interval 100**
:Example Set moderate advertising interval (200ms):
	| **> interval 200**
:Example Set slow advertising interval (500ms):
	| **> interval 500**
:Example Set very slow advertising interval (1 second):
	| **> interval 1000**
:Example Set maximum advertising interval (10.24 seconds):
	| **> interval 10240**

clear
-----

Clear advertise config.

This will stop advertising if it is currently advertising.

If you want to change the advertise configuration while advertising you must
first clear the advertise configuration and then set the new advertise
configuration.

:Usage: **> clear [uuids/service/manufacturer/config-name...]**
:[uuids/service/manufacturer/config-name...]: List of configuration to clear
:Example Clear all advertising configuration:
	| **> clear**
:Example Clear only advertised UUIDs:
	| **> clear uuids**
:Example Clear only service data:
	| **> clear service**
:Example Clear only manufacturer data:
	| **> clear manufacturer**
:Example Clear only advertised name:
	| **> clear name**
:Example Clear only appearance data:
	| **> clear appearance**
:Example Clear only TX power advertisement:
	| **> clear tx-power**
:Example Clear UUIDs and service data:
	| **> clear uuids service**
:Example Clear manufacturer data and name:
	| **> clear manufacturer name**
:Example Clear UUIDs, service data, and manufacturer data:
	| **> clear uuids service manufacturer**
:Example Clear discoverable mode and TX power:
	| **> clear discoverable tx-power**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

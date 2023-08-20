==============================
bluetoothctl-advertise-options
==============================

-------------------------
Advertise Options Submenu
-------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========
bluetoothctl advertise options submenu can be accessed by the command `menu advertise` in bluetoothctl. If the error "Failed to register advertisement: org.bluez.Error.Failed" is received then check /var/log/syslog for the specific error such as "Advertising data too long or couldn't be generated.". Assuming bluetoothd has the -v option set.

Advertise Options Commands
==========================

Advertising packets are structured data which is broadcast on the LE Advertising
channels and available for all devices in range.  Because of the limited space
available in LE Advertising packets (31 bytes), each packet's contents must be
carefully controlled.

This is a long form description of the commands that includes examples. Values can either be hexadecimal (0x0C)
decimal (12) or octal if  a leading zero (07). Footnotes are indicated by {x} and can be found at the bottom of the page.


uuids
-----
Set/Get advertise uuids
  The assumed format of the uuid is hex. Therefore uuids 0x1234 identical to uuids 1234.
  The valid uuids are:
  - 16 bit uuids - ex: uuids 0x1234
  - 32 bit uuids - ex: uuids 0x12345678
  - 128 bit uuids - ex: uuids 90f95193-35de-4306-a6e9-699328f15059

    .. note:: 128 bit uuids must be in the format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx where x is a hexadecimal digit and the dashes are included.

:Usage: **# uuids [all/uuid1 uuid2 ...]**

service
-------
Set/Get advertise service data

:Usage: **# service [uuid] [data=xx xx ...]**

manufacturer
------------
Set/Get advertise manufacturer data
  updating is in real time while advertising. This is currently limited to 25 bytes and will return an error message of "Too much data"
  if that maximum has been exceeded. However, this does not check if the advertising payload length maximum has been exceeded so you 
  may receive an error from bluetoothd that it "Failed to register advertisement" which means you need to reduce your manufacturer data length.

:Usage: **# manufacturer [id] [data=xx xx ...]**

data
----
Set/Get advertise data
  This allows you to advertise data with a given type. You cannot use a registered data type value {1} with 
  this command. For LE the advertising shows up in the primary advertisements
  Example: Advertises a nonregistered data type of 0x0C with three octets of data (01 0x0F 13)::

    data 0x0C 01 0x0F 13

  If you set only the type of the data without any data (data 0x0c) this will cause a parse error when turning advertise on.
  You can only send a maximum of 8 bytes of data. data 0x0c 00 01 02 03 04 05 06 07
  You can modify the advertising data while it is advertising 
  To get the currently set data use the command data without any arguments
  To delete the currently set data you need to...   (clear does not appear to work)

:Usage: **# data [type] [data=xx xx ...]**

discoverable
------------
Set/Get advertise discoverable
  For LE discoverable on will set the LE General Discoverable Mode flag to true in the primary advertisement if on.
  This feature can be changed during advertising, but will only trigger LE General Discoverable Mode even if you had previously selected 
  discoverable-timeout this will be ignored.
  Entering the command by itself will show the status of the setting

:Usage: **# discoverable [on/off]**

discoverable-timeout
--------------------
Set/Get advertise discoverable timeout
  Using this feature in LE will cause the LE Limited Discoverable Mode flag to be set in the primary advertisement and 
  The LE General Discoverable Mode flag will not be set. The LE Limited Discoverable Mode flag will automatically turn off after [seconds]
  discoverable [on] must be set to use this feature
  Entering the command by itself will show the time value

:Usage: **# discoverable-timeout [seconds]**

tx-power
--------
Show/Enable/Disable TX power to be advertised
  This sets the TX Power Level field in the advertising packet. The value is in dBm and can be between -127 and 127.
  Entering the command by itself will show the current value
  When this feature is turned on the LE device will advertise its transmit power in the primary advertisement
  This feature can be modified while advertising.
  Entering the command by itself will show the status of the setting

:Usage: **# tx-power [on/off] [power]**

name
----
Configure local name to be advertised
  Local name to be used in the advertising report. If the string is too big to fit into the packet it will be truncated.
  It will either advertise as a complete local name or if it has to be truncated then a shortened local name
  advertise.name "0123456789abcdef0123456789abcdef"
  Text: 0123456789abcdef0123456789abc
  There does not appear to be a way to tell if it is advertising with a complete or shortened local name.

:Usage: **# name [on/off/name]**

appearance
----------
Configure custom appearance to be advertised

:Usage: **# appearance [on/off/value]**

duration
--------
Set/Get advertise duration
  The Duration parameter configures the length of an Instance. The value is in seconds.
  A value of 0 indicates a default value is chosen for the Duration. The default is 2 seconds.
  If only one advertising Instance has been added, then the Duration value will be ignored.
  If multiple advertising Instances have been added, then the Duration value will be used to determine the length of time
  each Instance is advertised for. The Duration value is used to calculate the number of advertising events that will be
  used to advertise each Instance. The number of advertising events is calculated by dividing the Duration value by the
  advertising interval. The advertising interval is determined by the advertising parameters that are set for each
  Instance. The advertising interval is the maximum of the advertising intervals set for each Instance.
  The Duration value is used to calculate the number of advertising events that will be used to advertise each Instance.
  The number of advertising events is calculated by dividing the Duration value by the advertising interval. The advertising
  interval is determined by the advertising parameters that are set for each Instance. The advertising interval is the maximum
  of the advertising intervals set for each Instance.
  The Duration value is used to calculate the number of advertising events that will be used to advertise each Instance.
  The number of advertising events is calculated by dividing the Duration value by the advertising interval. The advertising
  interval is determined by the advertising parameters that are set for each Instance. The advertising interval is the maximum
  of the advertising intervals set for each Instance.
  The Duration value is used to calculate the number of advertising events that will be used to advertise each Instance.
  The number of advertising events is calculated by dividing the Duration value by the advertising interval. The advertising
  interval is determined by the advertising parameters that are set for each Instance. The advertising interval is the maximum
  of the advertising intervals set for each Instance.
  The Duration value is used to calculate the number of advertising events that will be used to advertise each Instance.
  The number of advertising events is calculated by dividing the Duration value by the advertising interval. The advertising
  interval is determined by the advertising parameters that are set for each Instance. The advertising interval is the maximum
  of the advertising intervals set for each Instance.
  The Duration value is used to calculate the number of advertising events that will be used to advertise each Instance.
  The number of advertising events is
  calculated by dividing the Duration value by the advertising interval. The advertising interval is determined by the
  advertising parameters that are set for each Instance. The advertising interval is the maximum of the advertising intervals
  set for each Instance.

:Usage: **# duration [seconds]**

timeout
-------
  Set/Get advertise timeout

:Usage: **# timeout [seconds]**

secondary
---------
  Set/Get advertise secondary channel
  The Secondary parameter configures the secondary channel used for advertising.

:Usage: **# secondary [1M/2M/Coded]**        

interval
--------
Set/Get advertise interval
  The Interval parameter configures the advertising interval of an Instance. The value is in milliseconds.
  A value of 0 indicates a default value is chosen for the Interval. The default is 100 milliseconds.
  The Interval value is used to calculate the number of advertising events that will be used to advertise each Instance.
  The number of advertising events is calculated by dividing the Duration value by the advertising interval. The advertising
  interval is determined by the advertising parameters that are set for each Instance. The advertising interval is the maximum
  of the advertising intervals set for each Instance.

:Usage: **# interval [milliseconds]**

clear
-----
Clear advertise config
  Clear the advertise configuration. This will stop advertising if it is currently advertising.
  If you want to change the advertise configuration while advertising you must first clear the advertise configuration
  and then set the new advertise configuration.

:Usage: **# clear [uuids/service/manufacturer/config-name...]**

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

NOTES
=====
A byte is defined as an octet
{1}  `Generic Access Profile Assigned Numbers document <https://btprodspecificationrefs.blob.core.windows.net/assigned-numbers/Assigned%20Number%20Types/Generic%20Access%20Profile.pdf>`

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

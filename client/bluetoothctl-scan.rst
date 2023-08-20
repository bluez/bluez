=================
bluetoothctl-scan
=================

------------
Scan Submenu
------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: July 2023
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [**-a** *capability*] [**-e**] [**-m**] [**-t** *seconds*] [**-v**] [**-h**] [scan.commands]

OPTIONS
=======

-a capability, --agent capability        Register agent handler: <capability>
-e, --endpoints                  Register Media endpoints
-m, --monitor                    Enable monitor output
-t seconds, --timeout seconds    Timeout in seconds for non-interactive mode
-v, --version       Display version
-h, --help          Display help

Scan Commands
=============
   The scan commands control options numbers for the commands can be hex (0x0F) or decimal (10)
   
uuids
-----
Set/Get UUIDs filter

:Usage: **# uuids [all/uuid1 uuid2 ...]**

rssi
----
Set/Get RSSI filter, and clears pathloss
This sets the minimum rssi value for reporting device advertisements. The value is in dBm.
Example: To only show devices with rssi values greater than or equal to -60 dBm, use `scan.rssi -60`.
If one or more discovery filters have been set, the RSSI delta-threshold imposed by starting discovery by default will not be applied.

:Usage: **# rssi [rssi]**

pathloss
--------
Set/Get Pathloss filter, and clears RSSI
This sets the maximum pathloss value for reporting device advertisements. The value is in dB.
Example: To only show devices with pathloss values less than or equal to 4 dB, use `scan.pathloss 4`.
If one or more discovery filters have been set, the RSSI delta-threshold imposed by starting discovery by default will not be applied.

:Usage: **# pathloss [pathloss]**

transport
---------
Set/Get transport filter
Transport parameter determines the type of scan. The default is auto.

Possible values:

- "auto": interleaved scan
- "bredr": BR/EDR inquiry
- "le": LE scan only

If "le" or "bredr" Transport is requested and the controller doesn't support it, an org.bluez.Error.Failed error will be returned. If "auto" transport is requested, the scan will use LE, BREDR, or both, depending on what's currently enabled on the controller. 

duplicate-data
--------------
Set/Get duplicate data filter
Disables duplicate detection of advertisement data. When enabled, PropertiesChanged signals will be generated for ManufacturerData and ServiceData every time they are discovered.

:Usage: **# duplicate-data [on/off]**

discoverable
------------
Set/Get discoverable filter
Makes the adapter discoverable while discovering. If the adapter is already discoverable, setting this filter won't have any effect.

:Usage: **# discoverable [on/off]**

pattern
-------
Set/Get pattern filter
Discover devices where the pattern matches either the prefix of the address or the device name, which is a convenient way to limit the number of device objects created during a discovery.
When set, it disregards device discoverable flags.
Note: The pattern matching is ignored if there are other clients that don't set any pattern, as it works as a logical OR. Also, setting an empty string "" pattern will match any device found.

:Usage: **# pattern [value]**


clear
-----
Clears discovery filter

:Usage: **# clear [uuids/rssi/pathloss/transport/duplicate-data/discoverable/pattern]**

back
----
Return to the main menu

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

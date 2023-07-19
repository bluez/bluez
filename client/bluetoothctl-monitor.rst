====================
bluetoothctl-monitor
====================

---------------
Monitor Submenu
---------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: July 2023
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [monitor.commands]

Monitor Commands
================

set-rssi-threshold
------------------

Set RSSI threshold parameter

:Usage: **# set-rssi-threshold <low_threshold> <high_threshold>**

set-rssi-timeout
----------------

Set RSSI timeout parameter

:Usage: **# set-rssi-timeout <low_timeout> <high_timeout>**

set-rssi-sampling-period
-------------------------

Set RSSI sampling period parameter

:Usage: **# set-rssi-timeout <low_timeout> <high_timeout>**

add-or-pattern
--------------

Register 'or pattern' type monitor with the specified RSSI parameters

:Usage: **# add-or-pattern [patterns=pattern1 pattern2 ...]**

get-pattern
-----------

Get advertisement monitor

:Usage: **# get-pattern <monitor-id/all>**

remove-pattern
--------------

Remove advertisement monitor

:Usage: **# remove-pattern <monitor-id/all>**

get-supported-info
------------------

Get advertisement manager supported features and supported monitor types

:Usage: **# get-supported-info**

print-usage
-----------

Print the command usage

:Usage: **# print-usage <add-or-pattern>**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org


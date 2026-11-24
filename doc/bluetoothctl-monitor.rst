====================
bluetoothctl-monitor
====================

---------------
Monitor Submenu
---------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: July 2023
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [monitor.commands]

This submenu configures advertisement monitors using the
**org.bluez.AdvertisementMonitor(5)** and
**org.bluez.AdvertisementMonitorManager(5)** interfaces.

Monitor Commands
================

set-rssi-threshold
------------------

Set RSSI threshold parameter

:Usage: **> set-rssi-threshold <low_threshold> <high_threshold>**
:<low_threshold>: Lower RSSI threshold value in dBm for monitoring
:<high_threshold>: Higher RSSI threshold value in dBm for monitoring
:Example Set low threshold to -80 dBm and high threshold to -40 dBm:
	| **> set-rssi-threshold -80 -40**
:Example Set low threshold to -70 dBm and high threshold to -30 dBm:
	| **> set-rssi-threshold -70 -30**
:Example Set very sensitive low threshold and moderate high threshold:
	| **> set-rssi-threshold -90 -50**
:Example Set less sensitive thresholds for close range monitoring:
	| **> set-rssi-threshold -60 -20**

set-rssi-timeout
----------------

Set RSSI timeout parameter

:Usage: **> set-rssi-timeout <low_timeout> <high_timeout>**
:<low_timeout>: Timeout value in seconds for low RSSI threshold
:<high_timeout>: Timeout value in seconds for high RSSI threshold
:Example Set low timeout to 5 seconds, high timeout to 10 seconds:
	| **> set-rssi-timeout 5 10**
:Example Set quick timeout response for both thresholds:
	| **> set-rssi-timeout 1 5**
:Example Set longer timeout periods for stable monitoring:
	| **> set-rssi-timeout 10 30**
:Example Set asymmetric timeout values:
	| **> set-rssi-timeout 3 15**

set-rssi-sampling-period
-------------------------

Set RSSI sampling period parameter

:Usage: **> set-rssi-sampling-period <sampling_period>**
:<sampling_period>: Sampling period in 100ms units (0-255, where 0 means report all, 255 means report only first)
:Example Set sampling period to 100ms (1 unit):
	| **> set-rssi-sampling-period 1**
:Example Set sampling period to 500ms (5 units):
	| **> set-rssi-sampling-period 5**
:Example Set sampling period to 1 second (10 units):
	| **> set-rssi-sampling-period 10**
:Example Report all advertisements (no sampling):
	| **> set-rssi-sampling-period 0**
:Example Report only first advertisement:
	| **> set-rssi-sampling-period 255**

add-or-pattern
--------------

Register 'or pattern' type monitor with the specified RSSI parameters

Each pattern requires 3 arguments: <start_position> <ad_data_type> <content_of_pattern>
Multiple patterns can be specified to create an OR condition.

:Usage: **> add-or-pattern <start_pos> <ad_type> <content> [start_pos ad_type content ...]**
:Uses: **org.bluez.AdvertisementMonitorManager(5)** method **RegisterMonitor**
:<start_pos>: Byte position in advertisement data where pattern matching starts (0-based)
:<ad_type>: Advertisement data type (e.g., 9 for Complete Local Name, 1 for Flags)
:<content>: Hexadecimal pattern content to match
:Example Monitor for "Samsung" in Complete Local Name (type 9):
	| **> add-or-pattern 0 9 53616d73756e67**
:Example Monitor for devices with Flags type (type 1) containing 0x06:
	| **> add-or-pattern 0 1 06**
:Example Monitor for two different patterns (OR condition):
	| **> add-or-pattern 0 9 53616d73756e67 0 9 4170706c65**
:Example Monitor for specific manufacturer data (type 255):
	| **> add-or-pattern 0 255 4c000215**

get-pattern
-----------

Get advertisement monitor

:Usage: **> get-pattern <monitor-id/all>**
:<monitor-id/all>: Monitor ID number to retrieve details for, or "all" for all active monitors
:Example Get details of monitor ID 0:
	| **> get-pattern 0**
:Example Get details of monitor ID 1:
	| **> get-pattern 1**
:Example Get details of monitor ID 5:
	| **> get-pattern 5**
:Example Get details of all active monitors:
	| **> get-pattern all**

remove-pattern
--------------

Remove advertisement monitor

:Usage: **> remove-pattern <monitor-id/all>**
:Uses: **org.bluez.AdvertisementMonitorManager(5)** method **UnregisterMonitor**
:<monitor-id/all>: Monitor ID number to remove, or "all" to remove all active monitors
:Example Remove monitor with ID 0:
	| **> remove-pattern 0**
:Example Remove monitor with ID 1:
	| **> remove-pattern 1**
:Example Remove monitor with ID 3:
	| **> remove-pattern 3**
:Example Remove all active advertisement monitors:
	| **> remove-pattern all**

get-supported-info
------------------

Get advertisement manager supported features and supported monitor types

:Usage: **> get-supported-info**
:Uses: **org.bluez.AdvertisementMonitorManager(5)** properties
:Example Display supported monitor features and types:
	| **> get-supported-info**

print-usage
-----------

Print the command usage

:Usage: **> print-usage <add-or-pattern>**
:<add-or-pattern>: Command name to display detailed usage information for
:Example Show detailed usage for add-or-pattern command:
	| **> print-usage add-or-pattern**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

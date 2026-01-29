=================
bluetoothctl-mgmt
=================

------------------
Management Submenu
------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: July 2023
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [mgmt.commands]

Mgmt Commands
=============

select
------

Select a different index

:Usage: **> select <index>**
:<index>: Controller index number (0-based) to select
:Example Select controller index 0 (hci0):
	| **> select 0**
:Example Select controller index 1 (hci1):
	| **> select 1**
:Example Select controller index 2 (hci2):
	| **> select 2**

revision
--------

Get the MGMT Revision

:Usage: **> revision**
:Example Display MGMT API revision information:
	| **> revision**

commands
--------

List supported commands

:Usage: **> commands**
:Example List all supported management commands:
	| **> commands**

config
------

Show configuration info

:Usage: **> config**
:Example Show current controller configuration:
	| **> config**

info
----

Show controller info

:Usage: **> info**
:Example Show detailed controller information:
	| **> info**

extinfo
-------

Show extended controller info

:Usage: **> extinfo**
:Example Show extended controller information:
	| **> extinfo**

auto-power
----------

Power all available features

:Usage: **> auto-power**
:Example Automatically power on all available controller features:
	| **> auto-power**

power
-----

Toggle powered state

:Usage: **> power <on/off>**
:<on/off>: Power state - "on" to enable controller, "off" to disable
:Example Power on the controller:
	| **> power on**
:Example Power off the controller:
	| **> power off**

discov
------

Toggle discoverable state

:Usage: **> discov <yes/no/limited> [timeout]**
:<yes/no/limited>: Discoverable mode - "yes" for general, "no" to disable, "limited" for limited discoverable
:[timeout]: Optional timeout in seconds for discoverable mode duration
:Example Make controller discoverable indefinitely:
	| **> discov yes**
:Example Make controller non-discoverable:
	| **> discov no**
:Example Enable limited discoverable mode:
	| **> discov limited**
:Example Make discoverable for 30 seconds:
	| **> discov yes 30**
:Example Make discoverable for 2 minutes:
	| **> discov yes 120**
:Example Make discoverable for 5 minutes:
	| **> discov yes 300**
:Example Limited discoverable for 60 seconds:
	| **> discov limited 60**

connectable
-----------

Toggle connectable state

:Usage: **> connectable <on/off>**
:<on/off>: Connectable state - "on" to allow connections, "off" to reject
:Example Make controller connectable:
	| **> connectable on**
:Example Make controller non-connectable:
	| **> connectable off**

fast-conn
---------

Toggle fast connectable state

:Usage: **> fast-conn <on/off>**
:<on/off>: Fast connectable state - "on" to enable fast connection mode, "off" to disable
:Example Enable fast connectable mode:
	| **> fast-conn on**
:Example Disable fast connectable mode:
	| **> fast-conn off**

bondable
--------

Toggle bondable state

:Usage: **> bondable <on/off>**
:<on/off>: Bondable state - "on" to enable bonding capability, "off" to disable
:Example Enable bonding capability:
	| **> bondable on**
:Example Disable bonding capability:
	| **> bondable off**

pairable
--------

Toggle bondable state

:Usage: **> pairable <on/off>**
:<on/off>: Pairable state - "on" to enable pairing capability, "off" to disable
:Example Enable pairing capability:
	| **> pairable on**
:Example Disable pairing capability:
	| **> pairable off**

linksec
-------

Toggle link level security

:Usage: **> linksec <on/off>**
:<on/off>: Link level security - "on" to enable, "off" to disable
:Example Enable link level security:
	| **> linksec on**
:Example Disable link level security:
	| **> linksec off**

ssp
---

Toggle SSP mode

:Usage: **> ssp <on/off>**
:<on/off>: Secure Simple Pairing mode - "on" to enable SSP, "off" to disable
:Example Enable Secure Simple Pairing:
	| **> ssp on**
:Example Disable Secure Simple Pairing:
	| **> ssp off**

sc
--

Toggle SC support

:Usage: **> sc <on/off/only>**
:<on/off/only>: Secure Connections support - "on" to enable, "off" to disable, "only" for exclusive use
:Example Enable Secure Connections support:
	| **> sc on**
:Example Disable Secure Connections support:
	| **> sc off**
:Example Use Secure Connections exclusively:
	| **> sc only**

hs
--

Toggle HS support

:Usage: **> hs <on/off>**
:<on/off>: High Speed support - "on" to enable 802.11 High Speed, "off" to disable
:Example Enable High Speed support:
	| **> hs on**
:Example Disable High Speed support:
	| **> hs off**

le
--

Toggle LE support

:Usage: **> le <on/off>**
:<on/off>: Low Energy support - "on" to enable LE functionality, "off" to disable
:Example Enable Low Energy support:
	| **> le on**
:Example Disable Low Energy support:
	| **> le off**

advertising
-----------

Toggle LE advertising

:Usage: **> advertising <on/off>**
:<on/off>: LE advertising state - "on" to enable advertising, "off" to disable
:Example Enable LE advertising:
	| **> advertising on**
:Example Disable LE advertising:
	| **> advertising off**

bredr
-----

Toggle BR/EDR support

:Usage: **> bredr <on/off>**
:<on/off>: BR/EDR support - "on" to enable Classic Bluetooth, "off" to disable
:Example Enable BR/EDR (Classic Bluetooth) support:
	| **> bredr on**
:Example Disable BR/EDR support:
	| **> bredr off**

privacy
-------

Toggle privacy support

:Usage: **> privacy <on/off> [irk]**
:<on/off>: Privacy support - "on" to enable privacy features, "off" to disable
:[irk]: Optional 32-character hexadecimal Identity Resolving Key
:Example Enable privacy with auto-generated IRK:
	| **> privacy on**
:Example Disable privacy:
	| **> privacy off**
:Example Enable privacy with specific IRK:
	| **> privacy on 0123456789abcdef0123456789abcdef**
:Example Enable privacy with different IRK:
	| **> privacy on 1234567890abcdef1234567890abcdef**

class
-----

Set device major/minor class

:Usage: **> class <major> <minor>**
:<major>: Major device class code (hexadecimal)
:<minor>: Minor device class code (hexadecimal)
:Example Set class to Audio/Video - Wearable Headset:
	| **> class 0x04 0x01**
:Example Set class to Audio/Video - Hands-free:
	| **> class 0x04 0x02**
:Example Set class to Audio/Video - Headphones:
	| **> class 0x04 0x06**
:Example Set class to Audio/Video - VCR:
	| **> class 0x04 0x0B**
:Example Set class to Computer - Desktop workstation:
	| **> class 0x01 0x01**
:Example Set class to Computer - Server:
	| **> class 0x01 0x02**
:Example Set class to Computer - Laptop:
	| **> class 0x01 0x03**
:Example Set class to Computer - Handheld PC/PDA:
	| **> class 0x01 0x04**
:Example Set class to Phone - Cellular:
	| **> class 0x02 0x01**
:Example Set class to Phone - Cordless:
	| **> class 0x02 0x02**
:Example Set class to Phone - Smart phone:
	| **> class 0x02 0x03**

disconnect
----------

Disconnect device

:Usage: **> disconnect [-t type] <remote address>**
:[-t type]: Optional address type (public, random, le_public, le_random)
:<remote address>: Bluetooth address of device to disconnect
:Example Disconnect device using public address:
	| **> disconnect 00:11:22:33:44:55**
:Example Disconnect another device:
	| **> disconnect AA:BB:CC:DD:EE:FF**
:Example Disconnect device with public address type:
	| **> disconnect -t public 00:11:22:33:44:55**
:Example Disconnect device with random address type:
	| **> disconnect -t random AA:BB:CC:DD:EE:FF**
:Example Disconnect LE device with public address:
	| **> disconnect -t le_public 11:22:33:44:55:66**
:Example Disconnect LE device with random address:
	| **> disconnect -t le_random CC:DD:EE:FF:00:11**

con
---

List connections

:Usage: **> con**
:Example List all active connections:
	| **> con**

find
----

Discover nearby devices

:Usage: **> find [-l|-b] [-L]**
:[-l|-b]: Discovery type - "-l" for LE only, "-b" for BR/EDR only (default: both)
:[-L]: Limited discovery mode flag
:Example Discover both LE and BR/EDR devices:
	| **> find**
:Example Discover LE devices only:
	| **> find -l**
:Example Discover BR/EDR devices only:
	| **> find -b**
:Example Discover devices in limited mode:
	| **> find -L**
:Example Discover LE devices in limited mode:
	| **> find -l -L**
:Example Discover BR/EDR devices in limited mode:
	| **> find -b -L**

find-service
------------

Discover nearby service

:Usage: **> find-service [-u UUID] [-r RSSI_Threshold] [-l|-b]**
:[-u UUID]: Service UUID to search for (16-bit, 32-bit, or 128-bit)
:[-r RSSI_Threshold]: Minimum RSSI value in dBm for device filtering
:[-l|-b]: Discovery type - "-l" for LE only, "-b" for BR/EDR only
:Example Find devices with Generic Access service:
	| **> find-service -u 0x1800**
:Example Find devices with Battery Service:
	| **> find-service -u 0x180F**
:Example Find devices with custom service:
	| **> find-service -u 12345678-1234-5678-9abc-123456789abc**
:Example Find devices with RSSI ≥ -60 dBm:
	| **> find-service -r -60**
:Example Find devices with RSSI ≥ -80 dBm:
	| **> find-service -r -80**
:Example Find Battery Service devices with RSSI ≥ -70 dBm:
	| **> find-service -u 0x180F -r -70**
:Example Find Generic Access on LE devices with strong signal:
	| **> find-service -u 0x1800 -r -50 -l**
:Example Find Serial Port Profile on BR/EDR devices:
	| **> find-service -u 0x1101 -b**
:Example Find Battery Service on LE devices:
	| **> find-service -u 0x180F -l**

stop-find
---------

Stop discovery

:Usage: **> stop-find [-l|-b]**
:[-l|-b]: Discovery type to stop - "-l" for LE only, "-b" for BR/EDR only (default: all)
:Example Stop all discovery:
	| **> stop-find**
:Example Stop LE discovery only:
	| **> stop-find -l**
:Example Stop BR/EDR discovery only:
	| **> stop-find -b**

name
----

Set local name

:Usage: **> name <name> [shortname]**
:<name>: Complete local name for the controller
:[shortname]: Optional shortened local name
:Example Set complete local name:
	| **> name "My Bluetooth Device"**
:Example Set name without spaces:
	| **> name MyComputer**
:Example Set name with hyphens:
	| **> name "Home-Office-PC"**
:Example Set both complete and shortened names:
	| **> name "My Long Device Name" MyDevice**
:Example Set descriptive and short names:
	| **> name "Professional Workstation" ProWork**
:Example Set audio device names:
	| **> name "Bluetooth Audio Headset" BT-Audio**

pair
----

Pair with a remote device

:Usage: **> pair [-c cap] [-t type] <remote address>**
:[-c cap]: IO capability (DisplayOnly, DisplayYesNo, KeyboardOnly, NoInputNoOutput, KeyboardDisplay)
:[-t type]: Address type (public, random, le_public, le_random)
:<remote address>: Bluetooth address of device to pair with
:Example Pair with device using default settings:
	| **> pair 00:11:22:33:44:55**
:Example Pair with another device:
	| **> pair AA:BB:CC:DD:EE:FF**
:Example Pair with display-only IO capability:
	| **> pair -c DisplayOnly 00:11:22:33:44:55**
:Example Pair with display and yes/no capability:
	| **> pair -c DisplayYesNo AA:BB:CC:DD:EE:FF**
:Example Pair with keyboard-only capability:
	| **> pair -c KeyboardOnly 11:22:33:44:55:66**
:Example Pair with no I/O capability:
	| **> pair -c NoInputNoOutput CC:DD:EE:FF:00:11**
:Example Pair with keyboard and display capability:
	| **> pair -c KeyboardDisplay 22:33:44:55:66:77**
:Example Pair with public address device:
	| **> pair -t public 00:11:22:33:44:55**
:Example Pair with random address device:
	| **> pair -t random AA:BB:CC:DD:EE:FF**
:Example Pair with LE public address device:
	| **> pair -t le_public 11:22:33:44:55:66**
:Example Pair with LE random address device:
	| **> pair -t le_random CC:DD:EE:FF:00:11**
:Example Pair LE device with keyboard/display capability:
	| **> pair -c KeyboardDisplay -t le_public 00:11:22:33:44:55**
:Example Pair random address device with display/yes-no capability:
	| **> pair -c DisplayYesNo -t random AA:BB:CC:DD:EE:FF**

cancelpair
----------

Cancel pairing

:Usage: **> cancelpair [-t type] <remote address>**
:[-t type]: Address type (public, random, le_public, le_random)
:<remote address>: Bluetooth address of device to cancel pairing with
:Example Cancel ongoing pairing with device:
	| **> cancelpair 00:11:22:33:44:55**
:Example Cancel pairing with another device:
	| **> cancelpair AA:BB:CC:DD:EE:FF**
:Example Cancel pairing with public address device:
	| **> cancelpair -t public 00:11:22:33:44:55**
:Example Cancel pairing with LE random address device:
	| **> cancelpair -t le_random AA:BB:CC:DD:EE:FF**

unpair
------

Unpair device

:Usage: **> unpair [-t type] <remote address>**
:[-t type]: Address type (public, random, le_public, le_random)
:<remote address>: Bluetooth address of device to unpair
:Example Remove pairing with device:
	| **> unpair 00:11:22:33:44:55**
:Example Remove pairing with another device:
	| **> unpair AA:BB:CC:DD:EE:FF**
:Example Unpair public address device:
	| **> unpair -t public 00:11:22:33:44:55**
:Example Unpair LE public address device:
	| **> unpair -t le_public 11:22:33:44:55:66**
:Example Unpair LE random address device:
	| **> unpair -t le_random CC:DD:EE:FF:00:11**

keys
----

Load Link Keys

:Usage: **> keys**
:Example Load stored link keys:
	| **> keys**

ltks
----

Load Long Term Keys

:Usage: **> ltks**
:Example Load stored LE long term keys:
	| **> ltks**

irks
----

Load Identity Resolving Keys

:Usage: **> irks [--local index] [--file file path]**
:[--local index]: Local controller index to use
:[--file file path]: Custom IRK configuration file path
:Example Load IRKs with default local index and file:
	| **> irks**
:Example Load IRKs for controller index 0:
	| **> irks --local 0**
:Example Load IRKs for controller index 1:
	| **> irks --local 1**
:Example Load IRKs from custom configuration file:
	| **> irks --file /etc/bluetooth/irks.conf**
:Example Load IRKs from user file:
	| **> irks --file /home/user/bluetooth_irks.txt**
:Example Load IRKs for hci0 from specific file:
	| **> irks --local 0 --file /etc/bluetooth/hci0_irks.conf**

block
-----

Block Device

:Usage: **> block [-t type] <remote address>**
:[-t type]: Address type (public, random, le_public, le_random)
:<remote address>: Bluetooth address of device to block
:Example Block device using default address type:
	| **> block 00:11:22:33:44:55**
:Example Block another device:
	| **> block AA:BB:CC:DD:EE:FF**
:Example Block device with public address:
	| **> block -t public 00:11:22:33:44:55**
:Example Block device with random address:
	| **> block -t random AA:BB:CC:DD:EE:FF**
:Example Block LE device with public address:
	| **> block -t le_public 11:22:33:44:55:66**
:Example Block LE device with random address:
	| **> block -t le_random CC:DD:EE:FF:00:11**

unblock
-------

Unblock Device

:Usage: **> unblock [-t type] <remote address>**
:[-t type]: Address type (public, random, le_public, le_random)
:<remote address>: Bluetooth address of device to unblock
:Example Unblock device using default address type:
	| **> unblock 00:11:22:33:44:55**
:Example Unblock another device:
	| **> unblock AA:BB:CC:DD:EE:FF**
:Example Unblock device with public address:
	| **> unblock -t public 00:11:22:33:44:55**
:Example Unblock device with random address:
	| **> unblock -t random AA:BB:CC:DD:EE:FF**
:Example Unblock LE device with public address:
	| **> unblock -t le_public 11:22:33:44:55:66**
:Example Unblock LE device with random address:
	| **> unblock -t le_random CC:DD:EE:FF:00:11**

add-uuid
--------

Add UUID

:Usage: **> add-uuid <UUID> <service class hint>**
:<UUID>: Service UUID (16-bit, 32-bit, or 128-bit format)
:<service class hint>: Service class hint bitmask (hexadecimal)
:Example Add Serial Port Profile with object transfer hint:
	| **> add-uuid 0x1101 0x100000**
:Example Add A2DP with audio hint:
	| **> add-uuid 0x110E 0x200000**
:Example Add HFP with audio hint:
	| **> add-uuid 0x111E 0x200000**
:Example Add custom service UUID with no hint:
	| **> add-uuid 12345678-1234-5678-9abc-123456789abc 0x000000**
:Example Add custom UUID with object transfer hint:
	| **> add-uuid ABCD1234-ABCD-1234-ABCD-123456789ABC 0x100000**
:Example Add Generic Access with no specific hint:
	| **> add-uuid 0x1800 0x000000**
:Example Add Battery Service with no hint:
	| **> add-uuid 0x180F 0x000000**

rm-uuid
-------

Remove UUID

:Usage: **> rm-uuid <UUID>**
:<UUID>: Service UUID to remove (16-bit, 32-bit, or 128-bit format)
:Example Remove Serial Port Profile UUID:
	| **> rm-uuid 0x1101**
:Example Remove A2DP UUID:
	| **> rm-uuid 0x110E**
:Example Remove custom service UUID:
	| **> rm-uuid 12345678-1234-5678-9abc-123456789abc**

clr-uuids
---------

Clear UUIDs

:Usage: **> clr-uuids**
:Example Clear all registered UUIDs:
	| **> clr-uuids**

local-oob
---------

Local OOB data

:Usage: **> local-oob**
:Example Generate and display local OOB authentication data:
	| **> local-oob**

remote-oob
----------

Remote OOB data

:Usage: **> remote-oob [-t <addr_type>] [-r <rand192>] [-h <hash192>]
	[-R <rand256>] [-H <hash256>] <addr>**
:[-t <addr_type>]: Address type (public, random, le_public, le_random)
:[-r <rand192>]: P-192 random value (32 hexadecimal characters)
:[-h <hash192>]: P-192 hash value (32 hexadecimal characters)
:[-R <rand256>]: P-256 random value (64 hexadecimal characters)
:[-H <hash256>]: P-256 hash value (64 hexadecimal characters)
:<addr>: Remote device Bluetooth address
:Example Set remote OOB data for device (minimal):
	| **> remote-oob 00:11:22:33:44:55**
:Example Set P-192 random and hash values:
	| **> remote-oob -r 0123456789abcdef0123456789abcdef -h fedcba9876543210fedcba9876543210 00:11:22:33:44:55**
:Example Set P-256 random and hash values:
	| **> remote-oob -R 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -H fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 AA:BB:CC:DD:EE:FF**
:Example Set OOB data for LE public address device:
	| **> remote-oob -t le_public 11:22:33:44:55:66**
:Example Set OOB data for LE random address device:
	| **> remote-oob -t le_random CC:DD:EE:FF:00:11**
:Example Set complete OOB data with both P-192 and P-256 values:
	| **> remote-oob -t public -r 0123456789abcdef0123456789abcdef -h fedcba9876543210fedcba9876543210 -R 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -H fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 00:11:22:33:44:55**

did
---

Set Device ID

:Usage: **> did <source>:<vendor>:<product>:<version>**
:<source>:<vendor>:<product>:<version>: Device ID in format source:vendor:product:version (all hexadecimal)
:Example Set USB source with Linux Foundation vendor ID:
	| **> did 0x0002:0x1D6B:0x0001:0x0100**
:Example Set USB device with Cypress vendor ID:
	| **> did 0x0002:0x04B4:0x1234:0x0200**
:Example Set Bluetooth SIG source with Broadcom vendor:
	| **> did 0x0001:0x000F:0x0001:0x0100**
:Example Set Bluetooth SIG source with Apple vendor:
	| **> did 0x0001:0x004C:0x0001:0x0100**
:Example Set custom USB device ID:
	| **> did 0x0002:0xFFFF:0x1234:0x5678**
:Example Set Qualcomm Bluetooth device:
	| **> did 0x0001:0x05F1:0xABCD:0x0001**

static-addr
-----------

Set static address

:Usage: **> static-addr <address>**
:<address>: Static random Bluetooth address (must have bits 47-46 set to 11)
:Example Set static random address (bit 47=1, bit 46=1):
	| **> static-addr C0:00:00:00:00:01**
:Example Set another static random address:
	| **> static-addr D0:11:22:33:44:55**
:Example Set different static address:
	| **> static-addr E0:AA:BB:CC:DD:EE**

public-addr
-----------

Set public address

:Usage: **> public-addr <address>**
:<address>: Public Bluetooth address to set for the controller
:Example Set public Bluetooth address:
	| **> public-addr 00:11:22:33:44:55**
:Example Set different public address:
	| **> public-addr AA:BB:CC:DD:EE:FF**
:Example Set custom public address:
	| **> public-addr 12:34:56:78:9A:BC**

ext-config
----------

External configuration

:Usage: **> ext-config <on/off>**
:<on/off>: External configuration - "on" to enable external config, "off" to disable
:Example Enable external configuration:
	| **> ext-config on**
:Example Disable external configuration:
	| **> ext-config off**

debug-keys
----------

Toggle debug keys

:Usage: **> debug-keys <on/off>**
:<on/off>: Debug keys support - "on" to enable debug keys, "off" to disable
:Example Enable debug key support:
	| **> debug-keys on**
:Example Disable debug key support:
	| **> debug-keys off**

conn-info
---------

Get connection information

:Usage: **> conn-info [-t type] <remote address>**
:[-t type]: Address type (public, random, le_public, le_random)
:<remote address>: Bluetooth address of connected device
:Example Get connection information for device:
	| **> conn-info 00:11:22:33:44:55**
:Example Get info for another device:
	| **> conn-info AA:BB:CC:DD:EE:FF**
:Example Get info for public address device:
	| **> conn-info -t public 00:11:22:33:44:55**
:Example Get info for LE public address device:
	| **> conn-info -t le_public 11:22:33:44:55:66**
:Example Get info for LE random address device:
	| **> conn-info -t le_random CC:DD:EE:FF:00:11**

io-cap
------

Set IO Capability

:Usage: **> io-cap <cap>**
:<cap>: IO capability (DisplayOnly, DisplayYesNo, KeyboardOnly, NoInputNoOutput, KeyboardDisplay)
:Example Set IO capability to display only:
	| **> io-cap DisplayOnly**
:Example Set IO capability to display with yes/no:
	| **> io-cap DisplayYesNo**
:Example Set IO capability to keyboard only:
	| **> io-cap KeyboardOnly**
:Example Set IO capability to no input/output:
	| **> io-cap NoInputNoOutput**
:Example Set IO capability to keyboard and display:
	| **> io-cap KeyboardDisplay**

scan-params
-----------

Set Scan Parameters

:Usage: **> scan-params <interval> <window>**
:<interval>: Scan interval in hexadecimal (0x0004 to 0x4000, units of 0.625ms)
:<window>: Scan window in hexadecimal (0x0004 to 0x4000, units of 0.625ms)
:Example Set fast scan (16ms interval, 16ms window):
	| **> scan-params 0x0010 0x0010**
:Example Set moderate fast scan (32ms interval, 32ms window):
	| **> scan-params 0x0020 0x0020**
:Example Set balanced scan (96ms interval, 48ms window):
	| **> scan-params 0x0060 0x0030**
:Example Set slow scan (256ms interval, 80ms window):
	| **> scan-params 0x0100 0x0050**
:Example Set background scan (2.56s interval, 18ms window):
	| **> scan-params 0x0800 0x0012**
:Example Set very slow background scan:
	| **> scan-params 0x1000 0x0020**

get-clock
---------

Get Clock Information

:Usage: **> get-clock [address]**
:[address]: Optional remote device Bluetooth address (omit for local clock)
:Example Get local Bluetooth clock information:
	| **> get-clock**
:Example Get clock information for remote device:
	| **> get-clock 00:11:22:33:44:55**
:Example Get clock for another remote device:
	| **> get-clock AA:BB:CC:DD:EE:FF**

add-device
----------

Add Device

:Usage: **> add-device [-a action] [-t type] <address>**
:[-a action]: Device action (auto, allow, deny) - "auto" for auto-connect, "allow" for allow-only, "deny" to block
:[-t type]: Address type (public, random, le_public, le_random)
:<address>: Bluetooth address of device to add
:Example Add device with auto-connect action and default type:
	| **> add-device 00:11:22:33:44:55**
:Example Add another device with defaults:
	| **> add-device AA:BB:CC:DD:EE:FF**
:Example Add device with auto-connect action:
	| **> add-device -a auto 00:11:22:33:44:55**
:Example Add device with allow-only action (no auto-connect):
	| **> add-device -a allow 11:22:33:44:55:66**
:Example Add device with deny action (blocked):
	| **> add-device -a deny CC:DD:EE:FF:00:11**
:Example Add device with public address type:
	| **> add-device -t public 00:11:22:33:44:55**
:Example Add device with random address type:
	| **> add-device -t random AA:BB:CC:DD:EE:FF**
:Example Add LE device with public address:
	| **> add-device -t le_public 11:22:33:44:55:66**
:Example Add LE device with random address:
	| **> add-device -t le_random CC:DD:EE:FF:00:11**
:Example Add LE public device with auto-connect:
	| **> add-device -a auto -t le_public 00:11:22:33:44:55**
:Example Add random address device with allow action:
	| **> add-device -a allow -t random AA:BB:CC:DD:EE:FF**
:Example Add LE random device with deny action:
	| **> add-device -a deny -t le_random CC:DD:EE:FF:00:11**

del-device
----------

Remove Device

:Usage: **> del-device [-t type] <address>**
:[-t type]: Address type (public, random, le_public, le_random)
:<address>: Bluetooth address of device to remove
:Example Remove device using default address type:
	| **> del-device 00:11:22:33:44:55**
:Example Remove another device:
	| **> del-device AA:BB:CC:DD:EE:FF**
:Example Remove device with public address type:
	| **> del-device -t public 00:11:22:33:44:55**
:Example Remove device with random address type:
	| **> del-device -t random AA:BB:CC:DD:EE:FF**
:Example Remove LE device with public address:
	| **> del-device -t le_public 11:22:33:44:55:66**
:Example Remove LE device with random address:
	| **> del-device -t le_random CC:DD:EE:FF:00:11**

clr-devices
-----------

Clear Devices

:Usage: **> clr-devices**
:Example Clear all devices from the device list:
	| **> clr-devices**

bredr-oob
---------

Local OOB data (BR/EDR)

:Usage: **> bredr-oob**
:Example Generate and display local BR/EDR OOB authentication data:
	| **> bredr-oob**

le-oob
------

Local OOB data (LE)

:Usage: **> le-oob**
:Example Generate and display local LE OOB authentication data:
	| **> le-oob**

advinfo
-------

Show advertising features

:Usage: **> advinfo**
:Example Display advertising capabilities and supported features:
	| **> advinfo**

advsize
-------

Show advertising size info

:Usage: **> advsize [options] <instance_id>**
:[options]: Advertising options flags
:<instance_id>: Advertising instance identifier (0-based)
:Example Show advertising data size information for instance 0:
	| **> advsize 0**
:Example Show size information for advertising instance 1:
	| **> advsize 1**
:Example Show size information for advertising instance 5:
	| **> advsize 5**

add-adv
-------

Add advertising instance

:Usage: **> add-adv [options] <instance_id>**
:[options]: Advertising options (-c connectable, -s scannable, -g general discoverable, -l limited discoverable, -m managed flags, -p TX power)
:<instance_id>: Advertising instance identifier (0-based)
:Example Add advertising instance 0 with default settings:
	| **> add-adv 0**
:Example Add advertising instance 1:
	| **> add-adv 1**
:Example Add advertising instance 5:
	| **> add-adv 5**
:Example Add connectable advertising instance 0:
	| **> add-adv -c 0**
:Example Add scannable advertising instance 1:
	| **> add-adv -s 1**
:Example Add general discoverable advertising instance 2:
	| **> add-adv -g 2**
:Example Add limited discoverable advertising instance 3:
	| **> add-adv -l 3**
:Example Add managed flags advertising instance 4:
	| **> add-adv -m 4**
:Example Add TX power advertising instance 5:
	| **> add-adv -p 5**
:Example Add connectable and scannable advertising instance:
	| **> add-adv -c -s 0**
:Example Add general discoverable with TX power:
	| **> add-adv -g -p 1**
:Example Add connectable, general discoverable, and scannable:
	| **> add-adv -c -g -s 2**

rm-adv
------

Remove advertising instance

:Usage: **> rm-adv <instance_id>**
:<instance_id>: Advertising instance identifier (0-based) to remove
:Example Remove advertising instance 0:
	| **> rm-adv 0**
:Example Remove advertising instance 1:
	| **> rm-adv 1**
:Example Remove advertising instance 5:
	| **> rm-adv 5**

clr-adv
-------

Clear advertising instances

:Usage: **> clr-adv**
:Example Clear all advertising instances:
	| **> clr-adv**

add-ext-adv-params
------------------

Add extended advertising params

:Usage: **> add-ext-adv-params [options] <instance_id>**
:[options]: Extended advertising options (-c connectable, -s scannable, -d directed, -h high duty cycle, -l legacy PDU, -a anonymous, -i include TX power)
:<instance_id>: Extended advertising instance identifier (0-based)
:Example Add extended advertising parameters for instance 0:
	| **> add-ext-adv-params 0**
:Example Add extended advertising parameters for instance 1:
	| **> add-ext-adv-params 1**
:Example Add connectable extended advertising for instance 0:
	| **> add-ext-adv-params -c 0**
:Example Add scannable extended advertising for instance 1:
	| **> add-ext-adv-params -s 1**
:Example Add directed extended advertising for instance 2:
	| **> add-ext-adv-params -d 2**
:Example Add high duty cycle extended advertising for instance 3:
	| **> add-ext-adv-params -h 3**
:Example Add legacy PDU extended advertising for instance 4:
	| **> add-ext-adv-params -l 4**
:Example Add anonymous extended advertising for instance 5:
	| **> add-ext-adv-params -a 5**
:Example Add include TX power extended advertising for instance 6:
	| **> add-ext-adv-params -i 6**
:Example Add connectable and scannable extended advertising:
	| **> add-ext-adv-params -c -s 0**
:Example Add connectable extended advertising with TX power:
	| **> add-ext-adv-params -c -i 1**
:Example Add scannable legacy PDU extended advertising:
	| **> add-ext-adv-params -s -l 2**

add-ext-adv-data
----------------

Add extended advertising data

:Usage: **> add-ext-adv-data [options] <instance_id>**
:[options]: Data options (-s for scan response data, -c for complete data)
:<instance_id>: Extended advertising instance identifier (0-based)
:Example Add advertising data to extended instance 0:
	| **> add-ext-adv-data 0**
:Example Add advertising data to extended instance 1:
	| **> add-ext-adv-data 1**
:Example Add scan response data to extended instance 0:
	| **> add-ext-adv-data -s 0**
:Example Add scan response data to extended instance 1:
	| **> add-ext-adv-data -s 1**
:Example Add complete advertising data to instance 0:
	| **> add-ext-adv-data -c 0**
:Example Add complete scan response data to instance 1:
	| **> add-ext-adv-data -c -s 1**

appearance
----------

Set appearance

:Usage: **> appearance <appearance>**
:<appearance>: Appearance value (16-bit integer) representing device type
:Example Set appearance to Unknown:
	| **> appearance 0**
:Example Set appearance to Generic Phone:
	| **> appearance 64**
:Example Set appearance to Generic Computer:
	| **> appearance 128**
:Example Set appearance to Generic Audio/Video device:
	| **> appearance 832**
:Example Set appearance to Speaker:
	| **> appearance 833**
:Example Set appearance to Microphone:
	| **> appearance 834**
:Example Set appearance to Headset:
	| **> appearance 835**
:Example Set appearance to Headphones:
	| **> appearance 836**
:Example Set appearance to Generic HID:
	| **> appearance 960**
:Example Set appearance to Keyboard:
	| **> appearance 961**
:Example Set appearance to Mouse:
	| **> appearance 962**
:Example Set appearance to Joystick:
	| **> appearance 963**
:Example Set appearance to Generic Health Sensor:
	| **> appearance 1344**
:Example Set appearance to Heart Rate Sensor:
	| **> appearance 1345**
:Example Set appearance to Blood Pressure Monitor:
	| **> appearance 1346**
:Example Set appearance to Generic Sports and Fitness:
	| **> appearance 1472**
:Example Set appearance to Location Display:
	| **> appearance 1473**
:Example Set appearance to Location Navigation Display:
	| **> appearance 1474**

phy
---

Get/Set PHY Configuration

:Usage: **> phy [LE1MTX] [LE1MRX] [LE2MTX] [LE2MRX] [LECODEDTX] [LECODEDRX]
	[BR1M1SLOT] [BR1M3SLOT] [BR1M5SLOT][EDR2M1SLOT] [EDR2M3SLOT]
	[EDR2M5SLOT][EDR3M1SLOT] [EDR3M3SLOT] [EDR3M5SLOT]**
:[PHY flags]: PHY configuration flags to enable (LE1MTX, LE1MRX, LE2MTX, LE2MRX, LECODEDTX, LECODEDRX, BR1M1SLOT, etc.)
:Example Display current PHY configuration:
	| **> phy**
:Example Enable LE 1M TX PHY:
	| **> phy LE1MTX**
:Example Enable LE 1M RX PHY:
	| **> phy LE1MRX**
:Example Enable LE 2M TX PHY:
	| **> phy LE2MTX**
:Example Enable LE 2M RX PHY:
	| **> phy LE2MRX**
:Example Enable LE Coded TX PHY:
	| **> phy LECODEDTX**
:Example Enable LE Coded RX PHY:
	| **> phy LECODEDRX**
:Example Enable BR 1M 1-slot packets:
	| **> phy BR1M1SLOT**
:Example Enable BR 1M 3-slot packets:
	| **> phy BR1M3SLOT**
:Example Enable BR 1M 5-slot packets:
	| **> phy BR1M5SLOT**
:Example Enable EDR 2M 1-slot packets:
	| **> phy EDR2M1SLOT**
:Example Enable EDR 2M 3-slot packets:
	| **> phy EDR2M3SLOT**
:Example Enable EDR 2M 5-slot packets:
	| **> phy EDR2M5SLOT**
:Example Enable EDR 3M 1-slot packets:
	| **> phy EDR3M1SLOT**
:Example Enable EDR 3M 3-slot packets:
	| **> phy EDR3M3SLOT**
:Example Enable EDR 3M 5-slot packets:
	| **> phy EDR3M5SLOT**
:Example Enable LE 1M TX and RX PHYs:
	| **> phy LE1MTX LE1MRX**
:Example Enable LE 1M and 2M TX/RX PHYs:
	| **> phy LE1MTX LE1MRX LE2MTX LE2MRX**
:Example Enable 1-slot packets for all BR/EDR PHYs:
	| **> phy BR1M1SLOT EDR2M1SLOT EDR3M1SLOT**

wbs
---

Toggle Wideband-Speech support

:Usage: **> wbs <on/off>**
:<on/off>: Wideband Speech support - "on" to enable for audio profiles, "off" to disable
:Example Enable Wideband Speech support for audio profiles:
	| **> wbs on**
:Example Disable Wideband Speech support:
	| **> wbs off**

secinfo
-------

Show security information

:Usage: **> secinfo**
:Example Display security features and capabilities:
	| **> secinfo**

expinfo
-------

Show experimental features

:Usage: **> expinfo**
:Example Display available experimental features and their status:
	| **> expinfo**

exp-debug
---------

Set debug feature

:Usage: **> exp-debug <on/off>**
:<on/off>: Experimental debug features - "on" to enable, "off" to disable
:Example Enable experimental debug features:
	| **> exp-debug on**
:Example Disable experimental debug features:
	| **> exp-debug off**

exp-privacy
-----------

Set LL privacy feature

:Usage: **> exp-privacy <on/off>**
:<on/off>: Experimental Link Layer privacy - "on" to enable LL privacy features, "off" to disable
:Example Enable experimental Link Layer privacy features:
	| **> exp-privacy on**
:Example Disable experimental Link Layer privacy features:
	| **> exp-privacy off**

exp-quality
-----------

Set bluetooth quality report feature

:Usage: **> exp-quality <on/off>**
:<on/off>: Experimental quality reporting - "on" to enable Bluetooth quality reports, "off" to disable
:Example Enable experimental Bluetooth quality reporting:
	| **> exp-quality on**
:Example Disable experimental Bluetooth quality reporting:
	| **> exp-quality off**

exp-offload
-----------

Toggle codec support

:Usage: **> exp-offload <on/off>**
:<on/off>: Experimental codec offload - "on" to enable codec offload support, "off" to disable
:Example Enable experimental codec offload support:
	| **> exp-offload on**
:Example Disable experimental codec offload support:
	| **> exp-offload off**

read-sysconfig
--------------

Read System Configuration

:Usage: **> read-sysconfig**
:Example Read current system configuration parameters:
	| **> read-sysconfig**

set-sysconfig
-------------

Set System Configuration

:Usage: **> set-sysconfig <-v|-h> [options...]**
:<-v|-h>: Verbose output or help flag
:[options...]: System configuration options (--br-page-scan-type, --br-page-scan-interval, etc.)
:Example Show help for system configuration options:
	| **> set-sysconfig -h**
:Example Set system configuration with verbose output:
	| **> set-sysconfig -v**
:Example Set BR/EDR page scan type with verbose output:
	| **> set-sysconfig -v --br-page-scan-type=0**
:Example Set BR/EDR page scan interval:
	| **> set-sysconfig -v --br-page-scan-interval=0x800**
:Example Set BR/EDR page scan window:
	| **> set-sysconfig -v --br-page-scan-window=0x12**
:Example Set BR/EDR inquiry scan type:
	| **> set-sysconfig -v --br-inquiry-scan-type=0**
:Example Set BR/EDR link supervision timeout:
	| **> set-sysconfig -v --br-link-supervision-timeout=0x2000**
:Example Set LE minimum connection interval:
	| **> set-sysconfig -v --le-min-connection-interval=0x18**
:Example Set LE maximum connection interval:
	| **> set-sysconfig -v --le-max-connection-interval=0x28**
:Example Set multiple BR/EDR scan parameters:
	| **> set-sysconfig -v --br-page-scan-type=0 --br-page-scan-interval=0x800 --br-page-scan-window=0x12**
:Example Set multiple LE connection parameters:
	| **> set-sysconfig -v --le-min-connection-interval=0x18 --le-max-connection-interval=0x28 --le-connection-latency=0**

get-flags
---------

Get device flags

:Usage: **> get-flags [-t type] <address>**
:[-t type]: Address type (public, random, le_public, le_random)
:<address>: Bluetooth address of device to query flags for
:Example Get device flags for device using default type:
	| **> get-flags 00:11:22:33:44:55**
:Example Get flags for another device:
	| **> get-flags AA:BB:CC:DD:EE:FF**
:Example Get flags for public address device:
	| **> get-flags -t public 00:11:22:33:44:55**
:Example Get flags for random address device:
	| **> get-flags -t random AA:BB:CC:DD:EE:FF**
:Example Get flags for LE public address device:
	| **> get-flags -t le_public 11:22:33:44:55:66**
:Example Get flags for LE random address device:
	| **> get-flags -t le_random CC:DD:EE:FF:00:11**


set-flags
---------

Set device flags

:Usage: **> set-flags [-f flags] [-t type] <address>**
:[-f flags]: Device flags bitmask in hexadecimal (0x01=remote wake, 0x02=privacy)
:[-t type]: Address type (public, random, le_public, le_random)
:<address>: Bluetooth address of device to set flags for
:Example Set default flags for device:
	| **> set-flags 00:11:22:33:44:55**
:Example Set default flags for another device:
	| **> set-flags AA:BB:CC:DD:EE:FF**
:Example Set remote wake flag for device:
	| **> set-flags -f 0x01 00:11:22:33:44:55**
:Example Set device privacy flag:
	| **> set-flags -f 0x02 AA:BB:CC:DD:EE:FF**
:Example Set both remote wake and privacy flags:
	| **> set-flags -f 0x03 11:22:33:44:55:66**
:Example Set remote wake for public address device:
	| **> set-flags -f 0x01 -t public 00:11:22:33:44:55**
:Example Set privacy flag for LE public device:
	| **> set-flags -f 0x02 -t le_public 11:22:33:44:55:66**
:Example Set multiple flags for LE random device:
	| **> set-flags -f 0x03 -t le_random CC:DD:EE:FF:00:11**
:Example Clear all flags for device:
	| **> set-flags -f 0x00 00:11:22:33:44:55**
:Example Clear all flags for LE public device:
	| **> set-flags -f 0x00 -t le_public 11:22:33:44:55:66**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

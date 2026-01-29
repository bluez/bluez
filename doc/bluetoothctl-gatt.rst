=================
bluetoothctl-gatt
=================

-------------------------
Generic Attribute Submenu
-------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [gatt.commands]


Generic Attribute Commands
==========================

list-attributes
---------------

Lists the attributes of either the local device or a remote device,
encompassing services, characteristics, and handles. This command provides
a comprehensive overview of the available Bluetooth attributes, which can
be further interacted with using other commands.

:Usage: **> list-attributes [dev/local]**
:[dev/local]: Device MAC address, object path, or "local" to list locally registered attributes (optional, lists all if omitted)
:Example List attributes for specific service:
	| **> list-attributes /org/bluez/hci0/dev_00_11_22_33_44_55/service001a**
:Example List attributes for specific characteristic:
	| **> list-attributes /org/bluez/hci0/dev_00_11_22_33_44_55/service001a/char001c**
:Example List attributes for service on different device:
	| **> list-attributes /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service0020**
:Example List all Generic Access service attributes:
	| **> list-attributes 0x1800**
:Example List all Battery Service attributes:
	| **> list-attributes 0x180F**
:Example List all Device Name characteristic attributes:
	| **> list-attributes 0x2A00**
:Example List attributes using full UUID:
	| **> list-attributes 00001801-0000-1000-8000-00805f9b34fb**
:Example List attributes for custom service UUID:
	| **> list-attributes 12345678-1234-5678-9abc-123456789abc**

select-attribute
----------------

Selects a specific attribute on either the local or remote device for
subsequent operations. Before you can read or write to an attribute, you
must select it with this command. This establishes a context for many
other commands (read, write, notify, etc.), specifying the attribute
they should operate on.

:Usage: **> select-attribute <attribute/UUID/local> [attribute/UUID]**
:<attribute/UUID/local>: GATT attribute path, UUID, or "local" to select from local attributes
:[attribute/UUID]: Additional attribute path or UUID when using "local" (optional)
:Example Select specific characteristic:
	| **> select-attribute /org/bluez/hci0/dev_00_11_22_33_44_55/service001a/char001c**
:Example Select specific descriptor:
	| **> select-attribute /org/bluez/hci0/dev_00_11_22_33_44_55/service0020/char0022/desc0024**
:Example Select service on different device:
	| **> select-attribute /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/service001a**
:Example Select Device Name characteristic:
	| **> select-attribute 0x2A00**
:Example Select Battery Level characteristic:
	| **> select-attribute 0x2A19**
:Example Select Client Characteristic Configuration descriptor:
	| **> select-attribute 0x2902**
:Example Select Temperature characteristic using full UUID:
	| **> select-attribute 00002a6e-0000-1000-8000-00805f9b34fb**
:Example Select custom characteristic:
	| **> select-attribute 12345678-1234-5678-9abc-123456789abc**

attribute-info
--------------

Displays detailed information about an attribute. If no attribute or
UUID is specified, it shows information about the currently selected
attribute. This command is useful for understanding the properties and
capabilities of an attribute.

:Usage: **> attribute-info [attribute/UUID]**
:[attribute/UUID]: GATT attribute path or UUID to get info for (optional, uses current if omitted)
:Example Show information for currently selected attribute:
	| **> attribute-info**
:Example Show info for specific characteristic:
	| **> attribute-info /org/bluez/hci0/dev_00_11_22_33_44_55/service001a/char001c**
:Example Show info for Battery Level characteristic:
	| **> attribute-info 0x2A19**
:Example Show info for Device Name characteristic:
	| **> attribute-info 0x2A00**
:Example Show info for Temperature characteristic:
	| **> attribute-info 00002a6e-0000-1000-8000-00805f9b34fb**

read
----

Reads the value of an attribute. Requires that an attribute be selected
beforehand with select-attribute. The optional offset parameter can be
used for attributes that allow partial reads.

:Usage: **> read [offset]**
:[offset]: Byte offset to start reading from (optional, defaults to 0)
:Example Read attribute value from offset 0:
	| **> read**
:Example Read attribute value from offset 0 (explicit):
	| **> read 0**
:Example Read attribute value starting from offset 4:
	| **> read 4**
:Example Read attribute value starting from offset 10:
	| **> read 10**
:Example Read attribute value starting from offset 16:
	| **> read 16**

write
-----

Writes a value to an attribute. This command necessitates that an attribute
be selected in advance using select-attribute. Data must be provided in
hexadecimal format. Optional offset and type parameters can accommodate
specific write requirements.

:Usage: **> write <data="xx xx ..."> [offset] [type]**
:<xx xx ...>: Hexadecimal data bytes to write to the attribute
:[offset]: Byte offset to start writing at (optional, defaults to 0)
:[type]: Write type - request, command, or reliable (optional, defaults to request)
:Example Write "Hello" to attribute (ASCII bytes):
	| **> write "48 65 6C 6C 6F"**
:Example Write binary data to attribute:
	| **> write "01 02 03 04"**
:Example Write single byte value:
	| **> write "FF"**
:Example Write 2 bytes starting at offset 4:
	| **> write "01 02" 4**
:Example Write with write request (default):
	| **> write "48 65 6C 6C 6F" 0 request**
:Example Write with write command (no response):
	| **> write "01 02 03" 0 command**
:Example Write with reliable write:
	| **> write "FF EE DD" 0 reliable**

acquire-write
-------------

Acquires a Write file descriptor for a previously selected attribute. This
is useful for applications that need a file descriptor to perform
write operations.

:Usage: **> acquire-write**
:Example Acquire write file descriptor for current attribute:
	| **> acquire-write**

release-write
-------------

Releases the Write file descriptor acquired with acquire-write. This
command is necessary to clean up resources after you're done with the
write operation.

:Usage: **> release-write**
:Example Release write file descriptor for current attribute:
	| **> release-write**

acquire-notify
--------------

Acquires a Notify file descriptor for a previously selected attribute.
This enables applications to listen for notifications on attribute
value changes.

:Usage: **> acquire-notify**
:Example Acquire notify file descriptor for current attribute:
	| **> acquire-notify**

release-notify
--------------

Releases the Notify file descriptor obtained with acquire-notify. Ensures
resources are freed once notification listening is no longer needed.

:Usage: **> release-notify**
:Example Release notify file descriptor for current attribute:
	| **> release-notify**

notify
------

Enables or disables notifications for attribute value changes. Before
this command can be used, the relevant attribute must be selected. This
command allows applications to be notified of attribute changes without
polling.

:Usage: **> notify <on/off>**
:<on/off>: Enable or disable notifications for the current attribute
:Example Enable notifications for current attribute:
	| **> notify on**
:Example Disable notifications for current attribute:
	| **> notify off**

clone
-----

Creates a clone of a device or attribute. This can be useful for creating
a backup or working with a copy for testing purposes.

:Usage: **> clone [dev/attribute/UUID]**
:[dev/attribute/UUID]: Device MAC address, attribute path, or UUID to clone (optional, clones current if omitted)
:Example Clone entire device GATT database:
	| **> clone 00:11:22:33:44:55**
:Example Clone another device:
	| **> clone AA:BB:CC:DD:EE:FF**
:Example Clone specific service:
	| **> clone /org/bluez/hci0/dev_00_11_22_33_44_55/service001a**
:Example Clone specific characteristic:
	| **> clone /org/bluez/hci0/dev_00_11_22_33_44_55/service001a/char001c**
:Example Clone Generic Access service:
	| **> clone 0x1800**
:Example Clone Battery Service:
	| **> clone 0x180F**
:Example Clone Battery Level characteristic:
	| **> clone 0x2A19**

register-application
--------------------

Registers a new application with the Bluetooth system, allowing for the
management of services, characteristics, and descriptors under this
application.

:Usage: **> register-application [UUID ...]**
:[UUID ...]: Optional list of service UUIDs to register with the application
:Example Register GATT application without specific UUIDs:
	| **> register-application**
:Example Register application with Battery Service:
	| **> register-application 0x180F**
:Example Register with Generic Access and Battery Service:
	| **> register-application 0x1800 0x180F**
:Example Register application with custom service UUID:
	| **> register-application 12345678-1234-5678-9abc-123456789abc**
:Example Register with multiple standard services:
	| **> register-application 0x1800 0x180F 0x180A**

unregister-application
----------------------

Removes a previously registered application from the Bluetooth system.

:Usage: **> unregister-application**
:Example Unregister current GATT application:
	| **> unregister-application**

register-service
----------------

Adds a new service under a registered application. This command is
crucial for defining new services that devices can offer.

:Usage: **> register-service <UUID> [handle]**
:<UUID>: Service UUID to register (16-bit, 32-bit, or 128-bit format)
:[handle]: Specific attribute handle to assign (optional, auto-assigned if omitted)
:Example Register Generic Access service (auto handle):
	| **> register-service 0x1800**
:Example Register Battery Service (auto handle):
	| **> register-service 0x180F**
:Example Register Device Information service (auto handle):
	| **> register-service 0x180A**
:Example Register Generic Access service at handle 1:
	| **> register-service 0x1800 0x0001**
:Example Register Battery Service at handle 16:
	| **> register-service 0x180F 0x0010**
:Example Register Device Info service at handle 32:
	| **> register-service 0x180A 0x0020**
:Example Register custom service (auto handle):
	| **> register-service 12345678-1234-5678-9abc-123456789abc**
:Example Register custom service at specific handle:
	| **> register-service 12345678-1234-5678-9abc-123456789abc 0x0050**

unregister-service
------------------

Removes a service from a registered application, effectively ceasing
its availability.

:Usage: **> unregister-service <UUID/object>**
:<UUID/object>: Service UUID or object path of the service to unregister
:Example Unregister Generic Access service:
	| **> unregister-service 0x1800**
:Example Unregister Battery Service:
	| **> unregister-service 0x180F**
:Example Unregister custom service:
	| **> unregister-service 12345678-1234-5678-9abc-123456789abc**
:Example Unregister service by object path:
	| **> unregister-service /org/bluez/example/service0**
:Example Unregister another service:
	| **> unregister-service /org/bluez/example/service1**

register-includes
-----------------

Marks a service as included within another service, allowing for
service hierarchies and complex service structures.

:Usage: **> register-includes <UUID> [handle]**
:<UUID>: Service UUID to register as included service
:[handle]: Specific attribute handle to assign (optional, auto-assigned if omitted)
:Example Register Generic Access as included service:
	| **> register-includes 0x1800**
:Example Register Battery Service as included at handle 21:
	| **> register-includes 0x180F 0x0015**
:Example Register custom service as included:
	| **> register-includes 12345678-1234-5678-9abc-123456789abc**

unregister-includes
-------------------

Removes an included service relationship, simplifying the service structure.

:Usage: **> unregister-includes <Service-UUID> <Inc-UUID>**
:<Service-UUID>: Parent service UUID that contains the included service
:<Inc-UUID>: Included service UUID to remove from the parent service
:Example Unregister Battery Service inclusion from Generic Access:
	| **> unregister-includes 0x1800 0x180F**
:Example Unregister Device Info inclusion from custom service:
	| **> unregister-includes 12345678-1234-5678-9abc-123456789abc 0x180A**

register-characteristic
-----------------------

Introduces a new characteristic under a service, specifying its properties
and access permissions with flags.

:Usage: **> register-characteristic <UUID> <Flags=read,write,notify...> [handle]**
:<UUID>: Characteristic UUID to register (16-bit, 32-bit, or 128-bit format)
:<Flags=read,write,notify...>: Comma-separated list of characteristic properties and permissions
:[handle]: Specific attribute handle to assign (optional, auto-assigned if omitted)
:Example Register Device Name (read-only):
	| **> register-characteristic 0x2A00 read**
:Example Register Battery Level (read + notifications):
	| **> register-characteristic 0x2A19 read,notify**
:Example Register Heart Rate Measurement (notify-only):
	| **> register-characteristic 0x2A37 notify**
:Example Register Device Name (read + write):
	| **> register-characteristic 0x2A00 read,write**
:Example Register Battery Level (read + write + notify):
	| **> register-characteristic 0x2A19 read,write,notify**
:Example Register Temperature (read + indications):
	| **> register-characteristic 0x2A6E read,indicate**
:Example Register Device Name at handle 3:
	| **> register-characteristic 0x2A00 read 0x0003**
:Example Register Battery Level at handle 19:
	| **> register-characteristic 0x2A19 read,notify 0x0013**
:Example Register custom characteristic with full capabilities:
	| **> register-characteristic 12345678-1234-5678-9abc-123456789abc read,write,notify**
:Example Register custom write-only characteristic:
	| **> register-characteristic ABCD1234-ABCD-1234-ABCD-123456789ABC write-without-response**
:Example Register with all flags:
	| **> register-characteristic 0x2A00 read,write,write-without-response,notify,indicate**

unregister-characteristic
-------------------------

Eliminates a characteristic from a service, removing its functionality.

:Usage: **> unregister-characteristic <UUID/object>**
:<UUID/object>: Characteristic UUID or object path of the characteristic to unregister
:Example Unregister Device Name characteristic:
	| **> unregister-characteristic 0x2A00**
:Example Unregister Battery Level characteristic:
	| **> unregister-characteristic 0x2A19**
:Example Unregister custom characteristic:
	| **> unregister-characteristic 12345678-1234-5678-9abc-123456789abc**
:Example Unregister characteristic by object path:
	| **> unregister-characteristic /org/bluez/example/service0/char0**
:Example Unregister another characteristic:
	| **> unregister-characteristic /org/bluez/example/service1/char1**

register-descriptor
-------------------

Adds a descriptor to a characteristic, further defining its behavior and
access controls.

:Usage: **> register-descriptor <UUID> <Flags=read,write...> [handle]**
:<UUID>: Descriptor UUID to register (16-bit, 32-bit, or 128-bit format)
:<Flags=read,write...>: Comma-separated list of descriptor properties and permissions
:[handle]: Specific attribute handle to assign (optional, auto-assigned if omitted)
:Example Register Client Characteristic Configuration:
	| **> register-descriptor 0x2902 read,write**
:Example Register Characteristic User Description:
	| **> register-descriptor 0x2901 read**
:Example Register Characteristic Presentation Format:
	| **> register-descriptor 0x2904 read**
:Example Register CCCD at handle 5:
	| **> register-descriptor 0x2902 read,write 0x0005**
:Example Register User Description at handle 21:
	| **> register-descriptor 0x2901 read 0x0015**
:Example Register custom descriptor:
	| **> register-descriptor 12345678-1234-5678-9abc-123456789abc read,write**
:Example Register custom read-only descriptor:
	| **> register-descriptor ABCD1234-ABCD-1234-ABCD-123456789ABC read**
:Example Register Valid Range descriptor:
	| **> register-descriptor 0x2906 read**
:Example Register External Report Reference:
	| **> register-descriptor 0x2907 read**
:Example Register Report Reference:
	| **> register-descriptor 0x2908 read**

unregister-descriptor
---------------------

Removes a descriptor from a characteristic, simplifying its behavior.

:Usage: **> unregister-descriptor <UUID/object>**
:<UUID/object>: Descriptor UUID or object path of the descriptor to unregister
:Example Unregister Client Characteristic Configuration:
	| **> unregister-descriptor 0x2902**
:Example Unregister Characteristic User Description:
	| **> unregister-descriptor 0x2901**
:Example Unregister custom descriptor:
	| **> unregister-descriptor 12345678-1234-5678-9abc-123456789abc**
:Example Unregister descriptor by object path:
	| **> unregister-descriptor /org/bluez/example/service0/char0/desc0**
:Example Unregister another descriptor:
	| **> unregister-descriptor /org/bluez/example/service1/char1/desc1**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

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

:Usage: **> list-attributes <attribute/UUID> <dev/local>**

select-attribute
----------------

Selects a specific attribute on either the local or remote device for
subsequent operations. Before you can read or write to an attribute, you
must select it with this command. This establishes a context for many
other commands (read, write, notify, etc.), specifying the attribute
they should operate on.

:Usage: **> select-attribute <attribute/UUID/local>**

attribute-info
--------------

Displays detailed information about an attribute. If no attribute or
UUID is specified, it shows information about the currently selected
attribute. This command is useful for understanding the properties and
capabilities of an attribute.

:Usage: **> attribute-info [attribute/UUID]**

read
----

Reads the value of an attribute. Requires that an attribute be selected
beforehand with select-attribute. The optional offset parameter can be
used for attributes that allow partial reads.

:Usage: **> read [offset]**

write
-----

Writes a value to an attribute. This command necessitates that an attribute
be selected in advance using select-attribute. Data must be provided in
hexadecimal format. Optional offset and type parameters can accommodate
specific write requirements.

:Usage: **> write <data=xx xx ...> [offset] [type]**

acquire-write
-------------

Acquires a Write file descriptor for a previously selected attribute. This
is useful for applications that need a file descriptor to perform
write operations.

:Usage: **> acquire-write**

release-write
-------------

Releases the Write file descriptor acquired with acquire-write. This
command is necessary to clean up resources after you're done with the
write operation.

:Usage: **> release-write**

acquire-notify
--------------

Acquires a Notify file descriptor for a previously selected attribute.
This enables applications to listen for notifications on attribute
value changes.

:Usage: **> acquire-notify**

release-notify
--------------

Releases the Notify file descriptor obtained with acquire-notify. Ensures
resources are freed once notification listening is no longer needed.

:Usage: **> release-notify**

notify
------

Enables or disables notifications for attribute value changes. Before
this command can be used, the relevant attribute must be selected. This
command allows applications to be notified of attribute changes without
polling.

:Usage: **> notify <on/off>**

clone
-----

Creates a clone of a device or attribute. This can be useful for creating
a backup or working with a copy for testing purposes.

:Usage: **> clone [dev/attribute/UUID]**

register-application
--------------------

Registers a new application with the Bluetooth system, allowing for the
management of services, characteristics, and descriptors under this
application.

:Usage: **> register-application [UUID ...]**

unregister-application
----------------------

Removes a previously registered application from the Bluetooth system.

:Usage: **> unregister-application**

register-service
----------------

Adds a new service under a registered application. This command is
crucial for defining new services that devices can offer.

:Usage: **> register-service <UUID> [handle]**

unregister-service
------------------

Removes a service from a registered application, effectively ceasing
its availability.

:Usage: **> unregister-service <UUID/object>**

register-includes
-----------------

Marks a service as included within another service, allowing for
service hierarchies and complex service structures.

:Usage: **>r egister-includes <UUID> [handle]**

unregister-includes
-------------------

Removes an included service relationship, simplifying the service structure.

:Usage: **> unregister-includes <Service-UUID><Inc-UUID>**

register-characteristic
-----------------------

Introduces a new characteristic under a service, specifying its properties
and access permissions with flags.

:Usage: **> register-characteristic <UUID> <Flags=read,write,notify...> [handle]**

unregister-characteristic
-------------------------

Eliminates a characteristic from a service, removing its functionality.

:Usage: **> unregister-characteristic <UUID/object>**

register-descriptor
-------------------

Adds a descriptor to a characteristic, further defining its behavior and
access controls.

:Usage: **> register-descriptor <UUID> <Flags=read,write...> [handle]**

unregister-descriptor
---------------------

Removes a descriptor from a characteristic, simplifying its behavior.

:Usage: **> unregister-descriptor <UUID/object>**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

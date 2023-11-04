=================
bluetoothctl-gatt
=================

-------------------------
Generic Attribute Submenu
-------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
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

List attributes.

:Usage: **# list-attributes <attribute/UUID>**

select-attribute
----------------

Select attribute.

:Usage: **# select-attribute <attribute/UUID>**

attribute-info
--------------

Select attribute.

:Usage: **# attribute-info [attribute/UUID]**

read
----

Read attribute value.

:Usage: **# read [offset]**

write
-----

Write attribute value.

:Usage: **# write <data=xx xx ...> [offset] [type]**

acquire-write
-------------

Acquire Write file descriptor.

:Usage: **# acquire-write**

release-write
-------------

Release Write file descriptor.

:Usage: **# release-write**

acquire-notify
--------------

Acquire Notify file descriptor.

:Usage: **# acquire-notify**

release-notify
--------------

Release Notify file descriptor.

:Usage: **# release-notify**

notify
------

Notify attribute value.

:Usage: **# notify <on/off>**

clone
-----

Clone a device or attribute.

:Usage: **# clone [dev/attribute/UUID]**

register-application
--------------------

Register application.

:Usage: **# register-application [UUID ...]**

unregister-application
----------------------

Unregister application

:Usage: **# unregister-application**

register-service
----------------

Register application service.

:Usage: **# register-service <UUID> [handle]**

unregister-service
------------------

Unregister application service

:Usage: **# unregister-service <UUID/object>**

register-includes
-----------------

Register as Included service.

:Usage: **#r egister-includes <UUID> [handle]**

unregister-includes
-------------------

Unregister Included service.

:Usage: **# unregister-includes <Service-UUID><Inc-UUID>**

register-characteristic
-----------------------

Register service characteristic.

:Usage: **# register-characteristic <UUID> <Flags=read,write,notify...> [handle]**

unregister-characteristic
-------------------------

Unregister service characteristic.

:Usage: **# unregister-characteristic <UUID/object>**

register-descriptor
-------------------

Register characteristic descriptor.

:Usage: **# register-descriptor <UUID> <Flags=read,write...> [handle]**

unregister-descriptor
---------------------

Unregister characteristic descriptor.

:Usage: **# unregister-descriptor <UUID/object>**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

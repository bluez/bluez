=====================
bluetoothctl-endpoint
=====================

----------------
Endpoint Submenu
----------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [endpoint.commands]

Endpoint Commands
=================

list
----

List available endpoints.

:Usage: **# list [local]**

show
----

Endpoint information.

:Usage: **# show <endpoint>**

register
--------

Register Endpoint.

:Usage: **# register <UUID> <codec> [capabilities...]**

unregister
----------

Unregister Endpoint.

:Usage: **# unregister <UUID/object>**

config
------

Configure Endpoint.

:Usage: **# config <endpoint> <local endpoint> [preset]**

presets
-------

List available presets.

:Usage: **# presets <UUID> [default]**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

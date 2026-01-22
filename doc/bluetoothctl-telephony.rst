======================
bluetoothctl-telephony
======================

-----------------
Telephony Submenu
-----------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: May 2025
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [telephony.commands]

Telephony Commands
==================

list
----

List available audio gateways.

:Usage: **> list**

show
----

Show audio gateway information.

:Usage: **> show [audiogw]**

select
------

Select default audio gateway.

:Usage: **> select <audiogw>**

dial
----

Dial number.

:Usage: **> dial <number> [audiogw]**

hangup-all
----------

Hangup all calls.

:Usage: **> hangup-all**

list-calls
----------

List available calls.

:Usage: **> list-calls**

show-call
---------

Show call information.

:Usage: **> show-call <call>**

answer
------

Answer call.

:Usage: **> answer <call>**

hangup
------

Hangup call.

:Usage: **> hangup <call>**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

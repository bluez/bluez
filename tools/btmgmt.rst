======
btmgmt
======

-------------------------------------
interactive bluetooth management tool
-------------------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: July 2023
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**btmgmt** [--options] [commands]

DESCRIPTION
===========

**btmgmt(1)** interactive bluetooth management tool. The tool issues commands
to the Kernel using the Bluetooth Management socket, some commands may require
net-admin capability in order to work since the Bluetooth Management interface
is considered a low-level interface meant for the likes of **bluetoothd(8)**,
it is not recommended for applications to use it directly as it may result in
unexpected behavior.

OPTIONS
=======

:-i/--index: Specify adapter index
:-m-/-monitor: Enable monitor output
:-t/--timeout: Timeout in seconds for non-interactive mode
:-v/--version: Display version
:-i/--init-script: Init script file
:-h/--help: Display help

COMMANDS
========

:main: See **bluetoothctl-mgmt(1)**
:monitor: See **bluetoothctl-monitor(1)**

AUTOMATION
==========

Two common ways to automate the tool are to pass the commands directly like in
the follow example:

.. code-block::

    btmgmt <<EOF
    list
    show
    EOF

Or create a script and pass it as init-script:

.. code-block::

    $ vi test-script.bt
    list
    show
    quit
    :wq
    $ btmgmt --init-script=test-script

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

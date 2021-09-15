======
rfcomm
======

----------------------------
RFCOMM configuration utility
----------------------------

:Author: Marcel Holtmann <marcel@holtmann.org>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: April 28, 2002
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**rfcomm** [*OPTIONS*] <*COMMAND*> <*dev*>

DESCRIPTION
===========

**rfcomm(1)** is used to set up, maintain, and inspect the RFCOMM configuration
of the Bluetooth subsystem in the Linux kernel. If no **command** is given,
or if the option **-a** is used, **rfcomm** prints information about the
configured RFCOMM devices.

OPTIONS
=======

-h      Gives a list of possible commands.

-a      Prints information about all configured RFCOMM devices.

-r      Switch TTY into raw mode (doesn't work with "bind").

-i <*hciX*> | <*bdaddr*>
    The command is applied to device *hciX*, which must be the name or the
    address of an installed Bluetooth device. If not specified, the command
    will be use the first available Bluetooth device.

-A     Enable authentication

-E     Enable encryption

-S     Secure connection

-C     Become the central of a piconet

-L <seconds>    Set linger timeout

COMMANDS
========

show <*dev*>
    Display the information about the specified device.

connect <*dev*> [*bdaddr*] [*channel*]
    Connect the RFCOMM device to the remote Bluetooth device on the specified
    channel. If no  channel  is  specified, it will use the channel
    number **1**. This command can be terminated with the key sequence CTRL-C.

listen <*dev*> [*channel*] [*cmd*]
    Listen  on  a specified RFCOMM channel for incoming connections.  If no
    channel is specified, it will use the channel number **1**, but a channel
    must be specified before cmd. If cmd is given, it will be executed as soon
    as a  client  connects.  When the child process terminates or the client
    disconnect, the command will terminate. Occurrences of {} in cmd will be
    replaced by the name of the device used by the connection. This command
    can be terminated with the key sequence CTRL-C.

watch <*dev*> [*channel*] [*cmd*]
    Watch is identical to listen except that when the child process
    terminates or the client disconnect, the command will restart listening
    with the same parameters.

bind <*dev*> [*bdaddr*] [*channel*]
    This binds the RFCOMM device to a remote Bluetooth device. The command
    does not establish a connection to the remote  device, it only creates
    the binding. The connection will be established right after an application
    tries to open the RFCOMM device. If no channel number is specified, it
    uses the channel number **1**.

release <*dev*>
    This command releases a defined RFCOMM binding.

    If **all** is specified for the RFCOMM device, then all bindings will be
    removed.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

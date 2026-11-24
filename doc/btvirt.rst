======
btvirt
======

-----------------------------
Bluetooth controller emulator
-----------------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: October 2026
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**btvirt** [*OPTIONS*]

DESCRIPTION
===========

**btvirt(1)** emulates Bluetooth controllers in software. It is used to test
the kernel Bluetooth subsystem and BlueZ without real hardware, most notably
by **test-runner(1)** and **test-functional(1)**.

The controllers are implemented by the BlueZ emulator (``emulator/btdev.c``)
and speak HCI. They can be exposed to a Bluetooth stack in several ways:

- as local virtual controllers through ``/dev/vhci`` (**-l**), which then
  appear as ``hciN`` on the machine running btvirt;
- as H:4 streams on Unix socket servers (**-s**) or a TCP server (**-t**),
  one controller per client connection;
- as virtio Bluetooth devices on a vhost-user server (**-V**), one
  controller per connection, for virtual machines;
- as an H:4 stream on a pseudo terminal (**-S**).

All controllers created by one btvirt process share an emulated air
interface: they can discover, connect to and exchange data with each other,
regardless of how each one is exposed. Controllers in different btvirt
processes cannot see each other, except for the test LE controllers created
with **-U**, see below.

btvirt runs until it receives **SIGINT** or **SIGTERM**.

OPTIONS
=======

At least one of **-l**, **-s**, **-t**, **-V**, **-S**, **-U** or
**--time** must be given.
Optional arguments must be attached to the option, as in **-l2**,
**-t45551** or **--server=/tmp/bt**.

-l[num], --local[=num]      Create *num* local virtual controllers through
                            ``/dev/vhci`` (default: 1). Requires access to
                            ``/dev/vhci``. The controller type is selected
                            with **-L**, **-B**, **-A** or **-C**.

-s[path], --server[=path]   Create Unix socket servers in the directory
                            *path* (default: ``/tmp``). Each client that
                            connects gets a new controller of the server's
                            type, attached as an H:4 stream. The following
                            sockets are created:

                            ``bt-server-bredrle``
                                BR/EDR/LE controllers, of the version given
                                with **-C**
                            ``bt-server-bredr``
                                BR/EDR-only controllers
                            ``bt-server-le``
                                LE-only controllers
                            ``bt-server-amp``
                                AMP controllers
                            ``bt-server-mon``
                                monitor socket, no controller is created

-t[port], --tcp[=port]      Create a TCP server on *port* (default: 45550).
                            Each client that connects gets a new BR/EDR/LE
                            controller, of the version given with **-C**,
                            attached as an H:4 stream. The server listens on
                            127.0.0.1 only.

-V[path], --vhost[=path]    Create a vhost-user server socket
                            ``bt-vhost-bredrle`` in the directory *path*
                            (default: ``/tmp``). Each connection gets a new
                            BR/EDR/LE controller, of the version given with
                            **-C**, provided to the guest as a virtio
                            Bluetooth device. See **virtio** for how to
                            attach it to QEMU or User Mode Linux guests.

--time[=path]               Create a time travel calendar socket ``bt-time``
                            in the directory *path* (default: ``/tmp``) for
                            User Mode Linux guests started with
                            ``time-travel=ext:<path>/bt-time``. The guests
                            and btvirt then share a simulated clock: time
                            only advances when every guest waits, and the
                            timers of the emulated controllers run on it.
                            Notifications of **-V** controllers are
                            exchanged in-band, so they are ordered with
                            the guests' clocks.

-S, --serial                Create a pseudo terminal with a BR/EDR/LE
                            controller attached as an H:4 stream. The path of
                            the terminal is printed on startup; attach it
                            with **btattach(1)**.

-U[num], --letest[=num]     Create *num* test LE controllers (default: 1)
                            through ``/dev/vhci``. Unlike the other
                            controllers, these exchange radio traffic with
                            test LE controllers in other btvirt processes,
                            using UDP broadcasts on port 45023.

-L, --le                    Make the controllers created with **-l** LE-only.

-B, --bredr                 Make the controllers created with **-l**
                            BR/EDR-only.

-A, --amp                   Make the controllers created with **-l** AMP
                            controllers.

-C version, --core=version  Core Specification version of the BR/EDR/LE
                            controllers created with **-l**, **-s** (on
                            ``bt-server-bredrle``), **-t** and **-V**. Supported
                            values are ``5.0``, ``5.2``, ``6.0`` and ``6.2``
                            (default).

-d, --debug                 Enable debug output for the **-l**, **-s** and
                            **-V** controllers.

-v, --version               Show version.

-h, --help                  Show help options.

VENDOR COMMANDS
===============

Controllers created with **-l** answer two vendor commands, so the kernel
treats them as supporting the corresponding extensions:

- opcode ``0xfc10``: emulator-specific vendor command;
- opcode ``0xfc1e``: Microsoft vendor extension (MSFT).

EXAMPLES
========

Create two local controllers, which show up as ``hciN`` and can connect to
each other::

    $ sudo btvirt -l2

Serve controllers to virtual machines, one per connecting VM, the way
**test-functional(1)** does::

    $ btvirt --server=/tmp/bt
    $ test-runner -u/tmp/bt/bt-server-bredrle -k bzImage -- ...

Provide controllers to User Mode Linux guests as virtio Bluetooth
devices, two from the same socket::

    $ btvirt -V/tmp/bt
    $ linux ... virtio_uml.device=/tmp/bt/bt-vhost-bredrle:40 \
                virtio_uml.device=/tmp/bt/bt-vhost-bredrle:40

Run the same guests on a simulated clock shared with btvirt::

    $ btvirt --time=/tmp/bt -V/tmp/bt
    $ linux ... time-travel=ext:/tmp/bt/bt-time \
                virtio_uml.device=/tmp/bt/bt-vhost-bredrle:40 \
                virtio_uml.device=/tmp/bt/bt-vhost-bredrle:40

Emulate a Bluetooth 5.2 controller over TCP::

    $ btvirt -C 5.2 -t

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

SEE ALSO
========

**test-runner(1)**, **test-functional(1)**, **btattach(1)**

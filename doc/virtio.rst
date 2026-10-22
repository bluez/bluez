======
virtio
======

------------------------------------------------------------
Virtio Bluetooth device and vhost-user controller backends
------------------------------------------------------------

Introduction
============

The virtio Bluetooth device (device ID 40) carries HCI packets between
a guest kernel and a Bluetooth controller provided by the host. The Linux
driver is ``drivers/bluetooth/virtio_bt.c``; it registers the device as an
``hciN`` with bus type ``HCI_VIRTIO``, without any attach step such as
**btattach(1)**.

The controller behind the device can be anything that speaks HCI: an
emulator, a firmware simulation or a proxy to real hardware. When the
controller runs as a separate host process, the device is provided through
the vhost-user protocol: the guest's virtio transport talks to the process
over a Unix socket.

This document describes the device as implemented by Linux and what a
vhost-user backend has to provide, as **btvirt(1)** does with **-V**; see
`btvirt support`_.

Why virtio and vhost-user
=========================

The two are separate layers:

- **virtio** is the device: how HCI packets are framed in virtqueues and
  which configuration the guest reads.
- **vhost-user** is the transport between the guest and the process that
  implements the device.

QEMU guests can get a controller without either of them, through an emulated
serial port and **btattach(1)**; this is what **test-runner(1)** **-u** does.
User Mode Linux (UML) has no serial device that can connect to a Unix socket;
its only way to attach an externally implemented device is ``virtio_uml``,
which speaks vhost-user. On UML, vhost-user virtio is therefore the
natural way to provide controllers.

It is also required for deterministic simulation. With UML time travel
(``time-travel=ext``), the guest's clock is driven by an external time
controller, and all inputs to the guest have to be scheduled through it.
Data arriving on a plain file descriptor, such as a serial line, is not; a
vhost-user backend can coordinate every message with the time controller
(see `Time travel`_).

Device
======

Feature bits
------------

The device must offer ``VIRTIO_F_VERSION_1``; the Linux driver refuses
devices without it. The device specific feature bits are
(``include/uapi/linux/virtio_bt.h``):

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Bit
     - Name
     - Meaning

   * - 0
     - ``VIRTIO_BT_F_VND_HCI``
     - The ``vendor`` configuration field is valid; the driver applies the
       vendor specific setup (see `Configuration`_).

   * - 1
     - ``VIRTIO_BT_F_MSFT_EXT``
     - The controller supports the Microsoft vendor extension, using the
       opcode in ``msft_opcode``.

   * - 2
     - ``VIRTIO_BT_F_AOSP_EXT``
     - The controller supports the Android (AOSP) vendor extension.

   * - 3
     - ``VIRTIO_BT_F_CONFIG_V2``
     - The configuration uses the ``virtio_bt_config_v2`` layout.

Configuration
-------------

Version 1 layout, packed:

.. code-block::

    struct virtio_bt_config {
            __u8  type;          /* 0: primary controller */
            __u16 vendor;
            __u16 msft_opcode;
    } __attribute__((packed));

Version 2 layout, used if ``VIRTIO_BT_F_CONFIG_V2`` is negotiated:

.. code-block::

    struct virtio_bt_config_v2 {
            __u8  type;
            __u8  alignment;
            __u16 vendor;
            __u16 msft_opcode;
    };

``type`` must be ``VIRTIO_BT_CONFIG_TYPE_PRIMARY`` (0); the driver rejects
other values.

``vendor`` selects the driver's setup and quirks when ``VIRTIO_BT_F_VND_HCI``
is negotiated:

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Value
     - Vendor
     - Driver behavior

   * - 0
     - none
     - generic controller

   * - 1
     - Zephyr
     - manufacturer 1521, Zephyr setup and set-address commands

   * - 2
     - Intel
     - manufacturer 2, Intel setup and set-address commands

   * - 3
     - Realtek
     - manufacturer 93, Realtek setup

A backend emulating a generic controller should not offer
``VIRTIO_BT_F_VND_HCI``, or should set ``vendor`` to 0.

Virtqueues
----------

.. list-table::
   :header-rows: 1
   :widths: auto

   * - Index
     - Name
     - Direction

   * - 0
     - tx
     - guest to device: HCI commands, ACL, SCO and ISO data

   * - 1
     - rx
     - device to guest: HCI events, ACL, SCO and ISO data

Each buffer holds exactly one HCI packet in H:4 format: the packet type byte
(``0x01`` command, ``0x02`` ACL, ``0x03`` SCO, ``0x04`` event, ``0x05`` ISO)
followed by the packet. There is no other header.

The Linux driver keeps a single receive buffer of 1000 bytes posted on the rx
queue and posts the next one only after it has processed a packet. A backend
must therefore expect to find no rx buffer available when it has several
packets to deliver back to back (for example an advertising report followed
by its scan response report), and has to queue them until the guest posts a
buffer, instead of dropping them. Packets longer than the posted buffer are
rejected by the driver.

The driver performs an HCI Reset when the device is opened, so the backend
must answer it within the kernel's HCI command timeout.

vhost-user backend
==================

A backend implements the vhost-user protocol as the slave (back-end) side, on
a Unix socket that the guest's VMM (QEMU, or the UML kernel itself) connects
to. Beyond the base protocol it must support:

- ``VHOST_USER_F_PROTOCOL_FEATURES``;
- protocol feature ``VHOST_USER_PROTOCOL_F_CONFIG``, so the guest can read
  the configuration with ``VHOST_USER_GET_CONFIG``;
- two virtqueues, tx and rx as above.

For time travel, it should also support ``VHOST_USER_PROTOCOL_F_SLAVE_REQ``
and ``VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS``, see `Time travel`_.

The backend reads packets from the tx queue and passes them to its
controller, and writes the controller's packets into rx buffers and notifies
the guest.

Attaching to a guest
====================

UML
---

Pass one ``virtio_uml.device`` parameter per controller, with the backend's
socket and the virtio Bluetooth device ID::

    linux ... virtio_uml.device=/tmp/bt-0:40 virtio_uml.device=/tmp/bt-1:40

The UML kernel needs ``CONFIG_VIRTIO_UML`` and ``CONFIG_BT_VIRTIO``.

QEMU
----

QEMU has no dedicated vhost-user Bluetooth device, but its generic
``vhost-user-test-device-pci`` attaches a backend by device ID. The guest
memory must be shared, for example with a ``memory-backend-memfd`` and
``share=on``, as **test-runner(1)** sets up for virtio-fs::

    -chardev socket,id=bt0,path=/tmp/bt-vhost-bredrle
    -device vhost-user-test-device-pci,chardev=bt0,virtio-id=40,num_vqs=2,config_size=5

Time travel
===========

With ``time-travel=ext:[<id>:]<socket>``, the UML kernel's time only advances
when an external time controller allows it, and every process taking part in
the simulation connects to the same controller using the protocol in
``include/uapi/linux/um_timetravel.h``. A controller backend that takes part
in the simulation:

- takes part in the scheduling of the time controller (calendar), so its
  own events (such as radio activity) happen at simulated times; btvirt
  does this by being the calendar itself;
- uses in-band notifications, which ``virtio_uml`` enables when both
  ``VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS`` and
  ``VHOST_USER_PROTOCOL_F_SLAVE_REQ`` are negotiated. Kicks and calls are then
  messages on the vhost-user sockets instead of eventfds or pipes. This is
  required: a call file descriptor is a regular interrupt, which UML does not
  handle while it waits for the time controller, whereas on a back-end
  request it asks the time controller to run at the current time before
  acknowledging it. The backend therefore has to keep serving the time
  controller while it waits for the acknowledgment.

Packet timing, controller timeouts and the guest's HCI command timeouts are
then all measured on the same simulated clock, and runs are reproducible.

btvirt support
==============

**btvirt(1)** **-V** creates a vhost-user server socket,
``bt-vhost-bredrle``. Each connection gets a new BR/EDR/LE controller that
shares btvirt's emulated air, like the Unix socket servers of **-s**, so one
socket path can be given to several devices. Packets for the driver are
queued until it posts receive buffers.

With **--time**, btvirt is also the guests' time travel calendar and
offers in-band notifications, see `Time travel`_.

User Mode Linux and KVM
=======================

**test-runner(1)** runs guests under QEMU, normally with KVM. A User Mode
Linux guest with btvirt as calendar differs in where the controllers run and
which clock everything follows.

With QEMU and KVM, the guest's clock follows the host's real time; the
controllers are reached over emulated serial ports (**btvirt(1)** **-s**) or
are inside the guest (``/dev/vhci``, used by the kernel testers)::

    host                                          real time
    ┌──────────────────────────────────────────────────────────────┐
    │ btvirt -s                                                    │
    │   └ bt-server-bredrle ── H:4 ──┐                             │
    │ qemu (KVM)                     │                             │
    │   ┌ guest ─────────────────────┴───────────────────────────┐ │
    │   │ kernel ── hci_uart (btattach) ── hciN                  │ │
    │   │ bluetoothd, bluetoothctl                               │ │
    │   │ or: mgmt-tester ── hciemu ── /dev/vhci ── hciN         │ │
    │   └────────────────────────────────────────────────────────┘ │
    └──────────────────────────────────────────────────────────────┘

With User Mode Linux and time travel, the guests run as host processes, but
their clocks only advance when btvirt, as calendar, lets them; the
controllers are virtio devices served by btvirt, and their timers run on
the same simulated clock::

    host                                          simulated time
    ┌──────────────────────────────────────────────────────────────┐
    │ btvirt --time -V                                             │
    │   ├ bt-time ─────────── calendar ───────┬─────────────┐      │
    │   └ bt-vhost-bredrle ── vhost-user ──┬──┼─────────┐   │      │
    │                                      │  │         │   │      │
    │   ┌ linux (UML) ─────────────────────┴──┴┐  ┌─────┴───┴──┐   │
    │   │ time-travel=ext:.../bt-time          │  │ linux (UML)│   │
    │   │ virtio_uml ── virtio_bt ── hciN      │  │ ...        │   │
    │   │ bluetoothd, bluetoothctl             │  │            │   │
    │   └──────────────────────────────────────┘  └────────────┘   │
    └──────────────────────────────────────────────────────────────┘

How time travel works
---------------------

Two clocks matter: the host's real time, which flows continuously, and the
simulated time of the guests, which only advances when every participant
waits and then jumps straight to the next event. Computing takes no
simulated time, and idle time takes no real time::

    simulated time
          ▲
    250 ms┤                      ┌────────   computing: real time passes,
          │                      │           simulated time stands still
          │                      │
          │                      │ ◀──────── idle until the next timer:
     10 ms┤           ┌──────────┘           skipped, no real time passes
          │           │
      0 ms┼───────────┘
          └──────────────────────────────────────────────▶ real time

A guest joins the calendar with ``time-travel=ext:<socket>`` and talks to it
with the messages of ``include/uapi/linux/um_timetravel.h``. When it has
nothing left to do before its next timer, it asks to run again at that time
and waits; the calendar answers with RUN once every other participant waits
too and no earlier event is due::

    guest                                   calendar (btvirt)
      │ REQUEST(t=10 ms)  next timer        │
      ├────────────────────────────────────▶│
      │◀──────────────────────────── ACK ───┤
      │ WAIT              nothing to do     │
      ├────────────────────────────────────▶│ all others wait,
      │                                     │ earliest event: 10 ms
      │◀─────────────────────── RUN(10 ms) ─┤
      │ runs its timer at 10 ms             │

The calendar always runs the earliest event, a guest's request or one of
btvirt's own timers, e.g. those of the emulated controllers, so every
participant sees the same order of events on every run (lock-step)::

    guest A   ──run── WAIT ·············· RUN(t1) ──run── WAIT ·····
    guest B   ──run──────── WAIT ·························· RUN(t2) ─
    btvirt                        timer(t0)
    time      ─────────────────t0────────t1─────────────────t2─────▶
                               (no real time passes while all wait)

Asking before each timer costs about four messages per event. With
``FREE_UNTIL``, the calendar instead tells a guest how far it may run on its
own, up to the next event of any other participant, so a guest only waits
when it has to::

    guest A   ── RUN(t1) + FREE_UNTIL(t3) ─▶ runs its own events at
              t1 < ta < tb < t3 without any message, then WAITs for t3
    guest B   ············ request at t3 ·············· RUN(t3) ──▶
    time      ────t1─────ta──────tb──────────────────────t3────────▶

A virtio notification (kick) from the guest to btvirt may cause an event for
it at the current time, e.g. the controller's reply. The guest sends its
time (UPDATE) before each kick, and btvirt lowers its limit to that time
before acknowledging it, so the guest cannot run past the reply::

    guest     ─ UPDATE(tk) ─ kick ─┐ stopped at tk  ┌─ IRQ at tk ──▶
    btvirt         FREE_UNTIL(tk) ─┘ reply event ───┘
    time      ───────────────────tk──────────────────────────────▶

Busy-waiting does not work under time travel: as computing takes no
simulated time, a loop waiting for time to pass only advances by the 256 ns
UML charges for each system call. A main loop woken up over and over by a
socket it does not handle, e.g. one that hung up while only ``G_IO_IN`` is
watched, then needs tens of thousands of iterations for a 250 ms timer.

Which tests benefit
-------------------

Wall clock time of the kernel testers with **test-runner(1)**, same kernel
version and machine, User Mode Linux with seccomp, with and without
**-T**, all tests passing::

    tester            tests    KVM    UML    UML -T
    mgmt-tester         514   78.2   94.0     20.3
    l2cap-tester        111    9.2   10.2      5.6
    iso-tester          141    8.1   11.7      7.6
    sco-tester           30    4.6    3.1      2.0
    rfcomm-tester        11    3.6    1.5      1.5
    smp-tester            8    3.6    1.5      1.0
    ioctl-tester         28    4.1    2.1      1.5
    userchan-tester       4    2.6    1.0      1.0
    bnep-tester           1    2.6    1.0      1.0

UML runs the guest's system calls and context switches considerably slower
than KVM, as each one goes through the host, so testers exchanging many
small messages are slower without time travel. With it, tests that wait,
like most of mgmt-tester, take no real time for timers and timeouts. Small
testers are faster under UML, which starts in a fraction of a second.

Under UML, reading the clock is a system call through the host too, about
6 us against 0.02 us with KVM, where the vDSO answers it. GLib's main loop
reads it for every source on every iteration, so testers run on the
mainloop of ``src/shared/mainloop.c`` instead, which waits with
``epoll_wait()`` and one ``timerfd`` per timer and does not read the clock.

Time travel helps most when tests wait: timers, timeouts and idle time take
no real time, and the timing is the same on every run. It also lets
controllers outside the guests, such as btvirt's or a firmware simulation,
share the guests' clock, as in **test-functional(1)**.

SEE ALSO
========

**btvirt(1)**, **test-runner(1)**, **test-functional(1)**, **btattach(1)**

- vhost-user protocol: ``docs/interop/vhost-user.rst`` in the QEMU sources
- ``drivers/bluetooth/virtio_bt.c`` and
  ``include/uapi/linux/virtio_bt.h`` in the Linux sources

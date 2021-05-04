=========
hciattach
=========

-------------------------------------------------
attach serial devices via UART HCI to BlueZ stack
-------------------------------------------------

:Authors: - Maxim Krasnyansky <maxk@qualcomm.com>
          - Nils Faerber <nils@kernelconcepts.de>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: Jan 22, 2002
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**hciattach** [*OPTIONS*] <*tty*> <*type|id*> [*speed*] [*flow*] [*sleep*] [*bdaddr*]

**hciattach** -1

DESCRIPTION
===========

**hciattach(1)** is used to attach a serial UART to the Bluetooth stack as HCI
transport interface.

OPTIONS
=======

-i          Send break
-n          Don't detach from controlling terminal.
-p          Print the PID when detaching.
-t timeout  Specify an initialization timeout. Default is 5 seconds.
-s speed    Specify an initial speed instead of the hardware default.
-l          List all available configurations.
-r          Set the HCI device into raw mode. The kernel and bluetooth daemon
            will ignore it.
-h, --help  Show help options

ARGUMENTS
=========

*show*
    This specifies the serial device to attach. A leading /dev can be omitted.

    Examples: **/dev/ttyS1 ttyS2**

*type|id*
    The *type* or *id* of the Bluetooth device that is to be attached,
    i.e. vendor or other device specific identifier.
    Currently supported types are

.. list-table::
    :header-rows: 1
    :widths: auto

    * - *type*
      - Description

    * - any
      - Unspecified HCI_UART interface, no vendor specific options

    * - ericsson
      - Ericsson based modules

    * - digi
      - Digianswer based cards

    * - xircom
      - Xircom PCMCIA cards: Credit Card Adapter and Real Port Adapter

    * - csr
      - CSR Casira serial adapter or BrainBoxes serial dongle (BL642)

    * - bboxes
      - BrainBoxes PCMCIA card (BL620)

    * - swave
      - Silicon Wave kits

    * - bcsp
      - Serial adapters using CSR chips with BCSP serial protocol

    * - ath3k
      - Atheros AR300x based serial Bluetooth device

    * - intel
      - Intel Bluetooth device

.. list-table::
   :header-rows: 1
   :widths: auto

   * - | Supported ID
       | (manufacturer id, product id)
     - Description

   * - 0x0105, 0x080a
     - Xircom PCMCIA cards: Credit Card Adapter and Real Port Adapter

   * - 0x0160, 0x0002
     - BrainBoxes PCMCIA card (BL620)

*speed*
    The *speed* specifies the UART speed to use. Baudrates higher than 115200bps
    require vendor specific  initializations that are not implemented for all
    types of devices. In general the following speeds are supported:

    Supported vendor devices are automatically initialised to their respective
    best settings.

.. list-table::
   :header-rows: 0
   :widths: auto

   * - 9600

   * - 19200

   * - 38400

   * - 57600

   * - 115200

   * - 230400

   * - 460800

   * - 921600

*flow*
    If the *flow* is appended to the list of options then hardware flow control
    is forced on the serial link (**CRTSCTS**). All above mentioned device
    types have flow set by default. To force no flow control use *noflow*
    instead.

*sleep|nosleep*
    Enables hardware specific power management feature. If *sleep* is appended
    to the list of options then this feature is enabled. To disable this
    feature use *nosleep* instead. All above mentioned device types have
    *nosleep* set by default.

    Note: This option will only be valid for hardware which support hardware
    specific power management enable option from host.

*bdaddr*
    The bdaddr specifies the Bluetooth Address to use. Some devices (like
    the STLC2500) do not store the Bluetooth address in hardware memory.
    Instead it must be uploaded during the initialization process. If this
    argument is specified, then the address will be used to initialize the
    device. Otherwise, a default address will be used.

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

===========
test-runner
===========

**test-runner** [*OPTIONS*] -- <test-name>

DESCRIPTION
===========

**test-runner(1)** is used to test Kernel changes to the Bluetooth subsystem,
it lunches a virtual machine using qemu(1) and mounts the local filesystem
using virtio (9p).

OPTIONS
=======

:-a:--auto: Find tests and run them
:-b/--dbus: Start D-Bus system daemon
:-s/--dbus-session: Start D-Bus session daemon
:-d/--daemon: Start bluetoothd
:-m/--monitor: Start btmon
:-l/--emulator: Start btvirt
:-A/-audio[=path]: Start audio server
:-u/--unix[=path]: Provide serial device
:-U/--usb=<qemu_args>: Provide USB device
:-q/--qemu=<path>: QEMU binary
:-k/--kernel=<image>: Kernel image (bzImage)
:-h/--help: Show help options

Kernel
======

The test-runner tool requires a kernel that is at least build with these
minimal options for a successful boot. These options should be installed as
.config in the kernel source directory followed by:

.. code-block::

	make olddefconfig

After that a default kernel with the required options can be built. More
option (like the Bluetooth subsystem) can be enabled on top of this.

.. code-block::

	CONFIG_VIRTIO=y
	CONFIG_VIRTIO_PCI=y

	CONFIG_NET=y
	CONFIG_INET=y

	CONFIG_NET_9P=y
	CONFIG_NET_9P_VIRTIO=y

	CONFIG_9P_FS=y
	CONFIG_9P_FS_POSIX_ACL=y

	CONFIG_SERIAL_8250=y
	CONFIG_SERIAL_8250_CONSOLE=y
	CONFIG_SERIAL_8250_PCI=yCONFIG_DEBUG_KERNEL=y
	CONFIG_SERIAL_8250_NR_UARTS=4

	CONFIG_TMPFS=y
	CONFIG_TMPFS_POSIX_ACL=y
	CONFIG_TMPFS_XATTR=y

	CONFIG_DEVTMPFS=y
	CONFIG_DEBUG_FS=y

Bluetooth
---------

.. code-block::

	CONFIG_BT=y
	CONFIG_BT_BREDR=y
	CONFIG_BT_RFCOMM=y
	CONFIG_BT_BNEP=y
	CONFIG_BT_HIDP=y
	CONFIG_BT_LE=y

	CONFIG_BT_HCIUART=y
	CONFIG_BT_HCIUART_H4=y
	CONFIG_BT_HCIVHCI=y

	CONFIG_CRYPTO_CMAC=y
	CONFIG_CRYPTO_USER_API=y
	CONFIG_CRYPTO_USER_API_HASH=y
	CONFIG_CRYPTO_USER_API_SKCIPHER=y

	CONFIG_UNIX=y

	CONFIG_UHID=y

For 6lowpan-tester, the following are required:

.. code-block::

   CONFIG_6LOWPAN=y
   CONFIG_6LOWPAN_DEBUGFS=y
   CONFIG_BT_6LOWPAN=y
   CONFIG_PACKET=y


Lock debugging
--------------

To catch locking related issues the following set of kernel config
options may be useful:

.. code-block::

	CONFIG_DEBUG_KERNEL=y
	CONFIG_LOCKDEP_SUPPORT=y
	CONFIG_DEBUG_SPINLOCK=y
	CONFIG_DEBUG_LOCK_ALLOC=y
	CONFIG_DEBUG_ATOMIC_SLEEP=y
	CONFIG_PROVE_LOCKING=y
	CONFIG_PROVE_RCU=y
	CONFIG_LOCKDEP=y
	CONFIG_DEBUG_MUTEXES=y
	CONFIG_KASAN=y

EXAMPLES
========

Running mgmt-tester
-------------------

.. code-block::

	$ tools/test-runner -k /pathto/bzImage -- tools/mgmt-tester

Running a specific test of mgmt-tester
--------------------------------------

.. code-block::

	$ tools/test-runner -k /pathto/bzImage -- tools/mgmt-tester -s "<name>"

Running bluetoothctl with emulated controller
---------------------------------------------

.. code-block::

	$ tools/test-runner -l -d -k /pathto/bzImage -- client/bluetoothctl
	[CHG] Controller 00:AA:01:00:00:00 Pairable: yes
	[bluetooth]#

Running bluetoothctl with emulated controller and audio support
---------------------------------------------------------------

.. code-block::

	$ tools/test-runner -l -d -A -k /pathto/bzImage -- client/bluetoothctl
	[CHG] Controller 00:AA:01:00:00:00 Pairable: yes
	[bluetooth]#
	[CHG] Controller 00:AA:01:00:00:00 Pairable: yes
	[CHG] Controller 00:AA:01:00:00:00 Class: 0x00600000 (6291456)
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000110e-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000111f-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 00001200-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000110b-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000110a-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000110c-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 00001800-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 00001801-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000180a-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000111e-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 Class: 0x006c0000 (7077888)
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000110e-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000111f-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 00001200-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000110b-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000110a-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000110c-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 00001800-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 00001801-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000180a-0000-1000-8000-00805f9b34fb
	[CHG] Controller 00:AA:01:00:00:00 UUIDs: 0000111e-0000-1000-8000-00805f9b34fb

Running shell with host controller using btproxy
------------------------------------------------

.. code-block::

	$ tools/btproxy -u [1]
	$ tools/test-runner -u -d -k /pathto/bzImage -- /bin/bash [2]

Running shell with host controller USB-passthrough
--------------------------------------------------

In addition the above kernel config option the following is required:

.. code-block::

	CONFIG_USB=y
	CONFIG_USB_XHCI_HCD=y
	CONFIG_USB_XHCI_PLATFORM=y

.. code-block::

	$ tools/test-runner -U "usb-host,vendorid=<0xxxxx>,productid=<0xxxxx>" \
	-d -k /pathto/bzImage -- /bin/bash

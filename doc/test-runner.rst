===========
test-runner
===========

**test-runner** [*OPTIONS*] -- <test-name>

DESCRIPTION
===========

**test-runner(1)** is used to test Kernel changes to the Bluetooth subsystem,
it launches a virtual machine using qemu(1) with the host filesystem mounted
read-only inside the guest.

OPTIONS
=======

:-a:--auto: Find tests and run them
:-b/--dbus: Start D-Bus system daemon
:-s/--dbus-session: Start D-Bus session daemon
:-d/--daemon: Start bluetoothd
:-m/--monitor: Start btmon
:-l/--emulator[=num]: Start btvirt
:-A/-audio[=path]: Start audio server
:-u/--unix[=path]: Provide serial device
:-U/--usb=<qemu_args>: Provide USB device
:-P/--pcie=<qemu_args>: Provide PCIe device
:-q/--qemu=<path>: QEMU binary
:-H/--qemu-host-cpu: Use host CPU (requires KVM support)
:-k/--kernel=<image>: Kernel image (bzImage)
:-F/--virtiofs[=<path>]: Path to virtiofsd, or no to disable virtio-fs
:-o/--option=<opt>: Additional argument passed to QEMU
:-h/--help: Show help options

ARCHITECTURE
============

**test-runner(1)** is both the launcher and the guest ``init``.  When run
normally it builds a QEMU command line and starts QEMU, replacing itself
with it unless it has to stay around to clean up after a ``virtiofsd`` or
a passed-through PCIe device.  The same binary is re-executed inside the
guest as PID 1, where it sets up the sandbox and runs the requested
command::

    ┌────────────────────────────────────────────────────────┐
    │ test-runner (launcher)                                 │
    │   ├ virtiofsd (optional)  ←─── vhost-user ───┐         │
    │   └ qemu                                     │         │
    │      ┌──── guest ─────────────────────────────┴─────┐  │
    │      │ kernel (bzImage), init=test-runner           │  │
    │      │   ├ prepare_sandbox()                        │  │
    │      │   ├ attach controller (optional)             │  │
    │      │   ├ start dbus / bluetoothd / btmon / btvirt │  │
    │      │   ├ fork+exec <command>                      │  │
    │      │   └ reboot() when it exits                   │  │
    │      └──────────────────────────────────────────────┘  │
    └────────────────────────────────────────────────────────┘

There is no disk image.  The launcher's root filesystem is passed through
read-only and used as the guest root, so the guest runs the very same
BlueZ build tree that was just compiled.

Two passthrough implementations are supported.  When ``virtiofsd`` is
available, a ``virtiofsd`` process is started alongside QEMU and exports
``/`` over a vhost-user socket::

    virtiofsd --socket-path <tmpdir>/virtiofs --shared-dir / --readonly
              --tag /dev/root ...
    -chardev socket,id=virtiofs0,path=<tmpdir>/virtiofs
    -device  vhost-user-fs-pci,queue-size=1024,chardev=virtiofs0,tag=/dev/root
    -object  memory-backend-memfd,id=mem0,size=<mem>,share=on
    -numa    node,memdev=mem0
    -append  "... rootfstype=virtiofs root=/dev/root ..."

Since vhost-user requires the guest memory to be shareable, the machine
memory is backed by a memfd object.  Otherwise, the fallback is 9p::

    -fsdev local,id=fsdev-root,path=/,readonly=on,security_model=none
    -device virtio-9p-pci,fsdev=fsdev-root,mount_tag=/dev/root
    -append "... rootfstype=9p rootflags=trans=virtio,version=9p2000.u ..."

9p passthrough is noticeably more CPU intensive, so virtio-fs is used by
default whenever possible.

Either way the kernel command line also carries the launcher settings::

    -append "... init=<test-runner> TESTHOME=<cwd> TESTARGS='<command>' ..."

The ``TEST*`` variables carry the options given to the launcher over to
the guest instance.

As PID 1, ``prepare_sandbox()`` mounts ``sysfs``, ``proc``, ``devtmpfs``,
``devpts``, ``debugfs`` and ``tmpfs`` on ``/dev/shm``, ``/run`` and
``/tmp``.  Since the root is read-only, writable ``tmpfs`` instances are
also overlaid on ``/var/lib/bluetooth``, ``/etc/bluetooth``,
``/etc/dbus-1`` and ``/usr/share/dbus-1``.

Console and controller
----------------------

The guest console is a virtio console, ``/dev/hvc0``, multiplexed onto the
launcher's stdio, so kernel messages and the command output appear on the
terminal that started test-runner.

With ``-u``, the given UNIX socket (typically a **btproxy(1)** or
**btvirt(1)** server socket) is attached as a second virtio console::

    -chardev socket,path=<socket>,id=bt0
    -device  virtconsole,chardev=bt0,name=bt.0

In the guest this is ``/dev/hvc1``.  test-runner sets the ``N_HCI`` line
discipline with the H:4 protocol on it, so the kernel ``hci_uart`` driver
registers an ``hciX`` device.  The transport is therefore plain HCI H:4
carried over a virtio console to a UNIX socket on the launcher side::

    guest                                             launcher
    ┌───────────────────────────┐                 ┌──────────────────┐
    │ bluetoothd                │                 │ btvirt/btproxy   │
    │   ↕ mgmt / HCI sockets    │                 │                  │
    │ hci_uart  hci0            │   virtconsole   │                  │
    │   ↕ H:4                   │     bt.0        │                  │
    │ /dev/hvc1  ───────────────┼─────────────────┤  AF_UNIX socket  │
    └───────────────────────────┘                 └──────────────────┘

With ``-U`` a host USB controller is passed through instead (a
``qemu-xhci`` controller plus the given ``usb-host`` device), and with
``-P`` a PCIe controller is passed through via vfio-pci.  In both cases
the guest uses the normal ``btusb``/``btintel_pcie`` drivers.

Extra QEMU devices
------------------

``-o`` appends raw arguments to the QEMU command line.  This is how
additional channels between the launcher and the guest are added, for
example by **test-functional(1)**, which attaches its own virtio-serial
ports and a writable shared directory this way.

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
	CONFIG_VIRTIO_CONSOLE=y
	CONFIG_VIRTIO_FS=y
	CONFIG_FUSE_FS=y

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

Filesystem passthrough uses virtio-fs when ``virtiofsd`` is installed on the
host, otherwise 9p. Use ``-Fno`` for kernels without ``CONFIG_VIRTIO_FS``.

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

	CONFIG_CRYPTO_AES=y
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

Other
-----

For tests requiring accurate time inside the VM, possible with KVM:

.. code-block::

	CONFIG_HYPERVISOR_GUEST=y
	CONFIG_PARAVIRT=y
	CONFIG_KVM_GUEST=y

	CONFIG_PTP_1588_CLOCK=y
	CONFIG_PTP_1588_CLOCK_KVM=y
	CONFIG_PTP_1588_CLOCK_VMCLOCK=y


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

Running bluetoothctl with 2 emulated controller
------------------------------------------------

.. code-block::

	$ tools/test-runner -l2 -d -k /pathto/bzImage -- client/bluetoothctl
	[CHG] Controller 00:AA:01:01:00:01 Pairable: yes
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

Running shell with host controller PCIe-passthrough
---------------------------------------------------

In addition the above kernel config option the following is required:

.. code-block::

	CONFIG_PCI=y
	CONFIG_PCI_MSI=y
	CONFIG_ACPI=y
	CONFIG_BT_HCIBTINTEL_PCIE=y

On the host, an IOMMU must be enabled in the firmware and on the host kernel
command line (``intel_iommu=on`` or ``amd_iommu=on``). The controller itself
does not need any manual preparation: test-runner unbinds it from its current
driver, binds it to vfio-pci, and restores the original driver once the guest
exits.

.. code-block::

	$ tools/test-runner -P "vfio-pci,host=0000:00:14.3" \
	-d -k /pathto/bzImage -- /bin/bash

Note that unlike the other modes, PCIe-passthrough boots the guest with ACPI
and APIC enabled, as these are required for device enumeration and MSI
interrupt delivery.

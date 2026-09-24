==============
functional-hog
==============

DESCRIPTION
===========

HID over GATT (HoG) functional tests, `test/functional/test_hog.py`,
driven through **bluetoothctl(1)**. See **functional-testing(7)** for
the conventions used here, and **test-functional(1)** for how to run
the suite.

SETUP
=====

Two hosts, connected over LE, both running **bluetoothd(8)** with
``ControllerMode = le`` and ``ExportClaimedServices = read-write``, as
the HID Service is claimed by the input plugin of the HID host and
bluetoothctl has to write the HID Control Point:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |       LE        | host1                  |
	| central                | --------------> | peripheral             |
	| bluetoothctl           |                 | bluetoothctl           |
	| HID host               |   GATT (HIDS)   | hog-device[-sci].bt    |
	|                        | <============== | HID Service            |
	+------------------------+                 +------------------------+

	--> connection is initiated by      ==> reports flow towards

host1 starts `bluetoothctl` with a script registering a HID Service
(HIDS, ``00001812-0000-1000-8000-00805f9b34fb``) acting as a keyboard,
through the ``gatt.register-service``, ``gatt.register-characteristic``
and ``gatt.register-descriptor`` commands:

``client/scripts/hog-device.bt``
	HIDS without Shorter Connection Interval (SCI) support:

	- HID Information (0x2A4A): ``11 01 00 02``, i.e. bcdHID 1.11,
	  bCountryCode 0x00 and Flags NormallyConnectable.
	- Report Map (0x2A4B): keyboard with Report ID 1.
	- Report (0x2A4D), with a Report Reference descriptor (0x2908)
	  ``01 01``, i.e. Report ID 1, Input Report.
	- Protocol Mode (0x2A4E): ``01``, i.e. Report Protocol Mode.
	- HID Control Point (0x2A4C).

``client/scripts/hog-device-sci.bt``
	Same as above, with SCI support:

	- HID Information (0x2A4A): ``11 01 00 06``, i.e. the SCI
	  Supported flag (0x04) is set as well.
	- HID SCI Mode (0x2C39): ``00``, i.e. None, with the notify
	  property so the HID device can confirm a mode change.
	- HID SCI Information (0x2C3A): ``08 01 08 00 50 00 08 00``, i.e.
	  Minimum Supported Connection Interval 1 ms, and one subgroup
	  with Min 1 ms, Max 10 ms and Stride 1 ms (in units of 0.125 ms).

Both scripts set the advertising data to the HIDS UUID and the
keyboard appearance (0x03C1). The same scripts can be used manually to
emulate a HoG device:

.. code-block::

	$ bluetoothctl --init-script client/scripts/hog-device-sci.bt
	[bluetoothctl]> advertise on

host0 runs a plain `bluetoothctl`, and both use
``-a auto:NoInputNoOutput`` so pairing is Just Works.

TEST CASES
==========

test_hog[no-sci]
----------------

:Setup: As above, with ``client/scripts/hog-device.bt`` on host1.

:Steps:
	1. host1: start `bluetoothctl` with the script.
	2. host0: ``scan on``; host1: ``advertise on``.
	3. host0: ``pair <host1 bdaddr>``.
	4. host0: ``info <host1 bdaddr>``.
	5. host0: ``gatt.select-attribute 2a4a`` and ``gatt.read``.
	6. host0: ``gatt.select-attribute 2a4d`` and ``gatt.notify on``.
	7. host1: ``gatt.select-attribute local
	   /org/bluez/app/service0/chrc2``, then for each report
	   ``gatt.write "<report>"``: ``00 00 04 00 00 00 00 00`` (a
	   pressed), ``02 00 05 00 00 00 00 00`` (Left Shift + b pressed)
	   and ``00 00 00 00 00 00 00 00`` (released).

:Expected:
	1. ``Application registered`` on host1.
	2. ``Advertising object registered`` on host1 and the device found
	   on host0.
	3. ``Pairing successful`` and ``ServicesResolved: yes``.
	4. ``Human Interface Device (00001812-...)`` is listed in the UUIDs.
	5. HID Information reads ``11 01 00 02``:

	   .. code-block::

		[bluetoothctl]> gatt.select-attribute 2a4a
		[bluetoothctl]> gatt.read
		Attempting to read /org/bluez/hci0/dev_XX/serviceXX/charXX
		  11 01 00 02                                      ....

	6. ``Notify started``, and the Report subscribed on host1
	   (``Notify sock acquired``, as bluetoothd on host1 forwards the
	   subscription with AcquireNotify, the input plugin of host0
	   having already enabled the notifications).
	7. Each report is notified to host0, in order:

	   .. code-block::

		[CHG] Attribute /org/bluez/hci0/dev_XX/serviceXX/charXX Value:
		  00 00 04 00 00 00 00 00                          ........

:Notes: The service is checked at the GATT level only, so the test
	does not depend on the kernel supporting uhid. The HID Service is
	claimed by the input plugin on host0, but it is still exported over
	D-Bus, read-write as configured in SETUP (see
	``ExportClaimedServices`` in **bluetoothd(8)**), so it can be read
	with bluetoothctl.

test_hog[sci]
-------------

:Setup: As above, with ``client/scripts/hog-device-sci.bt`` on host1.

:Steps: As for test_hog[no-sci], then:

	8. host0: ``gatt.select-attribute 2c39`` and ``gatt.read``.
	9. host0: ``gatt.select-attribute 2c3a`` and ``gatt.read``.
	10. host0: ``gatt.select-attribute 2c39`` and ``gatt.notify on``.
	11. host0: ``gatt.select-attribute 2a4c`` and ``gatt.write "0x03"``,
	    i.e. Enable SCI Fast mode written to the HID Control Point.
	12. host0: ``mgmt.conn-subrate <host1 bdaddr> 0x0008 0x0010 1 1 0 0
	    0x01f4``, i.e. interval 1 ms to 2 ms, within the range given in
	    HID SCI Information, no subrating, no latency and 5 s
	    supervision timeout.
	13. host1: ``gatt.select-attribute local
	    /org/bluez/app/service0/chrc5`` and ``gatt.write "0x03"``,
	    notifying the new mode with HID SCI Mode.

:Expected: As for test_hog[no-sci], except HID Information reads
	``11 01 00 06``, then:

	8. HID SCI Mode reads ``00``.
	9. HID SCI Information reads ``08 01 08 00 50 00 08 00``.
	10. ``Notify started``. HID SCI Mode is already subscribed on host1,
	    by the input plugin of host0 once HID Information tells SCI is
	    supported.
	11. host1 receives the write, over the socket acquired with
	    AcquireWrite as it is a Write Without Response:

	    .. code-block::

		[CHG] Attribute /org/bluez/app/service0/chrc4 (HID Control Point) written:
		  03                                               .

	12. ``Connection Subrate loaded successfully``, then the MGMT
	    Connection Subrate event with the new interval on both hosts:

	    .. code-block::

		hci0 XX type LE Public connection subrate interval 0x0008 subrate 0x0001 latency 0x0000 cont_num 0x0000 timeout 0x01f4

	13. The new mode is notified to host0, confirming it has been
	    changed, which the input plugin reports in the
	    **bluetoothd(8)** debug output (``SCI Mode changed: 0x03``):

	    .. code-block::

		[CHG] Attribute /org/bluez/hci0/dev_XX/serviceXX/charXX Value:
		  03                                               .

	.. code-block::

		[bluetoothctl]> gatt.select-attribute 2c39
		[bluetoothctl]> gatt.read
		  00                                               .

		[bluetoothctl]> gatt.select-attribute 2c3a
		[bluetoothctl]> gatt.read
		  08 01 08 00 50 00 08 00                          ....P...

:Notes: As the SCI Supported flag is set, the input plugin on host0
	reads HID SCI Mode and HID SCI Information as well, which can be
	seen in the **bluetoothd(8)** debug output (``SCI Mode:`` and
	``SCI Info:``), and enables the notifications of HID SCI Mode.

	As specified by HOGP.TS 4.6.1, the HID host requests a HID SCI
	mode by writing it to the HID Control Point (0x02 Default, 0x03
	Fast, 0x04 Low Power, 0x05 Full Range), HID SCI Mode being Read and
	Notify only. The Control Point is written with bluetoothctl, as the
	input plugin has no D-Bus API to request a mode.

	The HID device is meant to change the connection rate once the
	mode is written, but the kernel only issues the LE Connection Rate
	Request as central, so the connection rate is changed by the HID
	host. This requires
	the controllers to support Shorter Connection Intervals, which
	btvirt emulates as a BR/EDR/LE 6.2 controller.

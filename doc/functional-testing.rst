==================
functional-testing
==================

DESCRIPTION
===========

This document describes the test cases run by **test-functional(1)**,
i.e. the test modules under `test/functional`. For how to build,
configure and run the suite, see **test-functional(1)**.

This document covers the core test cases. Tests for a specific profile
are documented separately:

- **functional-avrcp(7)**: `test/functional/test_avrcp.py`
- **functional-obex(7)**: `test/functional/test_obex.py`

Each test case is described as:

:Setup: The hosts, the plugins running on them and their
	configuration, with a topology diagram showing how many hosts are
	used and the role each of them takes.
:Steps: The actions the test performs, in order.
:Expected: What has to be observed for the test to pass.
:Notes: Caveats, and why the test is written the way it is.

In the topology diagrams, ``-->`` points at the host that accepts the
connection, and ``==>`` at the host the data flows towards.

MARKERS
=======

Markers are defined in `test/pytest.ini` and can be selected with
``-m``:

``vm``
	Test requires a VM image (``--kernel``). Skipped if none is
	available.

``sa``
	Security advisory regression test. Added automatically to tests
	whose name matches ``_GHSA_xxxx_xxxx_xxxx``.

``tester``
	Kernel testers. These exercise the kernel rather than BlueZ
	userspace and are excluded from ``make check-functional``.

test_agent.py
=============

Pairing over D-Bus, driven directly through the **org.bluez** API using
the `Agent` plugin on both hosts.

test_agent_pair_bredr[accept]
-----------------------------

:Setup: Two hosts, each running `bluetoothd` with an agent registered
	on D-Bus.

	.. code-block::

		+--------------------+                 +--------------------+
		| host0              |      BR/EDR     | host1              |
		| bluetoothd, agent  | --------------> | bluetoothd, agent  |
		| discovers, pairs   |                 | pairable,          |
		|                    |                 | discoverable       |
		+--------------------+                 +--------------------+

:Steps:
	1. host0 calls ``org.bluez.Adapter1.StartDiscovery``.
	2. host1 sets ``Pairable`` and ``Discoverable`` to true.
	3. Wait until host0 has a device object for host1.
	4. host0 calls ``org.bluez.Device1.Pair``.
	5. Both agents reply to ``org.bluez.Agent1.RequestConfirmation``.

:Expected:
	1. ``StartDiscovery`` replies.
	2. host0 discovers host1.
	3. Both agents receive ``RequestConfirmation`` with the *same*
	   passkey.
	4. ``org.bluez.Device1.Pair`` replies successfully.

:Notes: This test is also used as the ``paired_hosts_bredr`` fixture
	(see `test/functional/conftest.py`), which other tests reuse to
	get two already paired hosts.

test_agent_pair_bredr[reject]
-----------------------------

:Setup: As above.

:Steps:
	1. Pair as above, up to the confirmation.
	2. host0 accepts the confirmation, host1 replies with an error.

:Expected: ``org.bluez.Device1.Pair`` returns an error.

test_bluetoothctl.py
====================

End to end tests of the **bluetoothctl(1)** client, driven through its
interactive prompt or its command line.

test_bluetoothctl_pair_bredr
----------------------------

:Setup: Two hosts, each running `bluetoothctl`.

	.. code-block::

		+--------------------+                 +--------------------+
		| host0              |      BR/EDR     | host1              |
		| bluetoothctl       | --------------> | bluetoothctl       |
		| scan on, pair      |                 | pairable on,       |
		|                    |                 | discoverable on    |
		+--------------------+                 +--------------------+

:Steps:
	1. host0: ``scan on``.
	2. host1: ``pairable on`` and ``discoverable on``.
	3. host0: ``pair <host1 bdaddr>`` once host1 is discovered.
	4. Both sides answer ``yes`` to the passkey confirmation.

:Expected:
	1. ``Controller <host0> Discovering: yes``.
	2. ``Changing pairable on succeeded`` and
	   ``Controller <host1> Discoverable: yes``.
	3. host0 prints ``Device <host1>``, then both sides prompt to
	   confirm the *same* passkey.
	4. host0 prints ``Pairing successful``.

test_bluetoothctl_pair_le
-------------------------

:Setup: Two hosts, each running `bluetoothd` with
	``ControllerMode = le`` and `bluetoothctl`.

	.. code-block::

		+--------------------+                 +--------------------+
		| host0              |        LE       | host1              |
		| bluetoothctl       | --------------> | bluetoothctl       |
		| scan on, pair      |                 | advertise on       |
		+--------------------+                 +--------------------+

:Steps:
	1. host0: ``scan on``.
	2. host1: ``advertise on``.
	3. host0: ``pair <host1 bdaddr>`` once host1 is discovered.
	4. Answer the passkey confirmation, or enter the passkey on host1
	   if legacy pairing was used.

:Expected:
	1. ``Controller <host0> Discovering: yes``.
	2. ``Advertising object registered``.
	3. host0 prints ``Device <host1>``.
	4. host0 prints ``Pairing successful``.

:Notes: If the controller is power cycled before `bluetoothd` starts,
	which is what the tester does, enabling Secure Connections Host
	Support may fail and pairing falls back to legacy passkey entry.
	The test accepts both, but warns when the legacy path is taken.

test_bluetoothctl_show
----------------------

:Setup: One host running `bluetoothd`, reused across the tests of this
	module.

	.. code-block::

		+--------------------------+
		| host0                    |
		| bluetoothd, bluetoothctl |
		+--------------------------+

:Steps: Run ``bluetoothctl show``.

:Expected: Exit status 0, and the output reports
	``Controller <bdaddr>``, ``Powered:`` and ``Discoverable: no``.

test_bluetoothctl_list
----------------------

:Setup: As above.

:Steps: Run ``bluetoothctl list``.

:Expected: Exit status 0, and the controller is listed and marked
	``[default]``.

test_bluetoothctl_script_show
-----------------------------

:Setup: As above.

:Steps: Run ``show`` through ``bluetoothctl --init-script``.

:Expected: Same as ``test_bluetoothctl_show``.

:Notes: Covers the script input path rather than the command line.

test_bluetoothctl_script_list
-----------------------------

:Setup: As above.

:Steps: Run ``list`` through ``bluetoothctl --init-script``.

:Expected: Same as ``test_bluetoothctl_list``.

test_btmgmt.py
==============

test_btmgmt_info
----------------

:Setup: One host with a controller and no `bluetoothd` running.

	.. code-block::

		+--------------------------+
		| host0                    |
		| btmgmt, no bluetoothd    |
		+--------------------------+

:Steps: Run ``btmgmt --index 0 info``.

:Expected: Exit status 0, and the output contains
	``addr <bdaddr>`` for the controller of the host.

:Notes: Skipped if `btmgmt` is not built. Checks the mgmt interface is
	usable without a daemon.

test_adv_monitor.py
===================

test_adv_monitor_GHSA_hhgc_hfgf_8m4x
------------------------------------

:Setup: One host running `bluetoothd` with ``Experimental = true``.

	.. code-block::

		+---------------------------------+
		| host0                           |
		| bluetoothd (Experimental)       |
		| advertisement monitor app       |
		+---------------------------------+

:Steps:
	1. Register an advertisement monitor application exposing one
	   monitor with 8 patterns of 31 bytes each.
	2. Call
	   ``org.bluez.AdvertisementMonitorManager1.RegisterMonitor``.

:Expected: ``RegisterMonitor`` completes, with either a reply or an
	error, and `bluetoothd` does not crash.

:Notes: Regression test for NN-2026-0142, a heap overflow caused by
	``uint8`` length truncation when the mgmt command carrying the
	patterns exceeds 255 bytes (`src/adv_monitor.c`). The overflow
	happens during the ``ADD_ADV_PATTERNS_MONITOR`` mgmt call, before
	the monitor is activated. Marked ``sa``.

test_kernel_testers.py
======================

Kernel side tests: they run the BlueZ testers inside the VM against the
kernel under test. Excluded from ``make check-functional``; run them
with ``test/test-functional -m tester``.

test_kernel_tester[<tester>]
----------------------------

:Setup: One host, without a controller, reused across the parameters.

	.. code-block::

		+----------------------------------+
		| host0                            |
		| kernel under test, no controller |
		| tester creates its own hciX      |
		+----------------------------------+

:Steps:
	1. Run the tester in the VM.
	2. Parse its test summary.

:Expected: No test is reported as ``Failed`` or ``Timed out``, except
	the ones listed in the ``XFAIL`` table of the module.

:Notes: The testers covered are `mgmt-tester`, `smp-tester`,
	`l2cap-tester`, `rfcomm-tester`, `sco-tester`, `iso-tester`,
	`mesh-tester`, `ioctl-tester`, `bnep-tester`, `userchan-tester`
	and `6lowpan-tester`. A known failing case that unexpectedly
	passes emits an ``XPASS`` warning, so the entry can be dropped.
	Marked ``tester``.

test_kernel_selftest
--------------------

:Setup: As above.

:Steps: Run `check-selftest`, which reads the kernel Bluetooth selftest
	results.

:Expected: Exit status 0, and the output contains ``PASS`` and no
	``FAIL``.

:Notes: Skipped if ``CONFIG_BT_SELFTEST`` is not enabled, which is the
	case when the output is empty.

test_tests.py
=============

test_formatting
---------------

:Setup: None, the test does not use a VM.

:Steps: Run `Black <https://black.readthedocs.io/en/stable/>`__ in
	check mode over `test/functional`.

:Expected: The sources are formatted. Formatting problems are reported
	as a warning, not as a failure.

:Notes: Skipped if `black` is not installed.

ADDING TEST CASES
=================

When adding a test module or case, document it here as well, or in the
matching profile document. For regression tests of security advisories,
name the test ``test_<area>_GHSA_xxxx_xxxx_xxxx`` so it is
automatically marked ``sa``, and describe the issue it covers.

See **test-functional(1)** for how tests are written.

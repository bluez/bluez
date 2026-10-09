=================
functional-bearer
=================

DESCRIPTION
===========

Bearer functional tests, `test/functional/test_bearer.py`, covering the
**org.bluez.Bearer.LE(5)** and **org.bluez.Bearer.BREDR(5)** interfaces
of the device objects. See **functional-testing(7)** for the conventions
used here, and **test-functional(1)** for how to run the suite.

SETUP
=====

Two hosts, both running **bluetoothd(8)** with ``Experimental = true``,
as the bearer interfaces are experimental, and with the MIDI plugin
disabled (``-P midi``), as the MIDI profile would ask to pair as soon as
it finds the MIDI service the other host exports:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |   LE or BR/EDR  | host1                  |
	| bluetoothd, agent      | --------------> | bluetoothd, agent      |
	| connects or pairs      |                 | advertises (LE) or is  |
	|                        |                 | discoverable (BR/EDR)  |
	+------------------------+                 +------------------------+

	--> connection is initiated by

The LE tests run **bluetoothd(8)** with ``ControllerMode = le`` and have
host1 register a connectable advertisement, as bluetoothd does not
advertise on its own in that mode. Both hosts register an agent with
the ``NoInputNoOutput`` capability, so pairing is Just Works.

Each host reads the bearer properties of the device object it has for
the other host, and records the ``Disconnected`` signals of the bearer
interfaces.

TEST CASES
==========

test_bearer_le_connect
----------------------

:Setup: As above, over LE.

:Steps:
	1. host0 calls ``org.bluez.Adapter1.StartDiscovery`` and waits for a
	   device object for host1.
	2. host0 calls ``org.bluez.Bearer.LE1.Connect`` on it.
	3. Both hosts read ``Connected`` and ``Role`` on the LE bearer.
	4. host0 calls ``org.bluez.Bearer.LE1.Disconnect``.

:Expected:
	1. host1 is discovered.
	2. ``Connect`` replies.
	3. ``Connected`` is true on both hosts. ``Role`` is ``peripheral`` on
	   host0, which initiated the connection, and ``central`` on host1.
	4. ``Disconnect`` replies, and the LE bearer emits ``Disconnected``
	   with ``org.bluez.Reason.Local`` on host0 and
	   ``org.bluez.Reason.Remote`` on host1. ``Connected`` is false on
	   both hosts and ``Role`` is no longer present.

test_bearer_le_connectable
--------------------------

:Setup: As above, over LE.

:Steps: host0 discovers host1, as in test_bearer_le_connect, and reads
	``Connectable`` on the LE bearer.

:Expected: ``Connectable`` is true, as host1 advertises connectable.

test_bearer_le_not_connectable
------------------------------

:Setup: As above, over LE, except host1 registers an advertisement of
	type ``broadcast`` that is not discoverable, i.e. it advertises as a
	broadcaster, with the service UUID
	``6e2c1d84-7a3b-4f50-9c1e-5b8d2a7f0e13``, and runs no agent. host0
	runs **bluetoothd(8)** with ``FilterDiscoverable = false``, as
	otherwise it only creates device objects for discoverable
	advertisers.

:Steps:
	1. host0 calls ``org.bluez.Adapter1.StartDiscovery`` and waits for a
	   device object advertising the service UUID.
	2. host0 reads ``Connectable`` on its LE bearer.

:Expected:
	1. The device is discovered.
	2. ``Connectable`` is false.

:Notes: The kernel sends non-connectable advertising from a
	non-resolvable private address, so the device object has that
	address rather than host1's, and host0 finds it by the advertised
	service UUID instead.

test_bearer_le_pair
-------------------

:Setup: As above, over LE.

:Steps:
	1. host0 pairs with host1, which authorizes the pairing.
	2. Both hosts read ``Paired``, ``Bonded`` and ``Connected`` on the LE
	   bearer, and ``Paired`` on the BR/EDR bearer.

:Expected:
	1. ``org.bluez.Device1.Pair`` replies.
	2. ``Paired``, ``Bonded`` and ``Connected`` are true on the LE bearer
	   of both hosts. The BR/EDR bearer is not present, as bluetoothd
	   runs with ``ControllerMode = le``.

test_bearer_bredr_pair
----------------------

:Setup: As above, over BR/EDR.

:Steps:
	1. host0 pairs with host1 as in test_agent_pair_bredr[accept], see
	   **functional-testing(7)**.
	2. Both hosts read ``Paired``, ``Bonded``, ``Connected``,
	   ``Connectable`` and ``Role`` on the BR/EDR bearer.
	3. host0 calls ``org.bluez.Bearer.BREDR1.Disconnect``.

:Expected:
	1. Both agents confirm the same passkey and ``Pair`` replies.
	2. ``Paired``, ``Bonded``, ``Connected`` and ``Connectable`` are true
	   on both hosts, and ``Role`` is not present, as it is only
	   reported for LE.
	3. ``Disconnect`` replies, and the BR/EDR bearer emits
	   ``Disconnected`` with ``org.bluez.Reason.Local`` on host0 and
	   ``org.bluez.Reason.Remote`` on host1. ``Connected`` is false on
	   both hosts.

:Notes: The ACL link is terminated a short time after the profiles are
	disconnected, so the ``Disconnected`` signal follows the reply to
	``Disconnect``.

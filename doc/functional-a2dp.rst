===============
functional-a2dp
===============

DESCRIPTION
===========

A2DP functional tests, `test/functional/test_a2dp.py`, driven through
**bluetoothctl(1)**. See **functional-testing(7)** for the conventions
used here, and **test-functional(1)** for how to run the suite.

SETUP
=====

Two hosts, connected over BR/EDR:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |     BR/EDR      | host1                  |
	| central                | --------------> | peripheral             |
	| bluetoothctl           |                 | bluetoothctl           |
	| a2dp-source.bt         |   AVDTP (SBC)   | a2dp-sink.bt           |
	| A2DP Source endpoint   | ==============> | A2DP Sink endpoint     |
	+------------------------+                 +------------------------+

	--> connection is initiated by      ==> audio flows towards

Both hosts start `bluetoothctl` with an endpoint registration script:

``client/scripts/a2dp-source.bt`` on host0
	Registers a local A2DP Source endpoint
	(``0000110a-0000-1000-8000-00805f9b34fb``) with SBC. host0 is the
	central, i.e. the device sending audio.

``client/scripts/a2dp-sink.bt`` on host1
	Registers a local A2DP Sink endpoint
	(``0000110b-0000-1000-8000-00805f9b34fb``) with SBC. host1 is the
	peripheral, i.e. the device receiving audio.

The endpoints are registered *before* pairing, so the SDP records are
in place when the peer resolves the services. The hosts are then paired
over BR/EDR, trust each other, and the central connects.

TEST CASES
==========

test_a2dp_transport_created
---------------------------

:Setup: As above.

:Steps:
	1. Start `bluetoothctl` with the scripts on both hosts.
	2. Pair over BR/EDR: ``scan on`` on the central,
	   ``pairable on`` and ``discoverable on`` on the peripheral,
	   ``pair``, and confirm the passkey on both sides.
	3. ``trust`` the peer on both sides.
	4. Central: ``connect <peripheral bdaddr>``.
	5. Central: ``transport.show <transport>``.
	6. Peripheral: ``transport.show <transport>``.

:Expected:
	1. ``Endpoint /local/endpoint/ep0 registered`` on both hosts.
	2. ``Pairing successful``.
	3. ``trust succeeded`` on both hosts.
	4. ``Connection successful``, the stream is configured and a
	   transport appears on *both* hosts.
	5. The central transport reports
	   ``UUID: Audio Source (0000110a-...)``, ``Codec: 0x00``,
	   ``Media Codec: SBC``, ``Device:`` pointing at the peripheral
	   device object, and ``State: idle``.
	6. The peripheral transport reports
	   ``UUID: Audio Sink (0000110b-...)`` and ``Codec: 0x00``.

:Notes: A transport reports the UUID of the *local* endpoint it was
	created for, which is why the two sides differ. The transport
	paths differ as well: the central knows the remote SEP, so it uses
	``.../dev_XX/sepN/fdN``, while the peripheral uses
	``.../dev_XX/fdN``.

	Registering the endpoints after pairing makes ``connect`` fail
	with ``org.bluez.Error.BREDR.ProfileUnavailable``, as the services
	were already resolved. Without ``trust``, the peripheral blocks on
	an ``org.bluez.Agent1.AuthorizeService`` prompt.

test_a2dp_transport_acquire
---------------------------

:Setup: As above, with the transport already created.

:Steps: Central: ``transport.acquire <transport>``.

:Expected:
	1. ``Acquire successful: fd <fd> MTU <read>:<write>``.
	2. The transport moves to ``State: active``.

:Notes: Acquiring on the source side starts the stream, so the
	peripheral does not have to acquire its own transport.

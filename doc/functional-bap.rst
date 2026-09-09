==============
functional-bap
==============

DESCRIPTION
===========

BAP (LE Audio) functional tests, `test/functional/test_bap.py`, driven
through **bluetoothctl(1)**. See **functional-testing(7)** for the
conventions used here, and **test-functional(1)** for how to run the
suite.

SETUP
=====

Two hosts, connected over LE:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |      LE ACL     | host1                  |
	| initiator (central)    | --------------> | acceptor (peripheral)  |
	| bluetoothctl -a auto   |                 | bluetoothctl -a auto   |
	| bap-source-lc3.bt      |  CIS 0x00 (LC3) | bap-sink-lc3.bt        |
	| PAC Source endpoint    | ==============> | PAC Sink endpoint      |
	|                        |  CIS 0x01 (LC3) |                        |
	|                        | ==============> |                        |
	+------------------------+                 +------------------------+

	one CIG holding one CIS per audio location

	--> connection is initiated by      ==> audio flows towards

BAP requires the ISO socket support, so all hosts run `bluetoothd`
with:

.. code-block::

	[General]
	Experimental = true
	KernelExperimental = true
	ControllerMode = le

`bluetoothctl` is started with ``-a auto``, so pairing and service
authorization are accepted without prompting, and with an endpoint
registration script:

``client/scripts/bap-source-lc3.bt`` on host0
	Registers a local PAC Source endpoint
	(``00002bcb-0000-1000-8000-00805f9b34fb``) with LC3. host0 is the
	initiator, i.e. the device sending audio.

``client/scripts/bap-sink-lc3.bt`` on host1
	Registers a local PAC Sink endpoint
	(``00002bc9-0000-1000-8000-00805f9b34fb``) with LC3. host1 is the
	acceptor, i.e. the device receiving audio.

TEST CASES
==========

test_bap_unicast_transport_created
----------------------------------

:Setup: As above.

:Steps:
	1. Start `bluetoothctl` with the scripts on both hosts.
	2. Pair over LE: ``scan on`` on the initiator, ``advertise on`` on
	   the acceptor, then ``pair``.
	3. Initiator: ``endpoint.config <remote endpoint>
	   /local/endpoint/ep0 16_2_1``, using the remote PAC Sink endpoint
	   exposed once the services are resolved.
	4. Initiator: ``transport.show <transport>`` for each transport.

:Expected:
	1. ``Endpoint /local/endpoint/ep0 registered`` on both hosts.
	2. ``Pairing successful``.
	3. The remote endpoint appears as
	   ``Endpoint /org/bluez/hci0/dev_XX/pac_sinkN``, and configuring it
	   creates one transport per location on *both* hosts.
	4. Each transport of the initiator reports the local PAC Source
	   UUID (``00002bcb-...``), ``Codec: 0x06`` for LC3, ``Device:``
	   pointing at the acceptor device object, and ``State: idle``.

:Notes: The endpoints are registered with the locations and contexts
	`bluetoothctl` uses itself, ``0x0fff`` for the sink and ``0x000f``
	for the source. With narrower Supported Contexts the acceptor
	rejects the ``Enable`` with ``Invalid Metadata``, because the
	metadata of the stream carries the ``Unspecified`` context.

test_bap_unicast_transport_acquire
----------------------------------

:Setup: As above, with the transports already created.

:Steps: Initiator: ``transport.acquire <transport> <transport>``, for
	all the transports that were created.

:Expected: ``Acquire successful: fd <fd> MTU <read>:<write>`` for each
	transport, and each of them moves to ``State: active``.

:Notes: *All* the transports have to be acquired: the controller only
	creates the CIS once every CIS of the CIG is ready, so acquiring a
	single transport leaves the stream waiting until it times out,
	without ``LE Create CIS`` ever being sent.

	The acceptor does not have to acquire its transports for the CIS to
	be established, as `bluetoothd` sets up the ISO listener on its own
	when the stream is enabled.

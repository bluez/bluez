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

BAP requires the ISO socket support, so all hosts run `bluetoothd`
with:

.. code-block::

	[General]
	Experimental = true
	KernelExperimental = true
	ControllerMode = le

`bluetoothctl` is started with ``-a auto``, so pairing and service
authorization are accepted without prompting, and with an endpoint
registration script from `client/scripts`.

UNICAST
=======

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

``client/scripts/bap-source-lc3.bt`` on host0
	Registers a local PAC Source endpoint
	(``00002bcb-0000-1000-8000-00805f9b34fb``) with LC3. host0 is the
	initiator, i.e. the device sending audio.

``client/scripts/bap-sink-lc3.bt`` on host1
	Registers a local PAC Sink endpoint
	(``00002bc9-0000-1000-8000-00805f9b34fb``) with LC3. host1 is the
	acceptor, i.e. the device receiving audio.

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

BROADCAST
=========

Two hosts, with no connection between them:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |    extended +   | host1                  |
	| Broadcast Source       |    periodic     | Broadcast Sink         |
	| bluetoothctl -a auto   |   advertising   | bluetoothctl -a auto   |
	| broadcast-source.bt    | --------------> | broadcast-sink.bt      |
	| or -pbp variant        |                 |                        |
	| BCAA endpoint (0x1852) |   BIS 0 (LC3)   | BAA endpoint (0x1851)  |
	|                        | ==============> |                        |
	+------------------------+                 +------------------------+

	no ACL is established: the sink syncs to the periodic advertising,
	reads the BASE from it and then syncs to the BIG

	--> advertising is scanned by       ==> audio flows towards

``client/scripts/broadcast-source.bt`` on host0
	Registers a Broadcast Source endpoint
	(``00001852-0000-1000-8000-00805f9b34fb``) with LC3, configures it
	with the 16_2_1 preset and acquires the transport, which starts
	the broadcast. The stream is encrypted with the broadcast code
	`bluetoothctl` uses by default.

``client/scripts/broadcast-source-pbp.bt`` on host0
	As above, but adds the Public Broadcast Announcement service
	(``0x1856``) to the extended advertising first, so the broadcast
	is a Public Broadcast Profile one.

``client/scripts/broadcast-sink.bt`` on host1
	Registers a Broadcast Sink endpoint
	(``00001851-0000-1000-8000-00805f9b34fb``) with LC3 and scans.

Both test cases run for each source, i.e. with the ``lc3`` parameter
for a plain broadcast and with ``pbp`` for a Public Broadcast Profile
one.

test_bap_broadcast_transport_created[lc3|pbp]
---------------------------------------------

:Setup: As above.

:Steps:
	1. Start `bluetoothctl` with the source script on host0.
	2. Start `bluetoothctl` with the sink script on host1.
	3. Sink: ``transport.show <transport>``.

:Expected:
	1. ``Endpoint /local/endpoint/ep0 registered``, then
	   ``Acquire successful: fd <fd> MTU <read>:<write>`` on the
	   source, i.e. it is broadcasting.
	2. The sink syncs to the periodic advertising on its own and
	   creates a transport per BIS described by the BASE, under
	   ``/org/bluez/hci0/dev_XX/sidN/bisM/fdK``.
	3. The transport reports ``Codec: 0x06`` for LC3 and
	   ``State: idle``.

:Notes: The sink does not need a Broadcast Assistant here: it scans,
	finds the Broadcast Source and syncs by itself.

test_bap_broadcast_transport_acquire[lc3|pbp]
---------------------------------------------

:Setup: As above, with the transport already created.

:Steps:
	1. Sink: ``transport.select <transport>``.
	2. Answer ``Enter bcode[value/no]:`` with the broadcast code the
	   source used.

:Expected:
	1. The transport moves to ``State: broadcasting``, i.e. the sink
	   synced to the BIG.
	2. ``Acquire successful: fd <fd> MTU <read>:<write>`` and the
	   transport moves to ``State: active``.

:Notes: Selecting the transport is what moves it out of idle, and
	`bluetoothctl` starts acquiring it right after, so the test does
	not issue ``transport.acquire`` itself. The broadcast code has to
	match the one the source encrypted the BIG with, otherwise the
	sink cannot decrypt the stream.

BROADCAST ASSISTANT
===================

Two hosts, with the Broadcast Source and the Broadcast Assistant
colocated on host0, sharing its own broadcast with the Scan Delegator:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |                 | host1                  |
	| Broadcast Source       |   extended +    | Scan Delegator         |
	| + Broadcast Assistant  |  periodic adv   | (Broadcast Sink)       |
	| bluetoothctl -a auto   | --------------> | bluetoothctl -a auto   |
	| broadcast-source.bt    |                 | broadcast-delegator.bt |
	| BCAA endpoint (0x1852) |   BIG (BIS 1)   | BAA endpoint (0x1851)  |
	|                        | ==============> |                        |
	|                        | ACL, BASS, PAST |                        |
	|                        | --------------> |                        |
	+------------------------+                 +------------------------+

	--> advertising is scanned by          ==> audio flows towards

	The assistant connects to the delegator over ACL and shares the
	local broadcast with it: the delegator receives the periodic
	advertising sync over that connection (PAST), rather than scanning
	the source itself.

``client/scripts/broadcast-source.bt`` on host0
	Registers a Broadcast Source endpoint
	(``00001852-0000-1000-8000-00805f9b34fb``) with LC3, configures it
	with the 16_2_1 preset and acquires the transport, which starts
	the broadcast. The stream is encrypted with the broadcast code
	`bluetoothctl` uses by default.

``client/scripts/broadcast-delegator.bt`` on host1
	Registers a Broadcast Sink endpoint
	(``00001851-0000-1000-8000-00805f9b34fb``) with LC3, enables
	automatic transport selection and acquisition, and advertises, so
	the Broadcast Assistant can discover it and connect.

The local broadcast of host0 is exposed as a MediaAssistant object in
the ``local`` state, under the adapter path, e.g.
``/org/bluez/hci0/sid0/bis1``. The push is driven through the commands
of the assistant submenu, see **bluetoothctl-assistant(1)**.

test_bass_past_transport_acquire
--------------------------------

:Setup: As above.

:Steps:
	1. Start `bluetoothctl` with the source script on host0 and the
	   delegator script on host1.
	2. Assistant: ``scan on``, wait for the delegator device, then
	   ``connect`` it.
	3. Assistant: ``assistant.push <local assistant path>``, answering
	   the device prompt with the delegator device path and, if asked,
	   the broadcast code prompt with the code the stream is encrypted
	   with.

:Expected:
	1. ``Acquire successful: fd <fd> MTU <read>:<write>`` on the
	   source, i.e. it is broadcasting, and the local stream is
	   exposed as ``[NEW] Assistant <adapter>/sid0/bis1``. On the
	   delegator, ``Advertising object registered``.
	2. ``Connection successful``, with the delegator authorizing the
	   assistant.
	3. ``Assistant <path> pushed``.
	4. On the delegator a transport is created for the BIS, and
	   selected and acquired automatically, reaching
	   ``State: broadcasting``, i.e. it synced to the BIG, and then
	   ``State: active``.

:Notes: The delegator does not scan the source: it syncs to the
	periodic advertising over the ACL to the assistant, as pushing a
	local stream requests PAST. When instead the assistant scans and
	relays a *remote* source, it shares the stream without PAST and
	the delegator has to sync by scanning itself; that topology, with
	the assistant on a third host, is left to be added later.

	The broadcast code of the local stream is handed to the delegator
	by the push, so its automatic transport selection does not have to
	prompt for it, and the push itself is only asked for the device to
	share the stream with.

	The delegator is paired first: the Broadcast Receive State
	characteristic requires an encrypted link, and without it the
	assistant fails to read it and the push is rejected with
	``org.bluez.Error.InvalidArguments``.

	The stream is verified on the delegator rather than through the
	state of the MediaAssistant object, as an object created for a
	local stream stays in the ``local`` state.

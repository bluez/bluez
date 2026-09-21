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
	3. Wait for automatic stream configuration through the registered
	   endpoint's ``SelectProperties`` method.
	4. Initiator: ``transport.show <transport>`` for each transport.

:Expected:
	1. ``Endpoint /local/endpoint/ep0 registered`` on both hosts.
	2. ``Pairing successful``.
	3. One transport per location is created on *both* hosts.
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

test_bap_unicast_reconfigure_metadata[empty|media]
------------------------------------------------

:Setup: As above, with both transports already created and ATT MTU 64.

:Steps:
	1. Create two custom presets from the existing codec configurations
	   and QoS, with empty or Media streaming-context metadata. Call
	   ``MediaEndpoint1.ClearConfiguration`` on the remote endpoint.
	2. Wait for completion and check that both old transports are gone.
	3. Issue ``endpoint.config`` for both presets without waiting
	   between requests.
	4. Acquire both replacement transports.

:Expected: Both configuration requests succeed. Two replacement transports
	retain their codec configurations and the requested metadata. Both
	acquisitions succeed and the transports become active.

:Notes: MTU 64 meets BAP's minimum. It fits the two-ASE Codec Configuration
	response and one Codec Configured notification together, but not the
	second ASE notification. This exercises the interval in which the
	initiator has received a successful response but is still waiting
	for a fresh Configured state before starting QoS.

	Release uses D-Bus directly: bluetoothctl has no command for
	``ClearConfiguration``. This test covers the initiator's playback
	streams; it does not exercise microphone streams or simultaneous
	playback and capture.

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

TRUE WIRELESS BROADCAST
=======================

Three hosts, with the two sinks acting as the sides of a true wireless
pair, e.g. a pair of earbuds, each one a device of its own:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |    extended +   | host1                  |
	| Broadcast Source       |    periodic     | Broadcast Sink, left   |
	| bluetoothctl -a auto   |   advertising   | bluetoothctl -a auto   |
	| broadcast-source-2bis  | --------------> | broadcast-sink-left.bt |
	| BCAA endpoint (0x1852) |                 | BAA endpoint (0x1851)  |
	|                        |  BIS 1, F.Left  | Front Left             |
	|                        | ==============> |                        |
	|                        |                 +------------------------+
	|                        |
	|                        |    extended +   +------------------------+
	|                        |    periodic     | host2                  |
	|                        |   advertising   | Broadcast Sink, right  |
	|                        | --------------> | bluetoothctl -a auto   |
	|                        |                 | broadcast-sink-right   |
	|                        |  BIS 2, F.Right | BAA endpoint (0x1851)  |
	|                        | ==============> | Front Right            |
	+------------------------+                 +------------------------+

	one BIG holding one BIS per channel, and each side syncing to the
	BIS carrying its own channel

	--> advertising is scanned by       ==> audio flows towards

There is no connection at all here, not between the source and the
sides and not between the sides either: each side scans, finds the
Broadcast Source, syncs to the periodic advertising, reads the BASE and
syncs to the BIG on its own.

``client/scripts/broadcast-source-2bis.bt`` on host0
	Registers a Broadcast Source endpoint
	(``00001852-0000-1000-8000-00805f9b34fb``) with LC3 and configures
	it twice with the 16_2_1 preset, in the same BIG, once with Front
	Left and once with Front Right as the channel allocation, so the
	BIG carries one BIS per channel. Both transports are acquired,
	which starts the broadcast, encrypted with the broadcast code
	`bluetoothctl` uses by default.

``client/scripts/broadcast-sink-left.bt`` on host1
	Registers a Broadcast Sink endpoint
	(``00001851-0000-1000-8000-00805f9b34fb``) with LC3 and Front Left
	as its only location, and scans.

``client/scripts/broadcast-sink-right.bt`` on host2
	As above, with Front Right as its only location.

Registering a single location is what makes a side take a single
channel: `bluetoothctl` adds the channel count to the capabilities, and
`bluetoothd` only creates a transport for a BIS whose Channel
Allocation is covered by the locations of the local PAC. A sink
registering both locations, as in the BROADCAST section above, takes
every BIS of the BIG instead.

test_bap_broadcast_earbuds_transport_created
--------------------------------------------

:Setup: As above.

:Steps:
	1. Start `bluetoothctl` with the source script on host0.
	2. Start `bluetoothctl` with the sink scripts on host1 and host2.
	3. Each side: list its **org.bluez.MediaTransport1** objects, to
	   check that nothing besides the transport of its own BIS was
	   created.

:Expected:
	1. ``Endpoint /local/endpoint/ep0 registered``, then two
	   ``Acquire successful: fd <fd> MTU <read>:<write>`` on the
	   source, one per BIS, i.e. it is broadcasting both channels.
	2. Each side syncs to the periodic advertising on its own and
	   creates exactly one transport, for the BIS carrying its own
	   channel: ``.../sid0/bis1/fdN`` on the left side and
	   ``.../sid0/bis2/fdN`` on the right one.
	3. Each transport reports ``Codec: 0x06`` for LC3 and
	   ``State: idle``.

:Notes: The BIS index of the path is what tells the two apart, as each
	side only ever sees its own.

	The objects are listed over D-Bus rather than with
	``transport.list``: the endpoint prints the transport it was
	configured with as well, so a listing cannot be told apart from
	it in the output.

	Both transports of the source have to be acquired, as for the CIS
	of a CIG: the BIG is only created once every BIS of it is ready.

test_bap_broadcast_earbuds_transport_acquire
--------------------------------------------

:Setup: As above, with the transport of each side already created.

:Steps:
	1. Each side: ``transport.select <transport>``.
	2. Answer ``Enter bcode[value/no]:`` with the broadcast code the
	   source used.

:Expected: On each side the transport moves to ``State: broadcasting``,
	i.e. it synced to the BIG, then ``Acquire successful: fd <fd> MTU
	<read>:<write>`` and ``State: active``.

:Notes: The two sides sync independently, so each has to be given the
	broadcast code of its own, and one side reaching ``active`` says
	nothing about the other: both are checked.

	Nothing keeps the sides in step, unlike a coordinated set, where
	they are at least discovered and connected together. Rendering
	them in sync is left to the BIG itself, through the presentation
	delay.

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

COORDINATED SET
===============

Three hosts, with the two acceptors forming a coordinated set, one for
each side, so the initiator has to discover both before it can stream:

.. code-block::

	+------------------------+                 +------------------------+
	| host1                  |      LE ACL     | host0                  |
	| acceptor, left         | <-------------- | initiator (central)    |
	| bluetoothctl -a auto   |                 | bluetoothctl -a auto   |
	| bap-sink-lc3-left.bt   |  CIS 0x00 (LC3) | bap-source-lc3.bt      |
	| PAC Sink, Front Left   | <============== | PAC Source endpoint    |
	+------------------------+                 |                        |
	                                           |                        |
	+------------------------+      LE ACL     |                        |
	| host2                  | <-------------- |                        |
	| acceptor, right        |                 |                        |
	| bluetoothctl -a auto   |  CIS 0x01 (LC3) |                        |
	| bap-sink-lc3-right.bt  | <============== |                        |
	| PAC Sink, Front Right  |                 |                        |
	+------------------------+                 +------------------------+

	both acceptors share the same SIRK, so they are resolved into a
	single set, and one CIS per member carries its channel

	connecting one member connects the rest of the set, so the
	initiator only connects once

	--> connection is initiated by      ==> audio flows towards

The acceptors run `bluetoothd` with the same SIRK, so the initiator
resolves them into one set:

.. code-block::

	[CSIS]
	SIRK = 861FAE703ED681F0C50B34155B6434FB
	Size = 2
	Rank = 1

``Rank`` differs per member, 1 for the left and 2 for the right one,
while ``SIRK`` and ``Size`` are the same, as they describe the set.

Each acceptor also has to include the RSI in its advertising, with
``advertise.rsi on``, otherwise the initiator cannot tell the two are
members of the same set, and the resolved set does not appear as a
**org.bluez.DeviceSet(5)** object.

``client/scripts/bap-sink-lc3-left.bt`` on host1
	Registers a local PAC Sink endpoint
	(``00002bc9-0000-1000-8000-00805f9b34fb``) with LC3 and Front Left
	as its only location, and advertises with the RSI.

``client/scripts/bap-sink-lc3-right.bt`` on host2
	As above, with Front Right as its only location.

Each acceptor takes a single channel, unlike the stereo unicast case
where one acceptor takes both: registering exactly one location makes
`bluetoothctl` add the channel count to the capabilities, so a member
is only ever configured for its own channel.

test_bap_unicast_set_transport_created
--------------------------------------

:Setup: As above.

:Steps:
	1. Start `bluetoothctl` with the scripts on the three hosts.
	2. Pair the initiator with one of the acceptors over LE.

:Expected:
	1. ``Endpoint /local/endpoint/ep0 registered`` on the three hosts.
	2. ``Pairing successful``, the members are resolved into a single
	   set, reported as
	   ``[NEW] DeviceSet /org/bluez/hci0/set_<sirk>``, and the other
	   member is bonded on its own, without the initiator connecting
	   or pairing it.
	3. A transport is created for each member, one per channel, i.e.
	   one for the Front Left endpoint and one for the Front Right
	   one.

	The endpoints are not configured by the test: the daemon
	configures a stream for them on its own, and configuring them
	again would add a CIS to the CIG for every extra configuration.

:Notes: Only one member is connected: finding a member of a set
	triggers connecting the remaining ones, so a single
	**org.bluez.Device(5)** ``Connect`` covers the whole set.

	Without the same SIRK, or without the RSI in the advertising, the
	members are not resolved into a set, each is connected on its own
	and the set behaviour this test covers does not happen.

test_bap_unicast_set_transport_acquire
--------------------------------------

:Setup: As above, with the transports already created.

:Steps: Initiator: ``transport.acquire <left> <right>``, for the
	transports of both members.

:Expected: ``Acquire successful: fd <fd> MTU <read>:<write>`` for each
	transport, and both move to ``State: active``.

:Notes: As for a stereo stream to a single acceptor, the CIS of a CIG
	are only created once every one of them is active, so the
	transports of both members have to be acquired: acquiring only
	one leaves the group incomplete and no CIS is created at all.

TRUE WIRELESS BROADCAST ASSISTANT
=================================

Three hosts, with the Broadcast Source and the Broadcast Assistant
colocated on host0, and the two sides of a true wireless pair as Scan
Delegators forming a coordinated set:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |  extended +     | host1                  |
	| Broadcast Source       |  periodic adv   | Scan Delegator, left   |
	| + Broadcast Assistant  | --------------> | bluetoothctl -a auto   |
	| bluetoothctl -a auto   |                 | broadcast-delegator-   |
	| broadcast-source-2bis  |  BIS 1, F.Left  |   left.bt              |
	| BCAA endpoint (0x1852) | ==============> | BAA endpoint (0x1851)  |
	|                        |                 | Front Left, rank 1     |
	|                        | ACL, BASS, PAST |                        |
	|                        | --------------> |                        |
	|                        |                 +------------------------+
	|                        |
	|                        |  extended +     +------------------------+
	|                        |  periodic adv   | host2                  |
	|                        | --------------> | Scan Delegator, right  |
	|                        |                 | bluetoothctl -a auto   |
	|                        | BIS 2, F.Right  | broadcast-delegator-   |
	|                        | ==============> |   right.bt             |
	|                        |                 | BAA endpoint (0x1851)  |
	|                        | ACL, BASS, PAST | Front Right, rank 2    |
	|                        | --------------> |                        |
	+------------------------+                 +------------------------+

	the two delegators share the same SIRK, so they are resolved into
	a single set and connecting one connects the other

	the assistant pushes one BIS to each side, and each of them
	receives the periodic advertising sync over its own connection

	--> advertising is scanned by       ==> audio flows towards

This combines the two topologies above: the BIG carries one BIS per
channel, as in TRUE WIRELESS BROADCAST, while the sides are members of
a coordinated set, as in COORDINATED SET, so the assistant discovers
and connects them as one device.

The delegators run `bluetoothd` with the same ``[CSIS]`` configuration
as the acceptors of the COORDINATED SET section, with ``Rank`` 1 for
the left one and 2 for the right one, and both advertise the RSI.

``client/scripts/broadcast-source-2bis.bt`` on host0
	As in TRUE WIRELESS BROADCAST: a BIG with one BIS per channel,
	encrypted with the broadcast code `bluetoothctl` uses by default.
	The two local streams are exposed as MediaAssistant objects in
	the ``local`` state, under the adapter path, i.e.
	``/org/bluez/hci0/sid0/bis1`` and ``/org/bluez/hci0/sid0/bis2``.

``client/scripts/broadcast-delegator-left.bt`` on host1
	Registers a Broadcast Sink endpoint
	(``00001851-0000-1000-8000-00805f9b34fb``) with LC3 and Front Left
	as its only location, enables automatic transport selection and
	acquisition, and advertises with the RSI, so the Broadcast
	Assistant can discover it as a member of the set and connect.

``client/scripts/broadcast-delegator-right.bt`` on host2
	As above, with Front Right as its only location and rank 2.

test_bass_past_earbuds_transport_acquire
----------------------------------------

:Setup: As above.

:Steps:
	1. Start `bluetoothctl` with the source script on host0 and the
	   delegator scripts on host1 and host2.
	2. Assistant: ``scan on``, wait for both members to be found,
	   ``scan off``, then ``pair`` one of them.
	3. Assistant: ``assistant.push /org/bluez/hci0/sid0/bis1``,
	   answering the device prompt with the device path of the left
	   delegator, and ``assistant.push /org/bluez/hci0/sid0/bis2``
	   with the right one.

:Expected:
	1. Two ``Acquire successful: fd <fd> MTU <read>:<write>`` on the
	   source, i.e. it is broadcasting both channels, with the local
	   streams exposed as ``[NEW] Assistant <adapter>/sid0/bis1`` and
	   ``<adapter>/sid0/bis2``. On both delegators,
	   ``Advertising object registered``.
	2. ``Pairing successful``, the members are resolved into a single
	   set, reported as
	   ``[NEW] DeviceSet /org/bluez/hci0/set_<sirk>``, and the other
	   member is connected and bonded on its own, with the services
	   of both resolved.
	3. ``Assistant <path> pushed`` for both pushes.
	4. On each delegator a transport is created for the BIS that was
	   pushed to it, and selected and acquired automatically, reaching
	   ``State: broadcasting``, i.e. it synced to the BIG, and then
	   ``State: active``.

:Notes: Only one member is paired: finding a member of a set triggers
	connecting the remaining ones. Both links still have to be
	encrypted before the pushes, as the Broadcast Receive State
	characteristic of each member is read over its own connection,
	which is why the services of both are waited for.

	The hosts are reused between tests, so the members may be bonded
	already, in which case ``pair`` connects them instead, see
	**bluetoothctl(1)**. What is already in place is then checked over
	D-Bus rather than waited for on the output, as a device whose
	services are already resolved does not report it again.

	Each member gets a push of its own: BASS has no notion of a set,
	so the assistant adds the source to the Broadcast Receive State
	of each delegator separately, and each of them receives the
	periodic advertising sync over its own ACL (PAST).

	A push carries the BIS to sync to, but the location of the member
	is what decides whether a transport is created for it: pushing
	the right BIS to the left side leaves it without one, as the
	Channel Allocation does not match its PAC.

	The broadcast code of the local streams is handed to the
	delegators by the pushes, so their automatic transport selection
	does not have to prompt for it on either side.

	As in the BROADCAST ASSISTANT case, the streams are verified on
	the delegators rather than through the state of the MediaAssistant
	objects, which stay in the ``local`` state.

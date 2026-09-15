======================
functional-mpris-proxy
======================

DESCRIPTION
===========

mpris-proxy functional tests in `test/functional/test_mpris_proxy.py`.
See **functional-testing(7)** for the conventions used here, and
**test-functional(1)** for how to run the suite.

`mpris-proxy` bridges MPRIS 2.2 players and **bluetoothd**: it
registers a local session bus player with **bluetoothd** using
``org.bluez.Media1.RegisterPlayer``, and, run with ``--export``,
exports a remote ``org.bluez.MediaPlayer1`` object to the session bus
as an MPRIS player.

The upper tester drives two VM hosts, host0 as the client and host1 as
the server. The server presents a dummy MPRIS player. The client runs
a second `mpris-proxy` with ``--export``, which exports that remote
player on the client session bus, and the upper tester controls it
there as an ordinary MPRIS client. Each case runs once over BR/EDR,
where the bridge is an AVRCP Target and Controller, and once over LE,
where it is a Generic Media Control Service (GMCS) server and client.

SETUP
=====

.. code-block::

	BR/EDR:

	+--------------------------------+            +--------------------------------+
	| host0 / client                 |   BR/EDR   | host1 / server                 |
	| bluetoothd                     |   AVCTP    | bluetoothd                     |
	| mpris-proxy --export           |  PSM 0x17  | mpris-proxy                    |
	| MPRIS client (upper tester)    |  ------->  | dummy MPRIS player             |
	| org.mpris.MediaPlayer2.        |            | org.mpris.MediaPlayer2.        |
	|  <name> (session bus)          |            |  blueztest (session bus)       |
	+--------------------------------+            +--------------------------------+

	LE:

	+--------------------------------+            +--------------------------------+
	| host0 / client                 |     LE     | host1 / server                 |
	| bluetoothd                     |    GMCS    | bluetoothd                     |
	| mpris-proxy --export           |   (MCP)    | mpris-proxy                    |
	| MPRIS client (upper tester)    |  ------->  | dummy MPRIS player             |
	| org.mpris.MediaPlayer2.        |            | LE advertisement (GMCS)        |
	|  <name> (session bus)          |            | org.mpris.MediaPlayer2.        |
	|                                |            |  blueztest (session bus)       |
	+--------------------------------+            +--------------------------------+

The server host owns the session bus name
``org.mpris.MediaPlayer2.blueztest`` and exports
``/org/mpris/MediaPlayer2`` with the ``org.mpris.MediaPlayer2`` and
``org.mpris.MediaPlayer2.Player`` interfaces. Its player starts
stopped, at track 0. Every MPRIS method call it receives is reported
to the upper tester. It changes its properties only when the upper
tester tells it to, and then emits
``org.freedesktop.DBus.Properties.PropertiesChanged``.

The `mpris-proxy` on the server registers that player with its
**bluetoothd** through ``org.bluez.Media1.RegisterPlayer``, so the
server host is the AVRCP Target over BR/EDR and the GMCS server over
LE. The `mpris-proxy --export` on the client exports the
``org.bluez.MediaPlayer1`` object its bluetoothd creates for the
remote player as ``org.mpris.MediaPlayer2.<name>``, where ``<name>``
is derived from the remote device alias, at
``/org/mpris/MediaPlayer2`` on the client session bus. Both proxies
use adapter index 0.

In the LE configuration both hosts run bluetoothd with
``ControllerMode = le`` and ``Experimental = true``, and both hosts
register an ``org.bluez.Agent1`` with ``NoInputNoOutput`` capability.
The server also registers a connectable ``org.bluez.LEAdvertisement1``
advertising GMCS (``00001849-0000-1000-8000-00805f9b34fb``) through
``org.bluez.LEAdvertisingManager1.RegisterAdvertisement``, to connect
the service.

Before each case the upper tester does the following, and checks each
step:

	1. Pair the hosts over the bearer in use, unless they are already
	   paired, as the host setup is reused between cases. Over BR/EDR
	   the client discovers the server and calls ``Device1.Pair``, and
	   both agents confirm the passkey. Over LE pairing is Just
	   Works: the server agent authorizes it.
	2. On both hosts, set ``Trusted`` to true with
	   ``org.freedesktop.DBus.Properties.Set`` on the
	   ``org.bluez.Device1`` object of the peer host.
	3. Connect on the client: ``org.bluez.Device1.ConnectProfile``
	   with the AVRCP Controller UUID
	   (``0000110c-0000-1000-8000-00805f9b34fb``) over BR/EDR, or
	   ``org.bluez.Device1.Connect`` over LE. The call must reply, or
	   fail with ``AlreadyConnected`` since a previous case may still
	   be connected.
	4. Wait until the client session bus has exactly one name with the
	   prefix ``org.mpris.MediaPlayer2.``, listed with
	   ``org.freedesktop.DBus.ListNames``. That is the exported player.
	5. Wait until its ``PlaybackStatus``, read with
	   ``org.freedesktop.DBus.Properties.Get``, is the idle status:
	   ``Stopped`` over BR/EDR, ``Paused`` over LE.

The same connection and exported player are used by both cases.

TEARDOWN
========

After each case, also on failure, the upper tester resets the dummy
player on the server to stopped and track 0, which emits
``PropertiesChanged`` for ``PlaybackStatus`` and ``Metadata``, and
drops the method calls left over from the previous case. It then waits
until the exported player on the client again reads the idle status.
The hosts, both bluetoothd instances, both proxies and the connection
are left running.

TEST CASES
==========

test_mpris_proxy_playback_control
---------------------------------

:Setup: As above.

:Steps: For each of ``Play``, ``Pause`` and ``Stop``, in that order:

	1. The upper tester calls the method on the exported player
	   ``org.mpris.MediaPlayer2.Player`` interface on the client
	   session bus, and waits for the reply.
	2. It waits until the dummy player on the server reports the same
	   MPRIS method call.
	3. It then lets the dummy player react as a player application
	   would, setting ``PlaybackStatus`` to ``Playing``, ``Paused``
	   and ``Stopped``, emitted as ``PropertiesChanged``.
	4. It waits until the exported player on the client reports the
	   expected ``PlaybackStatus``.

:Expected:
	1. Each call is answered on the client session bus.
	2. The dummy player on the server receives ``Play``, ``Pause`` and
	   ``Stop``.
	3. The exported player on the client reports ``Playing``,
	   ``Paused`` and ``Stopped`` over BR/EDR. Over LE, ``Stop`` is
	   reported as ``Paused``.

:Notes: GMCS has no stopped state, so a stopped player is published by
	the server in the paused state, and reads as ``Paused`` on the
	client.

test_mpris_proxy_track_control
------------------------------

:Setup: As above.

:Steps:
	1. The upper tester reads the current track number of the dummy
	   player on the server.
	2. It calls ``Next`` on the exported player on the client session
	   bus and waits for the reply.
	3. It waits until the dummy player reports ``Next``, and then has
	   it increment the track number and emit the new ``Metadata``,
	   whose ``xesam:title`` is ``Test Track <n>``.
	4. It waits until the exported player on the client reports that
	   title in ``Metadata``.
	5. It repeats the same for ``Previous``, which decrements the
	   track number.

:Expected:
	1. The dummy player on the server receives ``Next`` and
	   ``Previous``.
	2. The metadata of the new track reaches the exported player on
	   the client: the title matches over both bearers, and
	   ``xesam:trackNumber`` matches over BR/EDR.

:Notes: The dummy player changes its state only once the upper tester
	has observed the corresponding call. Over LE bluetoothd knows
	only the GMCS object name of the remote player, so the client
	sees the title but no track number, which is why the track number
	is checked over BR/EDR only.

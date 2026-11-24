# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
End-to-end tests for mpris-proxy.
"""

import logging
import subprocess

import dbus
import dbus.exceptions
import dbus.service
import pytest

from pytest_bluezenv import (
    Agent,
    Bluetoothd,
    DbusSession,
    EventPluginMixin,
    HostPlugin,
    LogStream,
    dbus_service_event_method,
    find_exe,
    get_dbus,
    mainloop_assert,
    mainloop_wrap,
    parametrized_host_config,
    quoted,
    wait_until,
)

from .le_utils import LeAdvertiser

BLUEZ_BUS_NAME = "org.bluez"

MPRIS_BUS_NAME = "org.mpris.MediaPlayer2.blueztest"
MPRIS_PATH = "/org/mpris/MediaPlayer2"
MPRIS_ROOT_INTERFACE = "org.mpris.MediaPlayer2"
MPRIS_PLAYER_INTERFACE = "org.mpris.MediaPlayer2.Player"

MPRIS_BUS_PREFIX = "org.mpris.MediaPlayer2."

BLUEZ_DEVICE_INTERFACE = "org.bluez.Device1"
PROPS_INTERFACE = "org.freedesktop.DBus.Properties"

AVRCP_CONTROLLER_UUID = "0000110c-0000-1000-8000-00805f9b34fb"

GMCS_UUID = "00001849-0000-1000-8000-00805f9b34fb"

LE_BLUETOOTHD_CONF = "[General]\nControllerMode = le\nExperimental = true\n"


def mpris_player_method(*a, **kw):
    return dbus_service_event_method(MPRIS_PLAYER_INTERFACE, *a, **kw)


class MprisPlayerService(dbus.service.Object):
    """
    Dummy implementation of the MPRIS 2.2 root and player interfaces on
    the session bus. Method calls are pushed as events to the owner
    plugin event queue, like AgentObject does.
    """

    class UnknownProperty(dbus.exceptions.DBusException):
        _dbus_error_name = "org.freedesktop.DBus.Error.UnknownProperty"

    @mainloop_assert
    def __init__(self, bus_name, owner):
        self.events = owner.events
        self.owner = owner
        super().__init__(bus_name, MPRIS_PATH)

    Play = mpris_player_method("Play")
    Pause = mpris_player_method("Pause")
    Stop = mpris_player_method("Stop")
    Next = mpris_player_method("Next")
    Previous = mpris_player_method("Previous")

    @dbus.service.method(PROPS_INTERFACE, in_signature="ss", out_signature="v")
    def Get(self, interface, prop):
        props = self._properties(interface)
        if prop not in props:
            raise self.UnknownProperty(f"No such property {prop} on {interface}")
        return props[prop]

    @dbus.service.method(PROPS_INTERFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        return self._properties(interface)

    @dbus.service.signal(PROPS_INTERFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    def _properties(self, interface):
        if interface == MPRIS_ROOT_INTERFACE:
            return self.owner.root_properties()
        if interface == MPRIS_PLAYER_INTERFACE:
            return self.owner.player_properties()
        return dbus.Dictionary({}, signature="sv")


class DummyMprisPlayer(HostPlugin, EventPluginMixin):
    """
    Host plugin providing a dummy MPRIS player on the session bus under the
    name org.mpris.MediaPlayer2.blueztest. mpris-proxy picks it up and
    registers it to BlueZ as a media player.

    Method calls received by the player are pushed as asynchronous
    events, named org.mpris.MediaPlayer2.Player.<method>. Tests use
    expect() to observe them, and update the player state explicitly with
    the setter methods, which emit MPRIS PropertiesChanged.
    """

    name = "dummy_player"
    depends = [DbusSession()]

    PLAYER_NAME = "BlueZ Test Player"

    @mainloop_wrap
    def setup(self, impl):
        EventPluginMixin.setup(self, impl)

        self.log = logging.getLogger(self.name)

        self.status = "Stopped"
        self.track_number = 0

        self.bus = get_dbus(session=True)
        self.bus_name = dbus.service.BusName(MPRIS_BUS_NAME, bus=self.bus)
        self.service = MprisPlayerService(self.bus_name, self)

        self.log.info(f"MPRIS player {MPRIS_BUS_NAME} exported")

    @mainloop_wrap
    def teardown(self):
        self.service.remove_from_connection()
        self.bus_name = None
        self.service = None

    @mainloop_wrap
    def set_status(self, status):
        # Emit unconditionally: the test relies on PropertiesChanged being
        # sent for every update it requests
        self.status = status
        self._emit_properties_changed(PlaybackStatus=dbus.String(status))

    @mainloop_wrap
    def advance_track(self, delta):
        self.track_number = max(0, self.track_number + delta)
        self._emit_properties_changed(Metadata=self.metadata())

    @mainloop_wrap
    def get_track_number(self):
        return self.track_number

    @mainloop_wrap
    def reset(self):
        # Emit unconditionally so that the remote state follows the reset,
        # then drop any events left over from the previous test
        self.status = "Stopped"
        self.track_number = 0
        while self.get_event(block=False) is not None:
            pass
        self._emit_properties_changed(
            PlaybackStatus=dbus.String(self.status), Metadata=self.metadata()
        )

    def _emit_properties_changed(self, **changed):
        self.service.PropertiesChanged(
            MPRIS_PLAYER_INTERFACE,
            dbus.Dictionary(changed, signature="sv"),
            dbus.Array([], signature="s"),
        )

    def metadata(self):
        return dbus.Dictionary(
            {
                "xesam:title": dbus.String(f"Test Track {self.track_number}"),
                "xesam:artist": dbus.Array([dbus.String("Test Artist")], signature="s"),
                "xesam:album": dbus.String("Test Album"),
                "xesam:trackNumber": dbus.Int32(self.track_number),
                "mpris:trackid": dbus.ObjectPath(
                    f"/org/mpris/MediaPlayer2/Track/{self.track_number}"
                ),
            },
            signature="sv",
        )

    def root_properties(self):
        return dbus.Dictionary(
            {
                "Identity": dbus.String(self.PLAYER_NAME),
                "CanQuit": dbus.Boolean(False),
                "CanRaise": dbus.Boolean(False),
                "HasTrackList": dbus.Boolean(False),
            },
            signature="sv",
        )

    def player_properties(self):
        return dbus.Dictionary(
            {
                "PlaybackStatus": dbus.String(self.status),
                "LoopStatus": dbus.String("None"),
                "Shuffle": dbus.Boolean(False),
                "Rate": dbus.Double(1.0),
                "MinimumRate": dbus.Double(1.0),
                "MaximumRate": dbus.Double(1.0),
                "Volume": dbus.Double(1.0),
                "Metadata": self.metadata(),
                "CanGoNext": dbus.Boolean(True),
                "CanGoPrevious": dbus.Boolean(True),
                "CanPlay": dbus.Boolean(True),
                "CanPause": dbus.Boolean(True),
                "CanSeek": dbus.Boolean(True),
                "CanControl": dbus.Boolean(True),
            },
            signature="sv",
        )


class MprisProxy(HostPlugin):
    """
    Host plugin running the mpris-proxy tool.

    Args:
        args: extra command line arguments, e.g. ("--export",) to also
            export the remote players found by BlueZ as MPRIS players on
            the session bus
    """

    name = "mpris_proxy"
    depends = [Bluetoothd(), DbusSession()]

    def __init__(self, args=()):
        self.extra_args = list(args)

    def presetup(self, config):
        try:
            self.exe = find_exe("tools", "mpris-proxy")
        except FileNotFoundError as exc:
            pytest.skip(reason=f"mpris-proxy: {exc!r}")

    @mainloop_wrap
    def setup(self, impl):
        self.log = logging.getLogger(self.name)
        self.log_stream = LogStream(self.name)

        cmd = [self.exe, "--index", "0"] + self.extra_args
        self.log.info("Start mpris-proxy: {}".format(quoted(cmd)))

        self.job = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=self.log_stream.stream,
            stderr=subprocess.STDOUT,
        )

    def teardown(self):
        self.log.info("Stop mpris-proxy")
        self.job.terminate()


class MprisClient(HostPlugin):
    """
    Host plugin used by the test on the controlling host to discover and
    control the remote player through the MPRIS client API, as exported
    to the session bus by `mpris-proxy --export`.
    """

    name = "mpris_client"
    depends = [DbusSession()]

    _missing_errors = (
        "org.freedesktop.DBus.Error.UnknownProperty",
        "org.freedesktop.DBus.Error.InvalidArgs",
    )

    @mainloop_wrap
    def exported_player(self):
        """Return the bus name of the single exported remote player, or None."""
        bus = get_dbus(session=True)
        obj = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")
        names = [
            str(name)
            for name in dbus.Interface(obj, "org.freedesktop.DBus").ListNames()
            if str(name).startswith(MPRIS_BUS_PREFIX)
        ]
        assert len(names) <= 1, f"unexpected exported players: {names}"
        return names[0] if names else None

    def _get(self, name, interface, prop):
        bus = get_dbus(session=True)
        props = dbus.Interface(bus.get_object(name, MPRIS_PATH), PROPS_INTERFACE)
        try:
            return props.Get(interface, prop)
        except dbus.exceptions.DBusException as exc:
            if exc.get_dbus_name() in self._missing_errors:
                return None
            raise

    @mainloop_wrap
    def get_status(self, name):
        value = self._get(name, MPRIS_PLAYER_INTERFACE, "PlaybackStatus")
        return str(value) if value is not None else None

    @mainloop_wrap
    def get_metadata(self, name):
        metadata = self._get(name, MPRIS_PLAYER_INTERFACE, "Metadata")
        if metadata is None:
            return {}
        return {str(key): str(value) for key, value in metadata.items()}

    @mainloop_wrap
    def call_method(self, name, method):
        """Call given org.mpris.MediaPlayer2.Player method synchronously."""
        bus = get_dbus(session=True)
        player = dbus.Interface(
            bus.get_object(name, MPRIS_PATH), MPRIS_PLAYER_INTERFACE
        )
        getattr(player, method)()


@mainloop_wrap
def vm_set_trusted(bdaddr):
    """Mark the device with the given address as trusted."""
    path = "/org/bluez/hci0/dev_" + bdaddr.upper().replace(":", "_")
    bus = get_dbus()
    props = dbus.Interface(bus.get_object(BLUEZ_BUS_NAME, path), PROPS_INTERFACE)
    props.Set(BLUEZ_DEVICE_INTERFACE, "Trusted", dbus.Boolean(True))


def idle_status(le):
    """Playback status a stopped player reads as, MCP has no stopped state."""
    return "Paused" if le else "Stopped"


@pytest.fixture
def mpris_player(paired_hosts, is_le):
    """
    Two paired and trusted hosts, the client connected to the dummy MPRIS
    player of the server, exported on the client session bus by
    mpris-proxy --export.

    The dummy player is reset also on failure, so the tests are
    order-independent.

    Yields (client, server, exported player bus name).
    """
    client, server = paired_hosts

    client.call(vm_set_trusted, server.bdaddr)
    server.call(vm_set_trusted, client.bdaddr)

    if is_le:
        method, args = "Connect", ()
    else:
        method, args = "ConnectProfile", (AVRCP_CONTROLLER_UUID,)

    client.agent.device_method(server.bdaddr, method, *args)
    event = client.agent.expect(
        (f"org.bluez.Device1.{method}:reply", f"org.bluez.Device1.{method}:error")
    )
    if event.kind.endswith(":error"):
        # OK if the player is already connected (reused host setup)
        assert "AlreadyConnected" in str(event.error), f"{method} failed: {event.error}"

    wait_until(lambda: client.mpris_client.exported_player())
    player_name = client.mpris_client.exported_player()

    wait_until(
        lambda: client.mpris_client.get_status(player_name) == idle_status(is_le)
    )

    yield client, server, player_name

    server.dummy_player.reset()
    wait_until(
        lambda: client.mpris_client.get_status(player_name) == idle_status(is_le)
    )


mpris_proxy_host_config = parametrized_host_config(
    [
        # BR/EDR
        (
            [MprisProxy(args=("--export",)), MprisClient(), Agent()],
            [MprisProxy(), DummyMprisPlayer(), Agent()],
        ),
        # LE
        (
            [
                Bluetoothd(conf=LE_BLUETOOTHD_CONF),
                MprisProxy(args=("--export",)),
                MprisClient(),
                Agent(capability="NoInputNoOutput"),
            ],
            [
                Bluetoothd(conf=LE_BLUETOOTHD_CONF),
                MprisProxy(),
                DummyMprisPlayer(),
                LeAdvertiser(service_uuids=[GMCS_UUID]),
                Agent(capability="NoInputNoOutput"),
            ],
        ),
    ],
    ids=["bredr", "le"],
    reuse=True,
)


def control_player(client, server, player_name, method, update, *args):
    """
    Call an MPRIS Player method on the remote player exported on the
    client session bus, wait for the dummy player to receive the matching
    MPRIS call, and run update(*args) to update the dummy player state, as
    a player application would react to the call.
    """
    client.mpris_client.call_method(player_name, method)
    server.dummy_player.expect(f"{MPRIS_PLAYER_INTERFACE}.{method}")
    update(*args)


@mpris_proxy_host_config
def test_mpris_proxy_playback_control(mpris_player, is_le):
    client, server, player_name = mpris_player

    for method, status, expected in (
        ("Play", "Playing", "Playing"),
        ("Pause", "Paused", "Paused"),
        ("Stop", "Stopped", idle_status(is_le)),
    ):
        control_player(
            client,
            server,
            player_name,
            method,
            server.dummy_player.set_status,
            status,
        )
        wait_until(lambda: client.mpris_client.get_status(player_name) == expected)


@mpris_proxy_host_config
def test_mpris_proxy_track_control(mpris_player, is_le):
    client, server, player_name = mpris_player

    track_number = server.dummy_player.get_track_number()

    for delta, method in ((1, "Next"), (-1, "Previous")):
        track_number += delta
        control_player(
            client,
            server,
            player_name,
            method,
            server.dummy_player.advance_track,
            delta,
        )
        wait_until(
            lambda: client.mpris_client.get_metadata(player_name).get("xesam:title")
            == f"Test Track {track_number}"
        )
        if not is_le:
            # Over LE, bluetoothd knows only the GMCS object name, no track number
            metadata = client.mpris_client.get_metadata(player_name)
            assert int(metadata["xesam:trackNumber"]) == track_number

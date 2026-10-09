# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for the org.bluez.Bearer.LE1 and org.bluez.Bearer.BREDR1 interfaces

host0 connects to or pairs with host1, and each host checks the bearer
interfaces of the device object it has for the other.
"""

import logging

import dbus
import pytest

from pytest_bluezenv import (
    Agent,
    Bluetoothd,
    EventPluginMixin,
    HostPlugin,
    get_dbus,
    host_config,
    mainloop_wrap,
    wait_until,
)

from .le_utils import LeAdvertiser, pair_le
from .test_agent import test_agent_pair_bredr as pair_bredr

pytestmark = [pytest.mark.vm]

BUS_NAME = "org.bluez"
PROPS_INTERFACE = "org.freedesktop.DBus.Properties"
DEVICE_INTERFACE = "org.bluez.Device1"
LE_INTERFACE = "org.bluez.Bearer.LE1"
BREDR_INTERFACE = "org.bluez.Bearer.BREDR1"

# The bearer interfaces are experimental
CONF = "[General]\nExperimental = true\n"
LE_CONF = CONF + "ControllerMode = le\n"

# bluetoothd only creates device objects for advertisers that are
# discoverable, which a broadcaster is not
SCANNER_CONF = LE_CONF + "FilterDiscoverable = false\n"

# Identifies the broadcast advertisement of host1 on host0, as it is sent
# from a non-resolvable private address rather than from host1's address
BROADCAST_UUID = "6e2c1d84-7a3b-4f50-9c1e-5b8d2a7f0e13"

# The MIDI profile asks to pair as soon as it finds the MIDI service the
# other host exports, which would need an agent reply in every test
ARGS = ("-P", "midi")


class Bearers(HostPlugin, EventPluginMixin):
    """
    Host plugin calling the bearer interfaces of remote devices, reading
    their properties and recording their Disconnected signals.
    """

    name = "bearers"
    depends = [Bluetoothd()]

    @mainloop_wrap
    def setup(self, impl):
        EventPluginMixin.setup(self, impl)

        self.log = logging.getLogger(self.name)
        self.bus = get_dbus(private=True)
        self.disconnected = []

        self.bus.add_signal_receiver(
            self._disconnected,
            signal_name="Disconnected",
            bus_name=BUS_NAME,
            path_keyword="path",
            interface_keyword="interface",
        )

    def _disconnected(self, reason, message, path=None, interface=None):
        if interface not in (LE_INTERFACE, BREDR_INTERFACE):
            return

        self.log.info(f"{path} {interface}.Disconnected: {reason}")
        self.disconnected.append((str(path), str(interface), str(reason)))

    def _devices(self):
        manager = dbus.Interface(
            self.bus.get_object(BUS_NAME, "/"), "org.freedesktop.DBus.ObjectManager"
        )

        for path, ifaces in manager.GetManagedObjects().items():
            device = ifaces.get(DEVICE_INTERFACE)
            if device is not None:
                yield str(path), device

    def _device_path(self, address):
        for path, device in self._devices():
            if device["Address"].lower() == address.lower():
                return path

        return None

    @mainloop_wrap
    def find_address(self, uuid):
        """
        Return the address of the device advertising the given service
        UUID, or None if there is none.
        """
        for path, device in self._devices():
            if uuid in [str(u).lower() for u in device.get("UUIDs", [])]:
                return str(device["Address"])

        return None

    @mainloop_wrap
    def get(self, address, interface, name):
        """
        Return a bearer property of the device with the given address, or
        None if the device, the bearer or the property is not there.
        """
        path = self._device_path(address)
        if path is None:
            return None

        props = dbus.Interface(self.bus.get_object(BUS_NAME, path), PROPS_INTERFACE)
        try:
            value = props.Get(interface, name)
        except dbus.exceptions.DBusException:
            return None

        if isinstance(value, dbus.Boolean):
            return bool(value)

        return str(value)

    @mainloop_wrap
    def call(self, address, interface, method):
        """
        Call a bearer method of the device with the given address.

        Events:
            Event(kind="{interface}.{method}:reply")
        """
        path = self._device_path(address)
        bearer = dbus.Interface(self.bus.get_object(BUS_NAME, path), interface)
        self._object_method(bearer, method)

    @mainloop_wrap
    def disconnect_reasons(self, address, interface):
        """
        Return the reasons of the Disconnected signals received on the
        given bearer of the device with the given address, in order.
        """
        path = f"/org/bluez/hci0/dev_{address.upper().replace(':', '_')}"
        return [r for p, i, r in self.disconnected if p == path and i == interface]


le_config = host_config(
    [
        Bluetoothd(conf=LE_CONF, args=ARGS),
        Agent(capability="NoInputNoOutput"),
        Bearers(),
    ],
    [
        Bluetoothd(conf=LE_CONF, args=ARGS),
        LeAdvertiser(),
        Agent(capability="NoInputNoOutput"),
        Bearers(),
    ],
)

bredr_config = host_config(
    [Bluetoothd(conf=CONF, args=ARGS), Agent(), Bearers()],
    [Bluetoothd(conf=CONF, args=ARGS), Agent(), Bearers()],
)


def start_discovery(host):
    host.agent.adapter_method("StartDiscovery")
    host.agent.expect("org.bluez.Adapter1.StartDiscovery:reply")


def discover(host, remote):
    start_discovery(host)
    wait_until(host.agent.has_device, remote.bdaddr)


def peers(host0, host1):
    """Both hosts, each with the other"""
    return ((host0, host1), (host1, host0))


def disconnect(host0, host1, interface):
    """
    Disconnect the bearer from host0, and check it is reported as
    disconnected on both hosts with the reason seen from each side.
    """
    host0.bearers.call(host1.bdaddr, interface, "Disconnect")
    host0.bearers.expect(f"{interface}.Disconnect:reply")

    for host, remote, reason in (
        (host0, host1, "org.bluez.Reason.Local"),
        (host1, host0, "org.bluez.Reason.Remote"),
    ):
        wait_until(
            lambda: host.bearers.disconnect_reasons(remote.bdaddr, interface)
            == [reason]
        )
        assert host.bearers.get(remote.bdaddr, interface, "Connected") is False


@le_config
def test_bearer_le_connect(hosts):
    host0, host1 = hosts

    discover(host0, host1)

    host0.bearers.call(host1.bdaddr, LE_INTERFACE, "Connect")
    host0.bearers.expect(f"{LE_INTERFACE}.Connect:reply")

    for host, remote in peers(host0, host1):
        wait_until(
            lambda: host.bearers.get(remote.bdaddr, LE_INTERFACE, "Connected") is True
        )

    assert host0.bearers.get(host1.bdaddr, LE_INTERFACE, "Role") == "peripheral"
    assert host1.bearers.get(host0.bdaddr, LE_INTERFACE, "Role") == "central"

    disconnect(host0, host1, LE_INTERFACE)

    for host, remote in peers(host0, host1):
        assert host.bearers.get(remote.bdaddr, LE_INTERFACE, "Role") is None


@host_config(
    [Bluetoothd(conf=SCANNER_CONF, args=ARGS), Agent(), Bearers()],
    # A broadcaster, so neither connectable nor discoverable
    [
        Bluetoothd(conf=LE_CONF, args=ARGS),
        LeAdvertiser(
            adv_type="broadcast",
            service_uuids=[BROADCAST_UUID],
            discoverable=False,
        ),
    ],
)
def test_bearer_le_not_connectable(hosts):
    host0, host1 = hosts

    start_discovery(host0)
    wait_until(lambda: host0.bearers.find_address(BROADCAST_UUID) is not None)
    address = host0.bearers.find_address(BROADCAST_UUID)

    wait_until(
        lambda: host0.bearers.get(address, LE_INTERFACE, "Connectable") is not None
    )
    assert host0.bearers.get(address, LE_INTERFACE, "Connectable") is False


@le_config
def test_bearer_le_connectable(hosts):
    host0, host1 = hosts

    discover(host0, host1)

    wait_until(
        lambda: host0.bearers.get(host1.bdaddr, LE_INTERFACE, "Connectable") is not None
    )
    assert host0.bearers.get(host1.bdaddr, LE_INTERFACE, "Connectable") is True


@le_config
def test_bearer_le_pair(hosts):
    host0, host1 = hosts

    pair_le(host0, host1)

    for host, remote in peers(host0, host1):
        for name in ("Paired", "Bonded", "Connected"):
            wait_until(
                lambda: host.bearers.get(remote.bdaddr, LE_INTERFACE, name) is True
            )

        assert host.bearers.get(remote.bdaddr, BREDR_INTERFACE, "Paired") is None


@bredr_config
def test_bearer_bredr_pair(hosts):
    host0, host1 = hosts

    pair_bredr(hosts, True)

    for host, remote in peers(host0, host1):
        for name in ("Paired", "Bonded", "Connected", "Connectable"):
            wait_until(
                lambda: host.bearers.get(remote.bdaddr, BREDR_INTERFACE, name) is True
            )

        # Role is only reported for LE
        assert host.bearers.get(remote.bdaddr, BREDR_INTERFACE, "Role") is None

    disconnect(host0, host1, BREDR_INTERFACE)

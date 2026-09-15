# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generic LE helpers for functional tests.

LeAdvertiser registers a connectable org.bluez.LEAdvertisement1: in
ControllerMode = le bluetoothd does not advertise on its own, so a host has
to advertise itself to be discovered and connected over LE.
"""

import logging

import dbus
import dbus.exceptions
import dbus.service

from pytest_bluezenv import (
    Bluetoothd,
    HostPlugin,
    get_dbus,
    mainloop_assert,
    mainloop_wrap,
    wait_until,
)

BLUEZ_BUS_NAME = "org.bluez"
PROPS_INTERFACE = "org.freedesktop.DBus.Properties"
LE_ADV_INTERFACE = "org.bluez.LEAdvertisement1"
LE_ADV_MANAGER_INTERFACE = "org.bluez.LEAdvertisingManager1"


class LeAdvertisement(dbus.service.Object):
    """
    Minimal generic org.bluez.LEAdvertisement1 implementation exporting the
    given service UUIDs over the given advertisement type.
    """

    class UnknownProperty(dbus.exceptions.DBusException):
        _dbus_error_name = "org.freedesktop.DBus.Error.UnknownProperty"

    @mainloop_assert
    def __init__(
        self,
        bus,
        path,
        adv_type="peripheral",
        service_uuids=(),
        discoverable=True,
    ):
        self.adv_path = path
        self._props = dbus.Dictionary(
            {
                "Type": dbus.String(adv_type),
                "ServiceUUIDs": dbus.Array(
                    [dbus.String(uuid) for uuid in service_uuids], signature="s"
                ),
            },
            signature="sv",
        )
        if discoverable:
            self._props["Discoverable"] = dbus.Boolean(True)
        super().__init__(bus, path)

    @dbus.service.method(PROPS_INTERFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface == LE_ADV_INTERFACE:
            return self._props
        return dbus.Dictionary({}, signature="sv")

    @dbus.service.method(PROPS_INTERFACE, in_signature="ss", out_signature="v")
    def Get(self, interface, prop):
        props = self.GetAll(interface)
        if prop not in props:
            raise self.UnknownProperty(f"No such property {prop} on {interface}")
        return props[prop]

    @dbus.service.signal(PROPS_INTERFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

    @dbus.service.method(LE_ADV_INTERFACE, in_signature="", out_signature="")
    def Release(self):
        pass


class LeAdvertiser(HostPlugin):
    """
    Host plugin registering a connectable LE advertisement, so that a remote
    host can discover and connect to it over LE. The advertised service
    UUIDs are given as the service_uuids argument.
    """

    name = "le_advertiser"
    depends = [Bluetoothd()]

    PATH_BASE = "/org/bluez/test/advertisement"

    def __init__(
        self,
        service_uuids=(),
        adv_type="peripheral",
        index=0,
        adapter_path="/org/bluez/hci0",
        discoverable=True,
    ):
        self.service_uuids = tuple(service_uuids)
        self.adv_type = adv_type
        self.index = index
        self.adapter_path = adapter_path
        self.discoverable = discoverable

    def setup(self, impl):
        # While registering, bluetoothd reads the advertisement properties
        # back from us, so wait for the reply outside the mainloop thread to
        # let the mainloop serve it
        self.log = logging.getLogger(self.name)

        self.registered = False
        self.register_error = None

        self._register()

        wait_until(lambda: self.registered)
        if self.register_error is not None:
            raise self.register_error

    @mainloop_wrap
    def _register(self):
        self.bus = get_dbus(private=True)
        self.adv = LeAdvertisement(
            self.bus,
            f"{self.PATH_BASE}{self.index}",
            self.adv_type,
            self.service_uuids,
            self.discoverable,
        )
        self.manager = dbus.Interface(
            self.bus.get_object(BLUEZ_BUS_NAME, self.adapter_path),
            LE_ADV_MANAGER_INTERFACE,
        )

        self.log.info(f"Register LE advertisement {self.adv.adv_path}")

        self.manager.RegisterAdvertisement(
            self.adv.adv_path,
            dbus.Dictionary({}, signature="sv"),
            reply_handler=self._registered,
            error_handler=self._register_error,
        )

    def _registered(self):
        self.log.info(f"LE advertisement {self.adv.adv_path} registered")
        self.registered = True

    def _register_error(self, err):
        self.log.error(f"LE advertisement {self.adv.adv_path} failed: {err}")
        self.register_error = err
        self.registered = True

    @mainloop_wrap
    def teardown(self):
        self.log.info(f"Unregister LE advertisement {self.adv.adv_path}")
        self.manager.UnregisterAdvertisement(
            self.adv.adv_path,
            reply_handler=lambda: None,
            error_handler=lambda err: self.log.debug(f"Unregister: {err}"),
        )
        self.adv.remove_from_connection()


def host_setup_is_le(host_setup):
    """True if the hosts run bluetoothd in LE-only mode."""
    return any(
        "ControllerMode = le" in (p.conf or "")
        for plugins in host_setup["setup"]
        for p in plugins
        if isinstance(p, Bluetoothd)
    )


def pair_le(client, server):
    """
    Pair Just Works over LE: client initiates and server authorizes, so
    only a single RequestAuthorization is expected.
    """
    server.agent.adapter_set("Pairable", True)

    client.agent.adapter_method("StartDiscovery")
    client.agent.expect("org.bluez.Adapter1.StartDiscovery:reply")
    wait_until(client.agent.has_device, server.bdaddr)

    client.agent.device_method(server.bdaddr, "Pair")
    server.agent.expect("org.bluez.Agent1.RequestAuthorization")
    server.agent.reply()
    client.agent.expect("org.bluez.Device1.Pair:reply")

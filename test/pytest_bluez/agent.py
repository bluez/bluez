# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
VM host plugins
"""
import os
import sys
import subprocess
import collections
import logging
import tempfile
import time
import shutil
import queue
from pathlib import Path

import dbus
import dbus.service

from . import env, utils
from .host_plugins import Bluetoothd

__all__ = ["Agent", "Event", "EventPluginMixin", "dbus_service_event_method"]

BUS_NAME = "org.bluez"
AGENT_INTERFACE = "org.bluez.Agent1"
AGENT_MANAGER_INTERFACE = "org.bluez.AgentManager1"
ADAPTER_INTERFACE = "org.bluez.Adapter1"
DEVICE_INTERFACE = "org.bluez.Device1"
PROPS_INTERFACE = "org.freedesktop.DBus.Properties"

log = logging.getLogger("agent")


class Rejected(dbus.DBusException):
    _dbus_error_name = "org.bluez.Error.Rejected"


class Event:
    """
    Asynchronous event.

    Properties:
        kind (str): event kind
        info (dict): event properties (also available as attributes)
    """

    def __init__(
        self, kind, reply_cb=None, error_cb=None, reply_type=None, info=None, **kw
    ):
        if info is None:
            info = {}
        info.update(kw)
        self.reply_cb = reply_cb
        self.error_cb = error_cb
        self.kind = kind
        self.reply_type = reply_type
        self.info = info

    def __getattr__(self, name):
        try:
            return self.__dict__["info"][name]
        except KeyError:
            raise AttributeError(name)

    def __getstate__(self):
        return dict(self.__dict__, reply_cb=None, error_cb=None)


class EventPluginMixin:
    """
    Simple expect() / reply() pattern for handing async events in
    host plugins.

    """

    def setup(self, impl):
        self.events = queue.SimpleQueue()
        self.cur_event = None

    def get_event(self, block=True):
        """
        Get most recent pending Event, blocking optional
        """
        if self.cur_event is not None:
            return self.cur_event

        try:
            self.cur_event = self.events.get(block=block)
            return self.cur_event
        except queue.Empty:
            return None

    def expect(self, kinds):
        """
        Get most recent pending Event and assert its kind

        Returns:
            event (Event)
        """
        if isinstance(kinds, str):
            kinds = (kinds,)
        kinds = tuple(kinds)

        event = self.get_event()
        if event.kind not in kinds:
            raise AssertionError(f"Got {event.kind=}, expected {kinds=}")
        if event.reply_cb is None:
            self.cur_event = None

        log.info(f"match {event.kind=}")
        return event

    @utils.mainloop_wrap
    def reply(self, *value):
        """
        Provide DBus reply to the most recent pending Event

        Arguments:
            *value: DBus reply return values
        """
        if len(value) == 1 and isinstance(value[0], Exception):
            self.cur_event.error_cb(value[0])
        else:
            if self.cur_event.reply_type is not None:
                value = self.cur_event.reply_type(*value)
            self.cur_event.reply_cb(*value)
        self.cur_event = None

    def reply_error(self, err=None):
        """
        Provide DBus error reply to the most recent pending Event

        Arguments:
            err (dbus.DBusException): DBus error. Default: org.bluez.Error.Rejected
        """
        if err is None:
            err = Rejected()
        self.reply(err)

    @utils.mainloop_assert
    def _object_method(self, obj, method, *a, **kw):
        iface = obj.dbus_interface

        reply_handler = kw.pop("reply_handler", None)
        error_handler = kw.pop("error_handler", None)

        def reply(*values):
            log.info(f"{iface}.{method} reply: {values!r}")
            if reply_handler is not None:
                reply_handler(*values)
            self.events.put(Event(f"{iface}.{method}:reply", values=values))

        def error(err):
            log.info(f"{iface}.{method} error: {err!r}")
            if error_handler is not None:
                error_handler(err)
            self.events.put(Event(f"{iface}.{method}:error", error=err))

        getattr(obj, method)(*a, **kw, reply_handler=reply, error_handler=error)


class Agent(env.HostPlugin, EventPluginMixin):
    """
    Host plugin providing org.bluez.Agent1 test implementation.

    Asynchronous events are handled via expect().

    Example:

        host.agent.device_method(host1.bdaddr, "Pair")
        event = host.agent.expect("org.bluez.Agent1.RequestConfirmation")
        assert event.passkey == 1234
        host.agent.reply()
    """

    depends = [Bluetoothd()]
    name = "agent"

    def __init__(self, capability="KeyboardDisplay", path="/agent"):
        self.capability = capability
        self.path = path

    @utils.mainloop_wrap
    def setup(self, impl):
        EventPluginMixin.setup(self, impl)

        self.bus = dbus.SystemBus(private=True)
        self.bus.set_exit_on_disconnect(False)

        self.agent = AgentObject(self.bus, self.path, self.events)

        bluez = self.bus.get_object(BUS_NAME, "/org/bluez")
        self.manager = dbus.Interface(bluez, AGENT_MANAGER_INTERFACE)
        self.manager.RegisterAgent(self.path, self.capability)

        log.info("Agent registered")

        self.manager.RequestDefaultAgent(self.path)

    @utils.mainloop_wrap
    def teardown(self):
        self.manager.UnregisterAgent(self.path)
        log.info("Agent unregistered")

    @utils.mainloop_wrap
    def has_device(self, address):
        """
        Return True if device with given address exists
        """
        try:
            self._find_device(address)
            return True
        except ValueError:
            return False

    @utils.mainloop_wrap
    def device_method(self, address, method, *a, **kw):
        """
        Call given org.bluez.Device1 DBus method

        Args:
            address (str): bdaddr of target device
            method (str): name of DBus method, without interface prefix
            *a, **kw: argument passed to the DBus method call

        Events:
            Event(kind="org.bluez.Device1.{method}:reply")
        """
        device = self._find_device(address)
        self._object_method(device, method, *a, **kw)

    @utils.mainloop_wrap
    def adapter_method(self, method, *a, **kw):
        """
        Call given org.bluez.Adapter1 DBus method

        Args:
            method (str): name of DBus method, without interface prefix
            *a, **kw: argument passed to the DBus method call

        Events:
            Event(kind="org.bluez.Adapter1.{method}")
        """
        adapter = dbus.Interface(
            self.bus.get_object(BUS_NAME, "/org/bluez/hci0"), ADAPTER_INTERFACE
        )
        self._object_method(adapter, method, *a, **kw)

    @utils.mainloop_wrap
    def adapter_set(self, key, value):
        """
        Set given org.bluez.Adapter1 property
        """
        adapter = dbus.Interface(
            self.bus.get_object(BUS_NAME, "/org/bluez/hci0"), PROPS_INTERFACE
        )
        adapter.Set(ADAPTER_INTERFACE, key, value)

    @utils.mainloop_wrap
    def adapter_get(self, key):
        """
        Get given org.bluez.Adapter1 property
        """
        adapter = dbus.Interface(
            self.bus.get_object(BUS_NAME, "/org/bluez/hci0"), PROPS_INTERFACE
        )
        return adapter.Get(ADAPTER_INTERFACE, key)

    @utils.mainloop_assert
    def _find_device(self, address):
        manager = dbus.Interface(
            self.bus.get_object(BUS_NAME, "/"), "org.freedesktop.DBus.ObjectManager"
        )
        objects = manager.GetManagedObjects()

        for path, ifaces in objects.items():
            device = ifaces.get(DEVICE_INTERFACE)
            if device is None:
                continue
            if device["Address"].lower() == address.lower():
                return dbus.Interface(
                    self.bus.get_object(BUS_NAME, path), DEVICE_INTERFACE
                )
        else:
            raise ValueError("Device {address=} not found")


def dbus_service_event_method(
    interface, name, args=(), in_signature="", out_signature="", sync=True
):
    """
    dbus.service.method that pushes Event instances to self.events

    Example:

        class AgentObject(dbus.service.Object):
            @utils.mainloop_assert
            def __init__(self, bus, path, events):
                self.events = events
                super().__init__(bus, path)

            AuthorizeService = dbus_service_event_method(
                "org.bluez.Agent1",
                "AuthorizeService", ("device", "uuid"), "os", sync=False
            )

    """

    reply_type = {"": "None", "s": "str", "u": "dbus.UInt32"}[out_signature]

    if not sync:
        cb_args = ("_reply", "_error")
        kw = dict(
            in_signature=in_signature,
            out_signature=out_signature,
            async_callbacks=("_reply", "_error"),
        )
    else:
        cb_args = ()
        kw = dict(in_signature=in_signature, out_signature=out_signature)
        assert not out_signature

    args_str = ", ".join(args)
    if args_str:
        args_str = ", " + args_str

    cb_args_str = ", ".join(cb_args)
    if cb_args:
        cb_args_str = ", " + cb_args_str

    args_dict = ", ".join(f"{k}={k}" for k in args)

    method_str = f"""def {name}(self{args_str}{cb_args_str}):
        info = dict({args_dict})
        log.info(f"{interface}.{name} {{info}}")
        self.events.put(Event("{interface}.{name}"{cb_args_str}, reply_type={reply_type}, info=info))
    """

    ns = dict(dbus=dbus, Event=Event, log=log)
    exec(method_str, ns)
    return dbus.service.method(interface, **kw)(utils.mainloop_assert(ns[name]))


def agent_method(*a, **kw):
    return dbus_service_event_method(AGENT_INTERFACE, *a, **kw)


class AgentObject(dbus.service.Object):
    @utils.mainloop_assert
    def __init__(self, bus, path, events):
        self.events = events
        super().__init__(bus, path)

    Release = agent_method("Release")
    AuthorizeService = agent_method(
        "AuthorizeService", ("device", "uuid"), "os", sync=False
    )
    RequestPinCode = agent_method("RequestPinCode", ("device",), "o", "s", sync=False)
    RequestPasskey = agent_method("RequestPasskey", ("device",), "o", "u", sync=False)
    RequestConfirmation = agent_method(
        "RequestConfirmation", ("device", "passkey"), "ou", sync=False
    )
    RequestAuthorization = agent_method(
        "RequestAuthorization", ("device",), "o", sync=False
    )
    DisplayPasskey = agent_method(
        "DisplayPasskey", ("device", "passkey", "entered"), "ouq"
    )
    DisplayPinCode = agent_method("DisplayPinCode", ("device", "pincode"), "os")
    Cancel = agent_method("Cancel")

# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Tests for Obex
"""
import sys
import os
import re
import pytest
import subprocess
import tempfile
import time
import logging
import json
import dbus
import threading
from pathlib import Path

import pytest

from pytest_bluez import (
    HostPlugin,
    Agent,
    host_config,
    find_exe,
    Bluetoothd,
    Bluetoothctl,
    Obexd,
    LogStream,
    wait_until,
    mainloop_wrap,
    mainloop_assert,
    Event,
    EventPluginMixin,
    dbus_service_event_method,
    Pexpect,
    utils,
)

pytestmark = [pytest.mark.vm]

log = logging.getLogger(__name__)


BUS_NAME = "org.bluez.obex"
PATH = "/org/bluez/obex"
AGENT_MANAGER_INTERFACE = "org.bluez.obex.AgentManager1"
AGENT_INTERFACE = "org.bluez.obex.Agent1"
CLIENT_INTERFACE = "org.bluez.obex.Client1"
SESSION_INTERFACE = "org.bluez.obex.Session1"
FILE_TRANSFER_INTERFACE = "org.bluez.obex.FileTransfer1"
TRANSFER_INTERFACE = "org.bluez.obex.Transfer1"

FTP_UUID = "00001106-0000-1000-8000-00805f9b34fb"


class ObexAgent(HostPlugin, EventPluginMixin):
    depends = [Bluetoothd()]
    name = "obex_agent"

    def __init__(self, path="/obexagent"):
        self.path = path

    @mainloop_wrap
    def setup(self, impl):
        EventPluginMixin.setup(self, impl)

        self.bus = dbus.SessionBus()
        self.bus.set_exit_on_disconnect(False)

        self.agent = ObexAgentObject(self.bus, self.path, self.events)

        bluez = self.bus.get_object(BUS_NAME, PATH)
        self.manager = dbus.Interface(bluez, AGENT_MANAGER_INTERFACE)
        self.manager.RegisterAgent(self.path)

        log.info("Obex agent registered")

    def cleanup(self):
        path = Path("/run/obex")
        for f in path.iterdir():
            f.unlink()


def agent_method(*a, **kw):
    return dbus_service_event_method(AGENT_INTERFACE, *a, **kw)


class ObexAgentObject(dbus.service.Object):
    @mainloop_assert
    def __init__(self, bus, path, events):
        self.events = events
        super().__init__(bus, path)

    AuthorizePush = agent_method("AuthorizePush", ("path",), "o", "s", sync=False)
    Cancel = agent_method("Cancel")


def write_obex_file(name, content):
    with open(f"/run/obex/{name}", "w") as f:
        f.write(content)


def read_file(name):
    with open(name, "r") as f:
        return f.read()


#
# Direct Obex Python client API tests
#


class ObexClient(HostPlugin, EventPluginMixin):
    name = "obex"

    @mainloop_wrap
    def setup(self, impl):
        EventPluginMixin.setup(self, impl)

        self.transferred = 0
        self.transfer_path = None
        self.transfer_size = 0

        self.bus = dbus.SessionBus()
        self.bus.set_exit_on_disconnect(False)
        self.log = logging.getLogger(self.name)
        self.client = dbus.Interface(
            self.bus.get_object(BUS_NAME, PATH), CLIENT_INTERFACE
        )

        self.bus.add_signal_receiver(
            self.properties_changed,
            dbus_interface="org.freedesktop.DBus.Properties",
            signal_name="PropertiesChanged",
            path_keyword="path",
        )

    @mainloop_wrap
    def connect(self, bdaddr):
        def reply(path):
            obj = self.bus.get_object(BUS_NAME, path)
            self.session = dbus.Interface(obj, SESSION_INTERFACE)
            self.ftp = dbus.Interface(obj, FILE_TRANSFER_INTERFACE)

        self._object_method(
            self.client, "CreateSession", bdaddr, {"Target": "ftp"}, reply_handler=reply
        )

    @mainloop_assert
    def properties_changed(self, interface, properties, invalidated, path):
        if path != self.transfer_path:
            return

        if "Status" in properties and (
            properties["Status"] == "complete" or properties["Status"] == "error"
        ):
            self.events.put(
                Event(
                    f"{FILE_TRANSFER_INTERFACE}:{properties['Status']}",
                    properties=properties,
                )
            )
            self.log.debug(f"Transfer {properties['Status']}")

        if "Transferred" not in properties:
            return

        value = properties["Transferred"]
        speed = (value - self.transferred) / 1000
        self.log.debug(
            f"Transfer progress {value}/{self.transfer_size} at {speed} kBps"
        )
        self.transferred = value

    @mainloop_wrap
    def ftp_list_folder(self):
        return self.ftp.ListFolder()

    @mainloop_wrap
    def ftp_get_file(self, dst, src):
        path, properties = self.ftp.GetFile(dst, src)
        self.transfer_path = path
        self.transfer_size = properties["Size"]
        return properties["Filename"]


@pytest.fixture
def paired_hosts(hosts):
    from .test_agent import test_agent_pair_bredr

    if hosts[0].agent.has_device(hosts[1].bdaddr):
        return hosts

    test_agent_pair_bredr(hosts, True)
    return hosts


obex_host_config = host_config(
    [Agent(), Obexd(), ObexClient(), Pexpect()],
    [Agent(), Obexd(), ObexAgent()],
    reuse=True,
)


@pytest.fixture
def obex_hosts(paired_hosts):
    host0, host1 = paired_hosts

    if hasattr(host0, "session"):
        return paired_hosts

    host0.obex.connect(host1.bdaddr)

    service = host1.agent.expect("org.bluez.Agent1.AuthorizeService")
    assert service.uuid == FTP_UUID
    host1.agent.reply()

    host0.obex.expect("org.bluez.obex.Client1.CreateSession:reply")

    yield paired_hosts

    host1.obex_agent.cleanup()


@obex_host_config
def test_obex_ftp_list(obex_hosts):
    host0, host1 = obex_hosts

    host1.call(write_obex_file, "test", "1234")

    (item,) = host0.obex.ftp_list_folder()
    assert item["Type"] == "file"
    assert item["Name"] == "test"
    assert item["Size"] == 4


@obex_host_config
def test_obex_ftp_get(obex_hosts):
    host0, host1 = obex_hosts

    host1.call(write_obex_file, "test", "1234")

    filename = host0.obex.ftp_get_file("", "test")
    host0.obex.expect("org.bluez.obex.FileTransfer1:complete")
    assert host0.call(read_file, filename) == "1234"


#
# obexctl tests
#


@pytest.fixture
def obexctl(obex_hosts):
    host0, host1 = obex_hosts

    exe = find_exe("tools", "obexctl")
    obexctl = host0.pexpect.spawn([exe])

    obexctl.expect("Client /org/bluez/obex")
    obexctl.send(f"connect {host1.bdaddr} {FTP_UUID}\n")

    service = host1.agent.expect("org.bluez.Agent1.AuthorizeService")
    assert service.uuid == FTP_UUID
    host1.agent.reply()

    obexctl.expect("Connection successful")
    obexctl.send(f"select /org/bluez/obex/client/session1\n")

    yield obexctl

    obexctl.close()


@obex_host_config
def test_obexctl_list(obex_hosts, obexctl):
    host0, host1 = obex_hosts

    host1.call(write_obex_file, "test", "1234")

    obexctl.send(f"ls\n")
    obexctl.expect(f"Type: file")
    obexctl.expect(f"Name: test")
    obexctl.expect(f"Size: 4")

# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
"""
Fixtures for testing
"""
import os
import sys
import subprocess
import collections
import logging
import tempfile
import time
import shutil
from pathlib import Path

import pytest
import pexpect

from . import env, utils

__all__ = ["host_config", "Bdaddr", "Call", "Bluetoothd", "Bluetoothctl", "DbusSession"]


log = logging.getLogger(__name__)


class Bdaddr(env.HostPlugin):
    name = "bdaddr"

    def setup(self, impl):
        self.value = utils.get_bdaddr()


class Call(env.HostPlugin):
    name = "call"

    def __call__(self, func, *a, **kw):
        return func(*a, **kw)


class _Dbus(env.HostPlugin):
    def __init__(self):
        self.exe = utils.find_exe("", "dbus-daemon")

    def setup(self, impl):
        self.logger = utils.LogStream(self.name)

        self.tmpdir = tempfile.TemporaryDirectory(prefix=f"{self.name}-", dir="/run")
        self.config = Path(self.tmpdir.name) / "config.xml"

        socket = (Path(self.tmpdir.name) / "socket").resolve()
        self.address = "unix:path={}".format(socket)

        with open(self.config, "w") as f:
            text = f"""
            <!DOCTYPE busconfig PUBLIC
                    "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
                    "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
            <busconfig>
            <type>{self.dbus_type}</type>
            <listen>{self.address}</listen>
            <policy context="default">
            <allow user="*"/>
            <allow own="*"/>
            <allow send_type="method_call"/>
            <allow send_type="signal"/>
            <allow send_type="method_return"/>
            <allow send_type="error"/>
            <allow receive_type="method_call"/>
            <allow receive_type="signal"/>
            <allow receive_type="method_return"/>
            <allow receive_type="error"/>
            </policy>
            </busconfig>
            """
            f.write(text)

        cmd = [
            self.exe,
            "--nofork",
            "--nopidfile",
            "--nosyslog",
            f"--config-file={self.config}",
        ]

        self.logger.log.debug(
            "Starting dbus-session @ {}: {}".format(self.address, utils.quoted(cmd))
        )

        self.job = subprocess.Popen(
            cmd,
            stdout=self.logger.stream,
            stderr=subprocess.STDOUT,
        )
        utils.wait_files([self.job], [socket])
        self.logger.log.debug("dbus-session ready")

        if self.dbus_type == "system":
            os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = self.address
        elif self.dbus_type == "session":
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = self.address

    def teardown(self):
        self.job.terminate()
        self.job.wait()
        self.tmpdir.cleanup()


class DbusSystem(_Dbus):
    name = "dbus-system"
    dbus_type = "system"


class DbusSession(_Dbus):
    name = "dbus-session"
    dbus_type = "session"


class Bluetoothd(env.HostPlugin):
    name = "bluetoothd"
    depends = [DbusSystem()]

    def __init__(self, debug=True, conf=None, args=()):
        self.conf = conf
        self.args = tuple(args)
        if debug and "-d" not in self.args:
            self.args += ("-d",)

    def setup(self, impl):
        import dbus

        exe = utils.find_exe("src", "bluetoothd")

        self.tmpdir = tempfile.TemporaryDirectory(prefix="bluetoothd-state-")
        state_dir = Path(self.tmpdir.name) / "state"
        conf = Path(self.tmpdir.name) / "main.conf"

        state_dir.mkdir()

        if self.conf is None:
            shutil.copyfile(utils.SRC_DIR / "src" / "main.conf", conf)
        else:
            with open(str(conf), "w") as f:
                f.write(self.conf)

        envvars = dict(os.environ)
        envvars["STATE_DIRECTORY"] = str(state_dir)

        cmd = [exe, "--nodetach", "-f", str(conf)] + list(self.args)

        log.info("Start bluetoothd: {}".format(utils.quoted(cmd)))

        self.logger = utils.LogStream("bluetoothd")
        self.job = subprocess.Popen(
            cmd,
            env=envvars,
            stdin=subprocess.DEVNULL,
            stdout=self.logger.stream,
            stderr=subprocess.STDOUT,
        )

        # Wait for the adapter to appear powered
        bus = dbus.SystemBus()
        while True:
            try:
                adapter = dbus.Interface(
                    bus.get_object("org.bluez", "/org/bluez/hci0"),
                    "org.freedesktop.DBus.Properties",
                )
                if adapter.Get("org.bluez.Adapter1", "Powered"):
                    break
            except dbus.DBusException:
                pass
            time.sleep(0.5)

        log.info("Bluetoothd ready")

    def teardown(self):
        log.info("Stop bluetoothd")
        self.job.terminate()
        self.job.wait()
        self.tmpdir.cleanup()


class Bluetoothctl(env.HostPlugin):
    name = "bluetoothctl"
    depends = [Bluetoothd()]

    def __init__(self):
        self.exe = utils.find_exe("client", "bluetoothctl")

    def setup(self, impl):
        self.logger = utils.LogStream("bluetoothctl")
        self.ctl = pexpect.spawn(self.exe, logfile=self.logger.stream)

    def teardown(self):
        self.ctl.terminate()
        self.ctl.wait()

    def expect(self, *a, **kw):
        ret = self.ctl.expect(*a, **kw)
        log.debug("pexpect: found")
        return ret, self.ctl.match.groups()

    def expect_prompt(self):
        prompt = "\\[[a-zA-Z0-9. -]+\\]>"
        return self.expect(prompt)

    def send(self, *a, **kw):
        return self.ctl.send(*a, **kw)


HOST_SETUPS = {}


def _expand_plugins(plugins):
    """
    Resolve plugin dependencies to linear load order
    """
    plugins = [Bdaddr(), Call()] + list(plugins)
    to_load = []
    seen = set()

    while plugins:
        deps = []
        for dep in plugins[0].depends or ():
            if type(dep) not in seen:
                deps.append(dep)
                seen.add(type(dep))
                continue

        if deps:
            plugins = deps + plugins
            continue

        to_load.append(plugins.pop(0))

    return tuple(to_load)


def host_config(*host_setup, hw=False):
    """
    Declare host configuration.

    - *host_setup: each argument is a list of plugins to be loaded on a host.
      The number of arguments specifies the number of hosts.

    - hw (bool): whether to require hardware BT controller

    """
    setup = tuple(_expand_plugins(plugins) for plugins in host_setup)

    host_setup = dict(setup=setup)
    vm_setup = dict(num_hosts=len(setup), hw=hw)

    vm_setup_name = "vm{}{}".format(len(setup), "hw" if hw else "")

    idx = HOST_SETUPS.setdefault(tuple(sorted(host_setup.items())), len(HOST_SETUPS))
    host_setup_name = f"hosts{idx}"

    def decorator(func):
        func = pytest.mark.parametrize(
            "host_setup", [host_setup], indirect=True, ids=[host_setup_name]
        )(func)
        func = pytest.mark.parametrize(
            "vm_setup", [vm_setup], indirect=True, ids=[vm_setup_name]
        )(func)
        return func

    return decorator

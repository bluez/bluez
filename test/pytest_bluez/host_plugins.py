# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
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
import signal
import functools
import threading
import resource
from pathlib import Path

import pytest
import pexpect
import dbus
from gi.repository import GLib

from . import env, utils

__all__ = [
    "host_config",
    "parametrized_host_config",
    "Bdaddr",
    "Bluetoothctl",
    "Bluetoothd",
    "Call",
    "DbusSession",
    "DbusSystem",
    "Pexpect",
    "Rcvbuf",
]


class Bdaddr(env.HostPlugin):
    """
    Host plugin providing `host.bdaddr`. Loaded by default.
    """

    name = "bdaddr"

    def setup(self, impl):
        self.value = utils.get_bdaddr()


class Rcvbuf(env.HostPlugin):
    """
    Host plugin setting pipe buffer size defaults. Loaded by default.
    """

    name = "rcvbuf"

    def __init__(self, rcvbuf=None):
        self.rcvbuf = rcvbuf

    def presetup(self, config):
        if self.rcvbuf is None:
            self.rcvbuf = config.getini("host_plugins.rcvbuf.default")

        self.rcvbuf = int(self.rcvbuf)

    def setup(self, impl):
        self.log = logging.getLogger(self.name)

        self.log.info(f"Set SO_RCVBUF default = {self.rcvbuf}")
        with open("/proc/sys/net/core/rmem_default", "wb") as f:
            f.write(f"{self.rcvbuf}".encode("ascii"))


class Call(env.HostPlugin):
    """
    Host plugin providing ``host.call(func, *args, **kw)`` and `call_async`
    which invoke the given functions on VM host side.  Loaded by default.

    Example:

        result = host0.call(my_func, 1, 2, 3)

    Example:

        result_async = host0.call(my_func, 1, 2, 3, sync=False)
        ...
        result = result_async.wait()
    """

    name = "call"

    def setup(self, impl):
        self._results = {}
        self._id = 0
        self.value = self.Proxy()

    def __call__(self, func, *a, **kw):
        return func(*a, **kw)

    def call_async(self, func, *a, **kw):
        value = None
        try:
            value = func(*a, **kw)
        except BaseException as exc:
            value = exc
            raise
        finally:
            self._id += 1
            self._results[self._id] = value

    def wait_async(self, id_value):
        return self._results.pop(id_value)

    class Proxy(env.PluginProxy):
        def __init__(self):
            self._id = 0

        def __call__(self, func, *a, **kw):
            if kw.pop("sync", True):
                return self._conn.call(
                    "call_plugin", self._name, "__call__", func, *a, **kw
                )
            else:
                self._conn.call_noreply(
                    "call_plugin", self._name, "call_async", func, *a, **kw
                )
                self._id += 1
                return Call.ResultProxy(self, self._id)

    class ResultProxy:
        def __init__(self, plugin, id_value):
            self.plugin = plugin
            self.id_value = id_value

        def wait(self):
            return self.plugin.wait_async(self.id_value)


class _Dbus(env.HostPlugin):
    def __init__(self):
        self.exe = utils.find_exe("", "dbus-daemon")

    def setup(self, impl):
        self.log = logging.getLogger(self.name)
        self.log_stream = utils.LogStream(self.name)

        self.tmpdir = utils.TmpDir(prefix=f"{self.name}-")
        self.config = Path(self.tmpdir.name) / "config.xml"

        socket = f"/run/dbus-{self.dbus_type}.socket"
        self.address = "unix:path={}".format(socket)

        # Have to set both, dbus-python needs both early
        os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/dbus-system.socket"
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/run/dbus-session.socket"

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
            <limit name="reply_timeout">{round(utils.DEFAULT_TIMEOUT * 1000)}</limit>
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

        self.log.debug(
            "Starting {} @ {}: {}".format(self.name, self.address, utils.quoted(cmd))
        )

        self.job = subprocess.Popen(
            cmd,
            stdout=self.log_stream.stream,
            stderr=subprocess.STDOUT,
        )
        utils.wait_files([self.job], [socket])
        self.log.debug(f"{self.name} ready")

    def teardown(self):
        self.job.terminate()
        self.tmpdir.cleanup()
        self.log_stream.close()


class DbusSystem(_Dbus):
    """
    Host plugin providing system DBus, at address
    `impl.plugins["dbus-system"].address`.

    Warning:
        dbus-python **MUST** be used only from the GLib main loop,
        as the library has concurrency bugs. All functions using it
        **MUST** either run from GLib main loop eg. via mainloop_wrap
    """

    name = "dbus-system"
    dbus_type = "system"


class DbusSession(_Dbus):
    """
    Host plugin providing system DBus, at address
    `impl.plugins["dbus-session"].address`.

    Warning:
        dbus-python **MUST** be used only from the GLib main loop,
        as the library has concurrency bugs. All functions using it
        **MUST** either run from GLib main loop eg. via mainloop_wrap
    """

    name = "dbus-session"
    dbus_type = "session"


class Bluetoothd(env.HostPlugin):
    """
    Host plugin starting Bluetoothd.
    """

    name = "bluetoothd"
    depends = [DbusSystem()]

    def __init__(self, debug=True, conf=None, args=()):
        super().__init__()

        self.conf = conf
        self.args = tuple(args)
        if debug and "-d" not in self.args:
            self.args += ("-d",)

    @utils.mainloop_wrap
    def setup(self, impl):
        self.log = logging.getLogger(self.name)

        exe = utils.find_exe("src", "bluetoothd")

        self.tmpdir = utils.TmpDir(prefix="bluetoothd-state-")
        state_dir = Path(self.tmpdir.name) / "state"
        conf = Path(self.tmpdir.name) / "main.conf"

        state_dir.mkdir()

        if self.conf is None:
            with open(str(conf), "w") as f:
                pass
        else:
            with open(str(conf), "w") as f:
                f.write(self.conf)

        envvars = dict(os.environ)
        envvars["STATE_DIRECTORY"] = str(state_dir)

        cmd = [exe, "--nodetach", "-f", str(conf)] + list(self.args)

        self.log.info("Start bluetoothd: {}".format(utils.quoted(cmd)))

        self.log_stream = utils.LogStream("bluetoothd")
        self.job = subprocess.Popen(
            cmd,
            env=envvars,
            stdin=subprocess.DEVNULL,
            stdout=self.log_stream.stream,
            stderr=subprocess.STDOUT,
        )

        # Wait for the adapter to appear powered
        self.log.info("Wait for bluetoothd...")
        bus = dbus.SystemBus()
        bus.set_exit_on_disconnect(False)

        def cond():
            try:
                adapter = dbus.Interface(
                    bus.get_object("org.bluez", "/org/bluez/hci0"),
                    "org.freedesktop.DBus.Properties",
                )
                if adapter.Get("org.bluez.Adapter1", "Powered"):
                    return True
            except dbus.DBusException:
                return False

        utils.wait_until(cond)

        self.log.info("Bluetoothd ready")

    def teardown(self):
        self.log.info("Stop bluetoothd")
        self.job.terminate()
        self.tmpdir.cleanup()
        self.log_stream.close()


class Pexpect(env.HostPlugin):
    """
    Host plugin for starting and controlling processes with pexpect.

    Example:

        btmgmt = host0.pexpect.spawn(find_exe("tools", "btmgmt"))
        btmgmt.send("info\n")
        btmgmt.expect("hci0")
        btmgmt.close()
    """

    name = "pexpect"
    depends = []

    def setup(self, impl):
        self.ctls = {}
        self.ctl_id = 0
        self.log = logging.getLogger(self.name)

        self.log_stream = utils.LogStream(self.name)
        self.value = self.Proxy()

    def spawn(self, cmd):
        from pexpect.popen_spawn import PopenSpawn

        self.log.info("Spawn {}".format(utils.quoted(cmd)))

        ctl = pexpect.popen_spawn.PopenSpawn(
            cmd,
            logfile=self.log_stream.stream,
            timeout=utils.DEFAULT_TIMEOUT,
        )
        self.ctl_id += 1
        self.ctls[self.ctl_id] = ctl
        return self.ctl_id

    def teardown(self):
        for ctl in self.ctls.values():
            ctl.sendeof()
            ctl.kill(signal.SIGTERM)
        self.log_stream.close()

    def close(self, ctl_id):
        ctl = self.ctls[ctl_id]
        ctl.sendeof()
        ctl.kill(signal.SIGTERM)
        del self.ctls[ctl_id]

    def expect(self, ctl_id, *a, **kw):
        ctl = self.ctls[ctl_id]
        ret = ctl.expect(*a, **kw)
        self.log.debug("match found")
        return ret, ctl.match.groups()

    def send(self, ctl_id, *a, **kw):
        ctl = self.ctls[ctl_id]
        return ctl.send(*a, **kw)

    class Proxy(env.PluginProxy):
        def spawn(self, cmd):
            ctl_id = self._conn.call("call_plugin", self._name, "spawn", cmd)
            return Pexpect.CtlProxy(self, ctl_id)

    class CtlProxy:
        def __init__(self, plugin, ctl_id):
            self._plugin = plugin
            self.ctl_id = ctl_id

        def __getattr__(self, name):
            method = getattr(self._plugin, name)
            return lambda *a, **kw: method(self.ctl_id, *a, **kw)

        def __enter__(self):
            return self

        def __exit__(self, type, value, tb):
            self.close()


class Bluetoothctl(env.HostPlugin):
    """
    Host plugin for starting and controlling `bluetoothctl` with pexpect.
    """

    name = "bluetoothctl"
    depends = [Bluetoothd()]

    def __init__(self):
        self.exe = utils.find_exe("client", "bluetoothctl")

    def setup(self, impl):
        from pexpect.popen_spawn import PopenSpawn

        self.log = logging.getLogger(self.name)
        self.log_stream = utils.LogStream(self.name)

        # Note: pexpect.spawn doesn't work under load: using a PTY
        # appears to cause some messages be not received by
        # bluetoothctl
        self.ctl = pexpect.popen_spawn.PopenSpawn(
            self.exe, logfile=self.log_stream.stream, timeout=utils.DEFAULT_TIMEOUT
        )

    def teardown(self):
        self.ctl.sendeof()
        self.ctl.kill(signal.SIGTERM)
        self.log_stream.close()

    def expect(self, *a, **kw):
        ret = self.ctl.expect(*a, **kw)
        self.log.debug("match found")
        return ret, self.ctl.match.groups()

    def send(self, *a, **kw):
        return self.ctl.send(*a, **kw)


HOST_SETUPS = 0
DEFAULT_PLUGINS = [Rcvbuf(), Bdaddr(), Call()]


def _expand_plugins(plugins):
    """
    Resolve plugin dependencies to linear load order
    """
    plugins = DEFAULT_PLUGINS + list(plugins)
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


def parametrized_host_config(
    param_host_setups, hw=False, mem=None, ids=None, reuse=False
):
    """
    Declare parametrized host configurations.

    See https://docs.pytest.org/en/stable/how-to/parametrize.html for the
    concept.

    Args:
        param_host_setups (list): list of host setups
        hw (bool): whether to require hardware BT controller
        reuse (bool): whether to define a setup where the test host processes
            are not required to be torn down between tests. This is only useful
            for tests that do not perturb e.g. bluetoothd state too much.

    Returns:
        callable: decorator setting pytest attributes
    """
    global HOST_SETUPS

    host_setups = []
    host_ids = []

    if ids is not None:
        if len(ids) != len(param_host_setups):
            raise ValueError("Wrong number of ids")
        host_ids = list(ids)

    num_hosts = set(len(setup) for setup in param_host_setups)
    if len(num_hosts) > 1:
        raise ValueError("Parametrized host setups must have same host count")
    num_hosts = num_hosts.pop()

    for host_setup in param_host_setups:
        setup = tuple(_expand_plugins(plugins) for plugins in host_setup)

        name = f"hosts{HOST_SETUPS}"
        HOST_SETUPS += 1

        host_setup = dict(setup=setup, name=name, reuse=bool(reuse))
        host_setups.append(host_setup)

        if ids is None:
            host_ids.append(name)

    vm_setup = dict(num_hosts=num_hosts, hw=hw, mem=str(mem) if mem else "")
    vm_ids = [
        "vm{}{}{}".format(len(setup), f"-{mem}" if mem else "", "-hw" if hw else "")
    ]

    def decorator(func):
        func = pytest.mark.parametrize(
            "host_setup", host_setups, indirect=True, ids=host_ids
        )(func)
        func = pytest.mark.parametrize(
            "vm_setup", [vm_setup], indirect=True, ids=vm_ids
        )(func)
        return func

    return decorator


def host_config(*host_setup, hw=False, mem=None, reuse=False):
    """
    Declare host configuration.

    Args:
        *host_setup: each argument is a list of plugins to be loaded on a host.
            The number of arguments specifies the number of hosts.
        hw (bool): whether to require hardware BT controller
        mem (str): amount of memory for the VM instances
        reuse (bool): whether to define a setup where the test host processes
            are not required to be torn down between tests. This is only useful
            for tests that do not perturb e.g. bluetoothd state too much.

    Returns:
        callable: decorator setting pytest attributes

    Example:

        @host_config([Bluetoothd()], [Bluetoothd()])
        def test_something(hosts):
            host0, host1 = hosts

    Example:

        # Allow not restarting Bluetoothd between tests sharing this configuration
        base_config = host_config([Bluetoothd()], reuse=True)

        @base_config
        def test_one(hosts):
            host0, = hosts

        @base_config
        def test_two(hosts):
            # Note: uses same Bluetoothd() instance as above
            host0, = hosts

    """
    return parametrized_host_config([host_setup], hw=hw, mem=mem, reuse=reuse)

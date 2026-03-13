# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
"""
Tests for Pipewire audio
"""
import sys
import os
import pytest
import subprocess
import tempfile
import time
import logging
import json
import dbus
from pathlib import Path

from .lib import (
    HostPlugin,
    host_config,
    find_exe,
    Bluetoothd,
    Bluetoothctl,
    DbusSession,
    LogStream,
)

pytestmark = [pytest.mark.vm, pytest.mark.pipewire]

log = logging.getLogger(__name__)


class Pipewire(HostPlugin):
    name = "pipewire"
    depends = [DbusSession(), Bluetoothd()]

    def __init__(
        self,
        uuids=(
            "0000110a-0000-1000-8000-00805f9b34fb",
            "0000110b-0000-1000-8000-00805f9b34fb",
        ),
    ):
        self.uuids = tuple(uuids)
        try:
            self.exe_pw = find_exe("", "pipewire")
            self.exe_wp = find_exe("", "wireplumber")
            self.exe_dump = find_exe("", "pw-dump")
        except FileNotFoundError:
            pytest.skip("skip", allow_module_level=True, reason="Pipewire not found")

    def setup(self, impl):
        self.tmpdir = tempfile.TemporaryDirectory(prefix="pipewire-", dir="/run")
        conf_dir = Path(self.tmpdir.name) / "config"
        runtime_dir = Path(self.tmpdir.name) / "runtime"

        conf_dir.mkdir()
        runtime_dir.mkdir()

        environ = dict(os.environ)

        environ["XDG_CONFIG_HOME"] = str(conf_dir)
        environ["XDG_STATE_HOME"] = str(runtime_dir)
        environ["XDG_RUNTIME_HOME"] = str(runtime_dir)
        environ["PIPEWIRE_RUNTIME_DIR"] = str(runtime_dir)
        environ["PIPEWIRE_DEBUG"] = "2"
        environ["WIREPLUMBER_DEBUG"] = "3"

        os.environ["PIPEWIRE_RUNTIME_DIR"] = str(runtime_dir)

        log.info("Start pipewire")

        self.logger = LogStream("pipewire")
        self.pw = subprocess.Popen(
            self.exe_pw,
            env=environ,
            stdout=self.logger.stream,
            stderr=subprocess.STDOUT,
        )
        self.wp = subprocess.Popen(
            self.exe_wp,
            env=environ,
            stdout=self.logger.stream,
            stderr=subprocess.STDOUT,
        )

        # Wait for Pipewire's bluetooth services
        bus = dbus.SystemBus()
        adapter = dbus.Interface(
            bus.get_object("org.bluez", "/org/bluez/hci0"),
            "org.freedesktop.DBus.Properties",
        )
        while True:
            uuids = [str(uuid) for uuid in adapter.Get("org.bluez.Adapter1", "UUIDs")]
            if all(uuid in uuids for uuid in self.uuids):
                break
            time.sleep(0.1)

        log.info("Pipewire ready")

    def pw_dump(self):
        ret = subprocess.run(["pw-dump"], stdout=subprocess.PIPE, encoding="utf-8")
        return ret.stdout

    def teardown(self):
        log.info("Stop pipewire")
        self.pw.terminate()
        self.wp.terminate()
        self.pw.wait()
        self.wp.wait()
        self.tmpdir.cleanup()


@host_config(
    [Bluetoothctl(), Pipewire()],
    [Bluetoothctl(), Pipewire()],
)
def test_pipewire(hosts):
    from .test_bluetoothctl_vm import test_bluetoothctl_pair

    host0, host1 = hosts

    # Pair first
    test_bluetoothctl_pair(hosts)

    # Connect
    host1.bluetoothctl.send(f"trust {host0.bdaddr}\n")

    host0.bluetoothctl.send(f"scan off\n")
    host0.bluetoothctl.send(f"connect {host1.bdaddr}\n")

    # Wait for pipewire devices to appear
    for j in range(20):
        text = host0.pipewire.pw_dump()
        if "bluez_output." in text:
            break
        time.sleep(1)
    else:
        assert False, "no pipewire devices seen within timeout"

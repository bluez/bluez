# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for bluetoothctl using VM instances
"""
import sys
import re
import pytest
import subprocess
import tempfile
import warnings

import time
import logging


from pytest_bluez import host_config, find_exe, run, Bluetoothd, Bluetoothctl

pytestmark = [pytest.mark.vm]

bluetoothctl = find_exe("client", "bluetoothctl")

bluetoothd_reuse_config = host_config([Bluetoothd()], reuse=True)


@host_config(
    [Bluetoothctl()],
    [Bluetoothctl()],
)
def test_bluetoothctl_pair_bredr(hosts):
    host0, host1 = hosts

    host0.bluetoothctl.send("scan on\n")
    host0.bluetoothctl.expect(f"Controller {host0.bdaddr.upper()} Discovering: yes")

    host1.bluetoothctl.send("pairable on\n")
    host1.bluetoothctl.expect("Changing pairable on succeeded")
    host1.bluetoothctl.send("discoverable on\n")
    host1.bluetoothctl.expect(f"Controller {host1.bdaddr.upper()} Discoverable: yes")

    host0.bluetoothctl.expect(f"Device {host1.bdaddr.upper()}")
    host0.bluetoothctl.send(f"pair {host1.bdaddr}\n")

    idx, m = host0.bluetoothctl.expect(r"Confirm passkey (\d+).*:")
    key = m[0].decode("utf-8")

    host1.bluetoothctl.expect(f"Confirm passkey {key}")

    host0.bluetoothctl.send("yes\n")
    host1.bluetoothctl.send("yes\n")

    host0.bluetoothctl.expect("Pairing successful")


@host_config(
    [Bluetoothd(conf="[General]\nControllerMode = le\n"), Bluetoothctl()],
    [Bluetoothd(conf="[General]\nControllerMode = le\n"), Bluetoothctl()],
)
def test_bluetoothctl_pair_le(hosts):
    host0, host1 = hosts

    host0.bluetoothctl.send("scan on\n")
    host0.bluetoothctl.expect(f"Controller {host0.bdaddr.upper()} Discovering: yes")

    host1.bluetoothctl.send("advertise on\n")
    host1.bluetoothctl.expect("Advertising object registered")

    host0.bluetoothctl.expect(f"Device {host1.bdaddr.upper()}")
    host0.bluetoothctl.send(f"pair {host1.bdaddr.upper()}\n")

    # BUG!: if controller is power cycled off/on at boot (before bluetoothd)
    # BUG!: which is what the tester here does,
    # BUG!: bluetoothd MGMT command to enable Secure Connections Host Support
    # BUG!: fails and we are left with legacy passkey. It seems we get randomly
    # BUG!: one of these depending on what state controller/kernel were before
    # BUG!: btmgmt power off/on

    idx, m = host0.bluetoothctl.expect(
        [r"\[agent\].*Passkey:.*m(\d+)", r"Confirm passkey (\d+).*:"]
    )
    key = m[0].decode("utf-8")

    if idx == 0:
        warnings.warn(
            "BUG: we got passkey authentication, bluetoothd/kernel should be fixed"
        )
        host1.bluetoothctl.expect(r"\[agent\] Enter passkey \(number in 0-999999\):")
        host1.bluetoothctl.send(f"{key}\n")
    else:
        host1.bluetoothctl.expect(f"Confirm passkey {key}")

        host0.bluetoothctl.send("yes\n")
        host1.bluetoothctl.send("yes\n")

    host0.bluetoothctl.expect("Pairing successful")


def run_bluetoothctl(*args):
    return run(
        [bluetoothctl] + list(args),
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        encoding="utf-8",
    )


def run_bluetoothctl_script(script):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as f:
        f.write(script)
        f.write("\nquit")
        f.flush()
        return run_bluetoothctl("--init-script", f.name)


@bluetoothd_reuse_config
def test_bluetoothctl_show(hosts):
    (host,) = hosts

    result = host.call(run_bluetoothctl, f"show")
    assert result.returncode == 0
    assert f"Controller {host.bdaddr.upper()}" in result.stdout
    assert "Powered: " in result.stdout
    assert "Discoverable: no" in result.stdout


@bluetoothd_reuse_config
def test_bluetoothctl_list(hosts):
    (host,) = hosts

    result = host.call(run_bluetoothctl, "list")
    assert result.returncode == 0
    assert re.search(rf"{host.bdaddr.upper()}.*\[default\]", result.stdout)


@bluetoothd_reuse_config
def test_bluetoothctl_script_show(hosts):
    (host,) = hosts

    result = host.call(run_bluetoothctl_script, f"show")
    assert result.returncode == 0
    assert f"Controller {host.bdaddr.upper()}" in result.stdout
    assert "Powered: " in result.stdout
    assert "Discoverable: no" in result.stdout


@bluetoothd_reuse_config
def test_bluetoothctl_script_list(hosts):
    (host,) = hosts

    result = host.call(run_bluetoothctl_script, f"list")
    assert result.returncode == 0
    assert re.search(rf"{host.bdaddr.upper()}.*\[default\]", result.stdout)

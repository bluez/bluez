# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
"""
Tests for bluetoothctl using VM instances
"""
import sys
import pytest
import subprocess
import tempfile

from .lib import host_config, find_exe, run, Bluetoothd, Bluetoothctl

pytestmark = [pytest.mark.vm]

bluetoothctl = find_exe("client", "bluetoothctl")


@host_config(
    [Bluetoothctl()],
    [Bluetoothctl()],
)
def test_bluetoothctl_pair(hosts):
    host0, host1 = hosts

    host0.bluetoothctl.send("show\n")
    host0.bluetoothctl.expect("Powered: yes")

    host1.bluetoothctl.send("show\n")
    host1.bluetoothctl.expect("Powered: yes")

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


def bluetoothctl_script(script):
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete_on_close=False
    ) as f:
        f.write(script)
        f.write("\nquit")
        f.close()
        return run(
            [bluetoothctl, "--init-script", f.name],
            stdout=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            encoding="utf-8",
        )


@host_config([Bluetoothd()])
def test_bluetoothctl_script_show(hosts):
    (host,) = hosts

    result = host.call(bluetoothctl_script, f"show")
    assert result.returncode == 0

    assert f"Controller {host.bdaddr.upper()}" in result.stdout
    assert "Powered: " in result.stdout
    assert "Discoverable: no" in result.stdout

# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for BAP (LE Audio) using bluetoothctl in VM instances
"""

import warnings

import pytest

from pytest_bluezenv import Bluetoothd, Pexpect, find_exe, host_config
from pytest_bluezenv.utils import bluez_src_dir

pytestmark = [pytest.mark.vm]

PAC_SINK_UUID = "00002bc9-0000-1000-8000-00805f9b34fb"
PAC_SOURCE_UUID = "00002bcb-0000-1000-8000-00805f9b34fb"

# BAP requires the ISO socket support, which is kernel experimental
BAP_CONF = """[General]
Experimental = true
KernelExperimental = true
ControllerMode = le
"""

PRESET = "16_2_1"

TRANSPORT_RE = r"Transport (/org/bluez/\S+/fd\d+)"


def dev_addr(host):
    return host.bdaddr.upper().replace(":", "_")


def expect_all(ctl, patterns):
    """
    Expect all the given patterns, in any order.
    """
    patterns = list(patterns)

    while patterns:
        idx, _ = ctl.expect(patterns)
        patterns.pop(idx)


def script(name):
    src = bluez_src_dir()
    if src is None:
        pytest.skip("BlueZ source directory not known")

    path = src / "client" / "scripts" / name
    if not path.exists():
        pytest.skip(f"{path} not found")

    return str(path)


def start_bluetoothctl(host, init_script):
    exe = find_exe("client", "bluetoothctl")
    # -a auto: accept pairing and authorize services without prompting
    ctl = host.pexpect.spawn([exe, "-a", "auto", "--init-script", script(init_script)])
    ctl.expect("Endpoint /local/endpoint/ep0 registered")
    return ctl


def pair_le(host0, ctl0, host1, ctl1):
    ctl0.send("scan on\n")
    ctl0.expect(f"Controller {host0.bdaddr.upper()} Discovering: yes")

    ctl1.send("advertise on\n")
    ctl1.expect("Advertising object registered")

    ctl0.expect(f"Device {host1.bdaddr.upper()}")
    ctl0.send(f"pair {host1.bdaddr.upper()}\n")

    # See test_bluetoothctl_pair_le: passkey confirmation is handled by
    # the auto agent, but legacy passkey entry still needs an answer
    idx, m = ctl0.expect([r"\[agent\].*Passkey:.*m(\d+)", "Pairing successful"])

    if idx == 0:
        warnings.warn(
            "BUG: we got passkey authentication, bluetoothd/kernel should be fixed"
        )
        key = m[0].decode("utf-8")
        ctl1.expect(r"\[agent\] Enter passkey \(number in 0-999999\):")
        ctl1.send(f"{key}\n")
        ctl0.expect("Pairing successful")

    ctl0.send("scan off\n")


unicast_host_config = host_config(
    [Bluetoothd(conf=BAP_CONF), Pexpect()],
    [Bluetoothd(conf=BAP_CONF), Pexpect()],
)


@pytest.fixture
def unicast_hosts(hosts):
    """
    Initiator (host0) with a local PAC Source endpoint and acceptor
    (host1) with a local PAC Sink endpoint, paired over LE, with the
    remote PAC Sink endpoint configured.
    """
    host0, host1 = hosts

    initiator = start_bluetoothctl(host0, "bap-source-lc3.bt")
    acceptor = start_bluetoothctl(host1, "bap-sink-lc3.bt")

    pair_le(host0, initiator, host1, acceptor)

    # Remote PAC Sink endpoint is exposed once services are resolved
    _, m = initiator.expect(r"Endpoint (/org/bluez/\S+/pac_sink\d+)")
    remote = m[0].decode("utf-8")

    initiator.send(f"endpoint.config {remote} /local/endpoint/ep0 {PRESET}\n")

    yield host0, host1, initiator, acceptor


def expect_transports(ctl):
    """
    The endpoint is configured for stereo, so one stream per location is
    created, each with its own CIS in the same CIG.
    """
    _, m = ctl.expect(r"Transport (/org/bluez/\S+/fd0)")
    left = m[0].decode("utf-8")
    _, m = ctl.expect(r"Transport (/org/bluez/\S+/fd1)")
    right = m[0].decode("utf-8")

    return left, right


@unicast_host_config
def test_bap_unicast_transport_created(unicast_hosts):
    host0, host1, initiator, acceptor = unicast_hosts

    left, right = expect_transports(initiator)
    expect_transports(acceptor)

    for transport in (left, right):
        initiator.send(f"transport.show {transport}\n")
        initiator.expect(f"Transport {transport}")
        initiator.expect(rf"UUID: .*\({PAC_SOURCE_UUID}\)")
        initiator.expect(r"Codec: 0x06")
        initiator.expect(f"Device: /org/bluez/hci0/dev_{dev_addr(host1)}")
        initiator.expect("State: idle")


@unicast_host_config
def test_bap_unicast_transport_acquire(unicast_hosts):
    host0, host1, initiator, acceptor = unicast_hosts

    left, right = expect_transports(initiator)

    # The CIS are only created once every CIS of the CIG is ready, so
    # all the transports need to be acquired
    initiator.send(f"transport.acquire {left} {right}\n")

    acquired = r"Acquire successful: fd \d+ MTU \d+:\d+"
    expect_all(
        initiator,
        [
            acquired,
            acquired,
            f"Transport {left} State: active",
            f"Transport {right} State: active",
        ],
    )

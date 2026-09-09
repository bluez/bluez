# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for A2DP using bluetoothctl in VM instances
"""

import pytest

from pytest_bluezenv import Bluetoothd, Pexpect, find_exe, host_config
from pytest_bluezenv.utils import bluez_src_dir

pytestmark = [pytest.mark.vm]

A2DP_SOURCE_UUID = "0000110a-0000-1000-8000-00805f9b34fb"
A2DP_SINK_UUID = "0000110b-0000-1000-8000-00805f9b34fb"

TRANSPORT_RE = r"Transport (/org/bluez/\S+/fd\d+)"


def dev_addr(host):
    return host.bdaddr.upper().replace(":", "_")


def script(name):
    src = bluez_src_dir()
    if src is None:
        pytest.skip("BlueZ source directory not known")

    path = src / "client" / "scripts" / name
    if not path.exists():
        pytest.skip(f"{path} not found")

    return str(path)


def start_bluetoothctl(host, init_script):
    """
    Start bluetoothctl registering the endpoints of the given script.

    The endpoints are registered before pairing, so that the SDP
    records are in place when the peer resolves the services.
    """
    exe = find_exe("client", "bluetoothctl")
    ctl = host.pexpect.spawn([exe, "--init-script", script(init_script)])
    ctl.expect("Endpoint /local/endpoint/ep0 registered")
    return ctl


def pair(host0, ctl0, host1, ctl1):
    ctl0.send("scan on\n")
    ctl0.expect(f"Controller {host0.bdaddr.upper()} Discovering: yes")

    ctl1.send("pairable on\n")
    ctl1.expect("Changing pairable on succeeded")
    ctl1.send("discoverable on\n")
    ctl1.expect(f"Controller {host1.bdaddr.upper()} Discoverable: yes")

    ctl0.expect(f"Device {host1.bdaddr.upper()}")
    ctl0.send(f"pair {host1.bdaddr}\n")

    idx, m = ctl0.expect(r"Confirm passkey (\d+).*:")
    key = m[0].decode("utf-8")

    ctl1.expect(f"Confirm passkey {key}")

    ctl0.send("yes\n")
    ctl1.send("yes\n")

    ctl0.expect("Pairing successful")

    ctl0.send("scan off\n")

    # Avoid service authorization prompts when connecting
    ctl1.send(f"trust {host0.bdaddr}\n")
    ctl1.expect("trust succeeded")
    ctl0.send(f"trust {host1.bdaddr}\n")
    ctl0.expect("trust succeeded")


a2dp_host_config = host_config(
    [Bluetoothd(), Pexpect()],
    [Bluetoothd(), Pexpect()],
)


@pytest.fixture
def a2dp_hosts(hosts):
    """
    Two hosts with A2DP endpoints registered via bluetoothctl: host0 is
    the central with an A2DP Source endpoint, host1 the peripheral with
    an A2DP Sink endpoint. The hosts are paired and connected, so that
    a stream is configured.
    """
    host0, host1 = hosts

    source = start_bluetoothctl(host0, "a2dp-source.bt")
    sink = start_bluetoothctl(host1, "a2dp-sink.bt")

    pair(host0, source, host1, sink)

    source.send(f"connect {host1.bdaddr}\n")
    source.expect("Connection successful")

    yield host0, host1, source, sink


@a2dp_host_config
def test_a2dp_transport_created(a2dp_hosts):
    host0, host1, source, sink = a2dp_hosts

    # Transport is created on both sides once the stream is configured
    _, m = source.expect(TRANSPORT_RE)
    transport = m[0].decode("utf-8")

    _, m = sink.expect(TRANSPORT_RE)
    sink_transport = m[0].decode("utf-8")

    # Central holds the A2DP Source endpoint
    source.send(f"transport.show {transport}\n")
    source.expect(f"Transport {transport}")
    source.expect(rf"UUID: Audio Source\s+\({A2DP_SOURCE_UUID}\)")
    source.expect(r"Codec: 0x00")
    source.expect("Media Codec: SBC")
    source.expect(f"Device: /org/bluez/hci0/dev_{dev_addr(host1)}")
    source.expect("State: idle")

    # Peripheral holds the A2DP Sink endpoint
    sink.send(f"transport.show {sink_transport}\n")
    sink.expect(f"Transport {sink_transport}")
    sink.expect(rf"UUID: Audio Sink\s+\({A2DP_SINK_UUID}\)")
    sink.expect(r"Codec: 0x00")


@a2dp_host_config
def test_a2dp_transport_acquire(a2dp_hosts):
    host0, host1, source, sink = a2dp_hosts

    _, m = source.expect(TRANSPORT_RE)
    transport = m[0].decode("utf-8")

    source.send(f"transport.acquire {transport}\n")
    source.expect(r"Acquire successful: fd \d+ MTU \d+:\d+")

    source.expect(f"Transport {transport} State: active")

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
    Expect all the given patterns, in any order, returning the groups
    each of them matched.
    """
    pending = list(enumerate(patterns))
    groups = [None] * len(patterns)

    while pending:
        idx, m = ctl.expect([pattern for _, pattern in pending])
        groups[pending[idx][0]] = m
        pending.pop(idx)

    return groups


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


def pair_le(host0, ctl0, host1, ctl1, advertise=True, services=False):
    ctl0.send("scan on\n")
    ctl0.expect(f"Controller {host0.bdaddr.upper()} Discovering: yes")

    if advertise:
        ctl1.send("advertise on\n")
        ctl1.expect("Advertising object registered")

    ctl0.expect(f"Device {host1.bdaddr.upper()}")
    ctl0.send(f"pair {host1.bdaddr.upper()}\n")

    pending = ["Pairing successful"]
    if services:
        pending.append(f"Device {host1.bdaddr.upper()} ServicesResolved: yes")

    # See test_bluetoothctl_pair_le: passkey confirmation is handled by
    # the auto agent, but legacy passkey entry still needs an answer
    legacy = r"\[agent\].*Passkey:.*m(\d+)"

    while pending:
        idx, m = ctl0.expect([legacy] + pending)

        if idx == 0:
            warnings.warn(
                "BUG: we got passkey authentication, bluetoothd/kernel "
                "should be fixed"
            )
            key = m[0].decode("utf-8")
            ctl1.expect(r"\[agent\] Enter passkey \(number in 0-999999\):")
            ctl1.send(f"{key}\n")
            continue

        pending.pop(idx - 1)

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


# Broadcast code used by the broadcast scripts, see BCAST_CODE in
# client/player.c
BCAST_CODE = (
    "0x01 0x02 0x68 0x05 0x53 0xf1 0x41 0x5a " "0xa2 0x65 0xbb 0xaf 0xc6 0xea 0x03 0xb8"
)

BCAST_SOURCES = ["broadcast-source.bt", "broadcast-source-pbp.bt"]
BCAST_IDS = ["lc3", "pbp"]

broadcast_host_config = host_config(
    [Bluetoothd(conf=BAP_CONF), Pexpect()],
    [Bluetoothd(conf=BAP_CONF), Pexpect()],
)


def start_broadcast(hosts, source_script):
    """
    Source broadcasting with the given script, and sink scanning for it.
    """
    source_host, sink_host = hosts

    source = start_bluetoothctl(source_host, source_script)
    source.expect(r"Acquire successful: fd \d+ MTU \d+:\d+")

    sink = start_bluetoothctl(sink_host, "broadcast-sink.bt")

    return source, sink


@broadcast_host_config
@pytest.mark.parametrize("source_script", BCAST_SOURCES, ids=BCAST_IDS)
def test_bap_broadcast_transport_created(hosts, source_script):
    source, sink = start_broadcast(hosts, source_script)

    # Sink syncs to the periodic advertising and creates a transport
    # for each BIS described by the BASE
    _, m = sink.expect(TRANSPORT_RE)
    transport = m[0].decode("utf-8")

    sink.send(f"transport.show {transport}\n")
    sink.expect(f"Transport {transport}")
    sink.expect(r"Codec: 0x06")
    sink.expect("State: idle")


@broadcast_host_config
@pytest.mark.parametrize("source_script", BCAST_SOURCES, ids=BCAST_IDS)
def test_bap_broadcast_transport_acquire(hosts, source_script):
    source, sink = start_broadcast(hosts, source_script)

    _, m = sink.expect(TRANSPORT_RE)
    transport = m[0].decode("utf-8")

    # Selecting the transport syncs to the BIG and starts acquiring it
    sink.send(f"transport.select {transport}\n")
    sink.expect(r"Enter bcode\[value/no\]:")
    sink.send(f"{BCAST_CODE}\n")

    expect_all(
        sink,
        [
            f"Transport {transport} State: broadcasting",
            r"Acquire successful: fd \d+ MTU \d+:\d+",
            f"Transport {transport} State: active",
        ],
    )


past_host_config = host_config(
    [Bluetoothd(conf=BAP_CONF), Pexpect()],
    [Bluetoothd(conf=BAP_CONF), Pexpect()],
)

LOCAL_ASSISTANT_RE = r"Assistant (/org/bluez/\S+/sid\d+/bis\d+)"


@past_host_config
def test_bass_past_transport_acquire(hosts):
    source_host, delegator_host = hosts

    # Source broadcasting, and its own stream exposed as a local
    # MediaAssistant object
    source = start_bluetoothctl(source_host, "broadcast-source.bt")
    groups = expect_all(
        source,
        [LOCAL_ASSISTANT_RE, r"Acquire successful: fd \d+ MTU \d+:\d+"],
    )
    assistant_path = groups[0][0].decode("utf-8")

    # Delegator advertising, selecting and acquiring automatically
    delegator = start_bluetoothctl(delegator_host, "broadcast-delegator.bt")
    delegator.expect("Advertising object registered")

    # Pair with the delegator: the Broadcast Receive State requires
    # an encrypted link to be read
    pair_le(
        source_host,
        source,
        delegator_host,
        delegator,
        advertise=False,
        services=True,
    )

    # Share the local broadcast: the delegator receives the periodic
    # advertising sync over the connection (PAST)
    source.send(f"assistant.push {assistant_path}\n")
    source.expect(r"Enter Device \(path\):")
    source.send(f"/org/bluez/hci0/dev_{dev_addr(delegator_host)}\n")

    # The local stream may already know the broadcast code
    idx, _ = source.expect(
        [r"Enter Broadcast Code \(auto/value\):", r"Assistant \S+ pushed"]
    )
    if idx == 0:
        source.send(f"{BCAST_CODE}\n")
        source.expect(r"Assistant \S+ pushed")

    # A transport is created on the delegator, selected and acquired
    # automatically
    _, m = delegator.expect(TRANSPORT_RE)
    transport = m[0].decode("utf-8")

    expect_all(
        delegator,
        [
            r"Acquire successful: fd \d+ MTU \d+:\d+",
            f"Transport {transport} State: broadcasting",
            f"Transport {transport} State: active",
        ],
    )

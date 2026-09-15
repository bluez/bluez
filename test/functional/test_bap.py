# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for BAP (LE Audio) using bluetoothctl in VM instances
"""

import re
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


# Reported when an operation cannot complete, so a test does not have to
# wait for its timeout to know it is not going to
FAILURES = [
    r"(Failed to \w+[^\r\n]*)",
    r"(Device \S+ not available)",
]


def expect_all(ctl, patterns, failures=FAILURES):
    """
    Expect all the given patterns, in any order, returning the groups
    each of them matched.

    Fail as soon as one of the failures shows up, e.g. a request that
    was rejected, instead of waiting for the timeout.
    """
    pending = list(enumerate(patterns))
    groups = [None] * len(patterns)

    while pending:
        idx, m = ctl.expect(list(failures) + [pattern for _, pattern in pending])

        if idx < len(failures):
            raise AssertionError(m[0].decode("utf-8") if m else "failed")

        idx -= len(failures)
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
    # Accept pairing and authorize services without prompting, with a
    # capability pairing Just Works, as there is no one to answer the
    # entry of a passkey
    ctl = host.pexpect.spawn(
        [
            exe,
            "-a",
            "auto:NoInputNoOutput",
            "--init-script",
            script(init_script),
        ]
    )
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

    pair_wait(ctl0, ctl1, pending)

    ctl0.send("scan off\n")


# Transport of the remote PAC Sink endpoint of a device
TRANSPORT = r"Transport (/org/bluez/hci0/dev_{}/pac_sink\d+/fd\d+)"

# What a command reports is printed as it runs, unlike what the peers
# report over the air, so waiting the default timeout for it only makes
# a failure slower
REPLY_TIMEOUT = 5


def list_transports(ctl0, hosts):
    """
    List the transports already available for the given hosts, giving
    None for those that are not.

    The listing has no end of its own, so a command with a known output
    is issued after it to tell when everything has been listed.
    """
    patterns = [TRANSPORT.format(dev_addr(host)) for host in hosts]

    ctl0.send("transport.list\nversion\n")

    transports = [None] * len(patterns)

    while True:
        idx, m = ctl0.expect([r"Version \d"] + patterns, timeout=REPLY_TIMEOUT)
        if not idx:
            return transports

        transports[idx - 1] = m[0].decode("utf-8")


def remove_device(ctl0, host):
    """
    Remove the given host, so the test starts from a state where it is
    neither paired nor connected.
    """
    addr = host.bdaddr.upper()

    ctl0.send(f"remove {addr}\n")

    # Not matched with expect_all: a device that is not available is
    # simply one with nothing to remove, not a failure
    ctl0.expect(
        rf"Device has been removed|Device {addr} not available",
        timeout=REPLY_TIMEOUT,
    )


def pair_wait(ctl0, ctl1, pending):
    """
    Wait for the given events while answering the pairing requests.
    """
    # See test_bluetoothctl_pair_le: passkey confirmation is handled by
    # the auto agent, but legacy passkey entry still needs an answer
    legacy = r"\[agent\].*Passkey:.*m(\d+)"

    pending = list(pending)

    while pending:
        idx, m = ctl0.expect(FAILURES + [legacy] + pending)

        if idx < len(FAILURES):
            raise AssertionError(m[0].decode("utf-8") if m else "failed")

        idx -= len(FAILURES)

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


# Key shared by the members of the set, see [CSIS] in main.conf
SIRK = "861FAE703ED681F0C50B34155B6434FB"

# A set is exposed under the SIRK of its members, in reverse byte order
SET_PATH = "set_" + bytes.fromhex(SIRK)[::-1].hex()


def csip_conf(rank):
    """
    Configuration of a member of a coordinated set: the key and the size
    describe the set, so they are the same for every member, while the
    rank identifies the member within it.
    """
    return BAP_CONF + f"""
[CSIS]
SIRK = {SIRK}
Encryption = true
Size = 2
Rank = {rank}
"""


set_host_config = host_config(
    [Bluetoothd(conf=BAP_CONF), Pexpect()],
    [Bluetoothd(conf=csip_conf(1)), Pexpect()],
    [Bluetoothd(conf=csip_conf(2)), Pexpect()],
)


@pytest.fixture
def set_hosts(hosts):
    """
    Initiator (host0) and two acceptors forming a coordinated set, one
    taking the left channel (host1) and one the right (host2), paired
    over LE.
    """
    host0, host1, host2 = hosts

    initiator = start_bluetoothctl(host0, "bap-source-lc3.bt")
    left = start_bluetoothctl(host1, "bap-sink-lc3-left.bt")
    right = start_bluetoothctl(host2, "bap-sink-lc3-right.bt")

    # Every member has to be advertising before connecting, so the set
    # can be resolved and the remaining members found. The acceptors
    # advertise themselves, as they have to include the RSI.
    #
    # Matched before anything else is read from them, as an expect
    # discards everything before what it matches.
    left.expect("Advertising object registered", timeout=REPLY_TIMEOUT)
    right.expect("Advertising object registered", timeout=REPLY_TIMEOUT)

    # A previous test may have left everything in place, in which case
    # there is nothing to set up and the transports are used as they
    # are
    transports = list_transports(initiator, (host1, host2))

    if all(transports):
        yield host0, host1, host2, initiator, left, right, transports
        return

    # Otherwise the setup starts from a clean state: a device kept from
    # a previous test would already be paired, connected and part of
    # the set, so none of the events waited for below would be
    # reported again
    remove_device(initiator, host1)
    remove_device(initiator, host2)
    remove_device(left, host0)
    remove_device(right, host0)

    initiator.send("scan on\n")
    initiator.expect(
        f"Controller {host0.bdaddr.upper()} Discovering: yes",
        timeout=REPLY_TIMEOUT,
    )

    # Connect only once every member has been found: the set is resolved
    # from the RSI of the members that are already known, so a member
    # found later would not be part of it
    expect_all(
        initiator,
        [
            f"Device {host1.bdaddr.upper()}",
            f"Device {host2.bdaddr.upper()}",
        ],
    )

    # Stop scanning before connecting, so the discovery does not
    # interfere with the connections to the members
    initiator.send("scan off\n")
    initiator.expect(
        f"Controller {host0.bdaddr.upper()} Discovering: no",
        timeout=REPLY_TIMEOUT,
    )

    initiator.send(f"pair {host1.bdaddr.upper()}\n")

    # Finding a member of a set connects the remaining ones, so the
    # other member is neither connected nor paired by the test: it is
    # bonded as reading its services requires an encrypted link, which
    # is what is waited for. Its connection is not, as the link of a
    # previous test may still be up, in which case the device is
    # reported as connected from the start and never changes.
    #
    # The streams are configured by the daemon, so the transports are
    # created without the test configuring the endpoints.
    #
    # The two members report independently, so their events interleave
    # and have to be matched in any order, in a single pass including
    # the pairing: an expect only reports what it matches and discards
    # everything before it, so waiting for one event at a time drops
    # the ones that happen meanwhile, e.g. a transport created while
    # the pairing is still being waited for.
    groups = expect_all(
        initiator,
        [
            "Pairing successful",
            f"DeviceSet /org/bluez/hci0/{SET_PATH}",
            f"Device {host2.bdaddr.upper()} Bonded: yes",
            TRANSPORT.format(dev_addr(host1)),
            TRANSPORT.format(dev_addr(host2)),
        ],
    )

    transports = [m[0].decode("utf-8") for m in groups[-2:]]

    yield host0, host1, host2, initiator, left, right, transports


@set_host_config
def test_bap_unicast_set_transport_created(set_hosts):
    host0, host1, host2, initiator, left, right, transports = set_hosts

    # One transport per member, each taking a single channel
    left.expect(TRANSPORT_RE)
    right.expect(TRANSPORT_RE)


@set_host_config
def test_bap_unicast_set_transport_acquire(set_hosts):
    host0, host1, host2, initiator, left, right, transports = set_hosts

    # The CIS of a CIG are only created once every one of them is
    # active, so the transports of both members have to be acquired
    initiator.send("transport.acquire {} {}\n".format(*transports))

    acquired = r"Acquire successful: fd \d+ MTU \d+:\d+"
    expect_all(
        initiator,
        [acquired, acquired]
        + [f"Transport {transport} State: active" for transport in transports],
    )

# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for the keys under which bluetoothd caches the SDP records of a
BR/EDR device, using VM instances

bluetoothd caches each record of a device under its ServiceRecordHandle.
A record without that attribute (0x0000) has no handle, so bluetoothd
chooses a key for it. These tests check that such a record keeps its key
from one discovery to the next, that no record is cached twice or
overwritten by another, and that no cached record is removed while the
device is known.

The records are of service classes no profile of bluetoothd handles, so
that Device1.Connect discovers the services of a known device again: it
only does so when it finds no service to connect.
"""

import configparser
import glob
import os
import struct

import dbus
import pytest

from pytest_bluezenv import (
    host_config,
    Agent,
    wait_until,
    mainloop_wrap,
    get_dbus,
)

from .test_sdp import (
    L2CAP_UUID,
    PNP_INFO_UUID,
    bluetoothd_state_directory,
    record_attrs,
)
from .test_sdp_out_of_range import (
    BASE_UUID,
    CONNECTING,
    SEARCH1,
    SEARCH2,
    ExperimentalBluetoothdRestart,
    OutOfRangeSdpServer,
    add_handle,
    browse,
    cached_records,
    check_records,
    device_properties,
    find_and_trust,
    find_device,
    read_back,
    record_uuid,
    service_records,
)

pytestmark = [pytest.mark.vm]

PUBLIC_BROWSE_GROUP = 0x1002

# A cached value that is no SDP record
NOT_A_RECORD = "DEADBEEF"

# Records of a response that takes bluetoothd long to handle if it compares
# every record with every other by content
MANY_RECORDS = 10000


def record(n, handle=None, version=None, svclass=None):
    """
    Attribute list of a record of service class svclass, by default
    0x7000 + n, with the given ServiceRecordHandle, and with attribute
    0x0200 set to version to tell versions of a record apart.
    """
    attrs = (
        # ServiceClassIDList
        bytes.fromhex("0900013503")
        + struct.pack(">BH", 0x19, svclass or 0x7000 + n)
        # ProtocolDescriptorList: L2CAP
        + bytes.fromhex("09000435053503190100")
    )

    if version is not None:
        attrs += struct.pack(">BHBH", 0x09, 0x0200, 0x09, version)

    return attrs if handle is None else add_handle(attrs, handle)


def pnp(handle=None):
    """Attribute list of a PnP Information record"""
    attrs = bytes.fromhex(
        "090001350319120009020009010309020109ffff090202090001090203090001"
        "0902042801090205090001"
    )

    return attrs if handle is None else add_handle(attrs, handle)


# Records without ServiceRecordHandle
A, B, C, E = (record(n) for n in (1, 2, 3, 5))
D = pnp()


def answers(l2cap, pnp_records=(D,)):
    """Records host1 returns for the L2CAP and the PnP Information search"""
    return {L2CAP_UUID: list(l2cap), PNP_INFO_UUID: list(pnp_records)}


def all_records(records):
    return [r for rs in records.values() for r in rs]


def uuid_of(attr_list):
    return record_uuid(record_attrs(attr_list))


def cache_value(attr_list):
    """
    A record as bluetoothd writes it to the cache file: in a sequence with
    an 8 bit size if the whole fits in 255 bytes, else a 16 bit one.
    """
    if len(attr_list) + 2 <= 0xFF:
        header = struct.pack(">BB", 0x35, len(attr_list))
    else:
        header = struct.pack(">BH", 0x36, len(attr_list))

    return (header + attr_list).hex().upper()


def seed_cache(address, entries):
    """
    Add entries to [ServiceRecords] of the cache file of a device, as an
    earlier bluetoothd may have left them. Returns the cached records.
    """
    state_dir = bluetoothd_state_directory()
    (adapter_dir,) = glob.glob(os.path.join(state_dir, "??:??:??:??:??:??"))
    path = os.path.join(adapter_dir, "cache", address.upper())
    os.makedirs(os.path.dirname(path), exist_ok=True)

    cache = configparser.ConfigParser(interpolation=None)
    cache.optionxform = str
    cache.read(path)

    if not cache.has_section("ServiceRecords"):
        cache.add_section("ServiceRecords")

    for key, value in entries.items():
        cache["ServiceRecords"][key] = value

    with open(path, "w") as f:
        cache.write(f, space_around_delimiters=False)

    return cached_records(address)


def check_cache(hosts, expected, others=None):
    """
    Check that host0 caches exactly the expected records of host1, each
    once, under a key of the documented format, those with a
    ServiceRecordHandle under it, and besides them exactly the entries of
    others, by key. Returns the key of each record, by record_attrs().
    """
    host0, host1 = hosts
    others = others or {}
    cached = host0.call(cached_records, host1.bdaddr)

    assert {key: value for key, value in cached if key in others} == others

    return check_records([e for e in cached if e[0] not in others], expected)


def check_kept(before, after, records):
    """Check that the given records kept their key"""
    for attrs in map(record_attrs, records):
        assert after[attrs] == before[attrs]


def discover(hosts, records, down_at=None):
    """
    Let bluetoothd on host0 discover the services of host1, which returns
    the given records and goes down at the given point, if any.
    """
    host0, host1 = hosts
    host1.sdp_peer.configure(records, down_at)

    # Its UUID is only added when a discovery of a new device is complete,
    # and for a known device Connect only fails once the discovery is done
    done_uuid = uuid_of(all_records(records)[0])

    return browse(hosts, down_at, done_uuid)


def rediscover(hosts, first, second, down_at=None):
    """
    Let bluetoothd on host0 discover the services of host1 twice: host1
    returns the records first, and then the records second, and goes down
    at the given point of the second discovery, if any. Returns the key
    of each record cached after the first discovery.
    """
    find_and_trust(hosts)

    discover(hosts, first)
    before = check_cache(hosts, all_records(first))

    discover(hosts, second, down_at)
    return before


@mainloop_wrap
def remove_device(address):
    path, _ = find_device(address)
    adapter = dbus.Interface(
        get_dbus().get_object("org.bluez", path.rsplit("/", 1)[0]),
        "org.bluez.Adapter1",
    )
    adapter.RemoveDevice(path)


def remove_and_find_again(hosts):
    """Remove host1 from bluetoothd on host0, and let it find host1 again"""
    host0, host1 = hosts

    host0.call(remove_device, host1.bdaddr)
    wait_until(lambda: host0.call(device_properties, host1.bdaddr) is None)

    find_and_trust(hosts)


def learn_keys(hosts, records):
    """
    Let bluetoothd on host0 discover the given records of host1, and then
    remove host1 so that it is a new device again. Returns the key each
    record got, so that tests do not depend on how bluetoothd chooses the
    keys of records without handle.
    """
    find_and_trust(hosts)
    discover(hosts, records)
    keys = check_cache(hosts, all_records(records))

    remove_and_find_again(hosts)
    return keys


def cached_count(address):
    return len(cached_records(address))


def key_handle(keys, attr_list):
    """The cache key of a record, as a handle value"""
    return int(keys[record_attrs(attr_list)], 16)


def in_memory(hosts):
    """
    Records bluetoothd on host0 has in memory for host1, as sorted
    record_attrs(). host1 connects to host0 for that, which does not make
    host0 discover its services again.
    """
    host0, host1 = hosts
    steps = host1.sdp_peer.get_steps()

    host1.sdp_peer.connect(host0.bdaddr)
    wait_until(lambda: host0.call(device_properties, host1.bdaddr)["Connected"])

    records = host0.call(service_records, host1.bdaddr)
    assert host1.sdp_peer.get_steps() == steps

    return sorted(map(record_attrs, records))


config = host_config([Agent()], [OutOfRangeSdpServer()])

# With Device1.GetServiceRecords
experimental_config = host_config(
    [ExperimentalBluetoothdRestart(), Agent()], [OutOfRangeSdpServer()]
)


#
# Records without ServiceRecordHandle
#


@config
def test_sdp_cache_same_record_twice(hosts):
    """The same record twice in one response is cached once"""
    find_and_trust(hosts)

    discover(hosts, answers([A, A, C]))

    check_cache(hosts, [A, C, D])


@experimental_config
def test_sdp_cache_in_memory_after_discovery(hosts):
    """
    Right after a discovery, bluetoothd has each record of it in memory
    once.
    """
    find_and_trust(hosts)

    discover(hosts, answers([A, B, C]))

    assert in_memory(hosts) == sorted(map(record_attrs, [A, B, C, D]))


@experimental_config
def test_sdp_cache_in_memory_after_rediscovery(hosts):
    """
    Right after a discovery of a known device, bluetoothd has in memory
    each record of that discovery once, while the cache also keeps the
    record host1 stopped returning.
    """
    rediscover(hosts, answers([A, B, C]), answers([A, C]))

    assert in_memory(hosts) == sorted(map(record_attrs, [A, C, D]))
    check_cache(hosts, [A, B, C, D])


@config
def test_sdp_cache_same_records(hosts):
    """The same records discovered again keep their key"""
    before = rediscover(hosts, answers([A, B, C]), answers([A, B, C]))

    after = check_cache(hosts, [A, B, C, D])
    assert after == before


@config
def test_sdp_cache_records_in_other_order(hosts):
    """Records returned in another order keep their key"""
    before = rediscover(hosts, answers([A, B, C]), answers([C, A, B]))

    after = check_cache(hosts, [A, B, C, D])
    assert after == before


@config
def test_sdp_cache_record_in_both_searches_again(hosts):
    """
    A record returned by both searches of a discovery of a known device is
    cached once, and keeps its key.
    """
    _, host1 = hosts
    before = rediscover(hosts, answers([A, B, C]), answers([A, B, C, D]))

    # host1 sent D in its response to both searches
    assert host1.sdp_peer.get_answered() == [[A, B, C, D], [D]]

    after = check_cache(hosts, [A, B, C, D])
    assert after == before


@config
def test_sdp_cache_fewer_records(hosts):
    """
    A record host1 stops returning stays cached, as bluetoothd keeps the
    records with a handle it no longer finds. The others keep their key.
    """
    before = rediscover(hosts, answers([A, B, C]), answers([A, C]))

    after = check_cache(hosts, [A, B, C, D])
    assert after == before


@experimental_config
def test_sdp_cache_changed_record_read_back(hosts):
    """
    After a restart, bluetoothd reads both versions of a changed record
    back, the old one first: it was cached first, and a lookup by UUID
    finds the first record of that UUID.
    """
    C2 = record(3, version=2)
    rediscover(hosts, answers([A, B, C]), answers([A, B, C2]))

    records = read_back(hosts, ordered=True)
    assert sorted(records) == sorted(map(record_attrs, [A, B, C, C2, D]))
    assert records.index(record_attrs(C)) < records.index(record_attrs(C2))


@config
def test_sdp_cache_changed_record_every_discovery(hosts):
    """
    A record that host1 returns changed at every discovery adds a cached
    record each time, as none is removed, and every record cached before
    keeps its key.
    """
    versions = [C] + [record(3, version=v) for v in (2, 3, 4)]

    find_and_trust(hosts)
    discover(hosts, answers([A, B, C]))
    cached = [A, B, C, D]
    before = check_cache(hosts, cached)

    for version in versions[1:]:
        discover(hosts, answers([A, B, version]))
        after = check_cache(hosts, cached + [version])
        check_kept(before, after, cached)

        cached.append(version)
        before = after


@config
@pytest.mark.parametrize("first", [False, True], ids=["added-last", "added-first"])
def test_sdp_cache_added_record(hosts, first):
    """A record host1 returns in addition does not take the key of another"""
    l2cap = [E, A, B, C] if first else [A, B, C, E]
    before = rediscover(hosts, answers([A, B, C]), answers(l2cap))

    after = check_cache(hosts, [A, B, C, D, E])
    check_kept(before, after, [A, B, C, D])


@config
@pytest.mark.parametrize("first", [False, True], ids=["added-last", "added-first"])
def test_sdp_cache_added_record_down_before_second_response(hosts, first):
    """
    host1 returns one more record in its first search, and goes out of
    range before the response to the second: the record of the second
    search that bluetoothd did not get again stays cached.
    """
    l2cap = [E, A, B, C] if first else [A, B, C, E]
    before = rediscover(hosts, answers([A, B, C]), answers(l2cap), SEARCH2)

    after = check_cache(hosts, [A, B, C, D, E])
    check_kept(before, after, [A, B, C, D])


@config
def test_sdp_cache_written_without_fix(hosts):
    """
    bluetoothd without support for records without handle cached one of
    them only, under 0xFFFFFFFF. That record keeps its key and is not
    cached twice.
    """
    host0, host1 = hosts
    find_and_trust(hosts)

    seeded = host0.call(seed_cache, host1.bdaddr, {"0xFFFFFFFF": cache_value(B)})
    assert seeded == [("0xFFFFFFFF", cache_value(B))]

    discover(hosts, answers([A, B, C]))

    keys = check_cache(hosts, [A, B, C, D])
    assert keys[record_attrs(B)] == "0xFFFFFFFF"


@config
@pytest.mark.parametrize(
    "key, value",
    [
        ("0xFFFFFFFF", NOT_A_RECORD),
        ("0xFFFFFFFE", NOT_A_RECORD),
        ("0xFFFFFFFF", ""),
        ("0xFFFFFFFF", "not hex"),
    ],
    ids=["first-key", "second-key", "empty", "not-hex"],
)
def test_sdp_cache_value_no_record(hosts, key, value):
    """
    A cache entry that is no record is left alone by the records without
    handle.
    """
    host0, host1 = hosts
    find_and_trust(hosts)

    seeded = host0.call(seed_cache, host1.bdaddr, {key: value})
    assert seeded == [(key, value)]

    discover(hosts, answers([A, B, C]))

    check_cache(hosts, [A, B, C, D], others={key: value})


@experimental_config
def test_sdp_cache_read_back_after_restart(hosts):
    """
    After a restart, bluetoothd reads each cached record back once, also
    after host1 stopped returning one of them.
    """
    rediscover(hosts, answers([A, B, C]), answers([A, C]))

    assert read_back(hosts) == sorted(map(record_attrs, [A, B, C, D]))


#
# Records with and without ServiceRecordHandle from one device
#


@config
@pytest.mark.parametrize("position", [0, 1, 2], ids=["first", "middle", "last"])
def test_sdp_cache_handle_equal_to_key_same_search(hosts, position):
    """
    A record with a handle equal to the key that bluetoothd gives a record
    without handle of the same search, C: all are cached, the one with a
    handle under it. Coming last, it is found after C got that key.
    """
    keys = learn_keys(hosts, answers([A, C]))

    R = record(4, handle=key_handle(keys, C))
    l2cap = [A, C]
    l2cap.insert(position, R)
    discover(hosts, answers(l2cap))

    check_cache(hosts, [A, R, C, D])


@config
@pytest.mark.parametrize("target", [0, 1], ids=["key-of-first", "key-of-second"])
def test_sdp_cache_handle_equal_to_key_later_search(hosts, target):
    """
    A record with a handle equal to the key a record without handle got in
    the first search comes in the second search.
    """
    keys = learn_keys(hosts, answers([A, C], ()))

    R = pnp(handle=key_handle(keys, [A, C][target]))
    discover(hosts, answers([A, C], [R]))

    check_cache(hosts, [A, C, R])


@config
@pytest.mark.parametrize(
    "target, l2cap, down_at",
    [
        ("C", "ABCR", None),
        ("C", "ABCR", SEARCH2),
        ("D", "ABCR", SEARCH2),
        ("D", "RABC", SEARCH2),
        ("B", "ACR", None),
    ],
    ids=[
        "key-of-c-complete",
        "key-of-c-down",
        "key-of-d-down",
        "key-of-d-first-down",
        "key-of-dropped-b",
    ],
)
def test_sdp_cache_handle_equal_to_key_later_discovery(hosts, target, l2cap, down_at):
    """
    host1 returns a new record R with a handle equal to the key of a cached
    record without handle, which must be moved, not overwritten: C, which
    bluetoothd got again before R; D, which bluetoothd does not get again
    as host1 goes out of range before the response to the second search;
    or B, which host1 no longer returns.
    """
    find_and_trust(hosts)

    discover(hosts, answers([A, B, C]))
    before = check_cache(hosts, [A, B, C, D])

    moved = {"B": B, "C": C, "D": D}[target]
    R = record(4, handle=key_handle(before, moved))
    records = {"A": A, "B": B, "C": C, "R": R}
    discover(hosts, answers([records[r] for r in l2cap]), down_at)

    after = check_cache(hosts, [A, B, C, D, R])
    check_kept(before, after, [r for r in (A, B, C, D) if r != moved])


@config
@pytest.mark.parametrize("down_at", [None, SEARCH2], ids=["dropped", "down"])
def test_sdp_cache_key_equal_to_cached_handle(hosts, down_at):
    """
    A new record without handle does not take the key of a cached record
    with that handle, P: also when host1 no longer returns P, or goes out
    of range before the response to the search that returns it.
    """
    keys = learn_keys(hosts, answers([A, E], ()))

    P = pnp(handle=key_handle(keys, E))
    discover(hosts, answers([A], [P]))
    before = check_cache(hosts, [A, P])

    discover(hosts, answers([A, E], () if down_at is None else [P]), down_at)

    after = check_cache(hosts, [A, E, P])
    check_kept(before, after, [A, P])


@config
def test_sdp_cache_handle_0xffffffff(hosts):
    """
    A record with handle 0xFFFFFFFF, the value bluetoothd gives a record
    without handle, is cached under it like any record with a handle.
    """
    R = record(4, handle=0xFFFFFFFF)
    find_and_trust(hosts)

    discover(hosts, answers([B, R, C]))

    keys = check_cache(hosts, [B, R, C, D])
    assert keys[record_attrs(R)] == "0xFFFFFFFF"


@config
def test_sdp_cache_same_handle_twice(hosts):
    """
    Of two different records with the handle 0xFFFFFFFF, the second is
    dropped as a duplicate of the first, as for any handle.
    """
    handle = 0xFFFFFFFF
    host0, host1 = hosts
    R1 = record(4, handle=handle)
    R2 = record(6, handle=handle)
    find_and_trust(hosts)

    discover(hosts, answers([R1, R2]))

    check_cache(hosts, [R1, D])
    uuids = host0.call(device_properties, host1.bdaddr)["UUIDs"]
    assert uuid_of(R1) in uuids
    assert uuid_of(R2) not in uuids


@config
def test_sdp_cache_same_handle_changed(hosts):
    """
    A record with the handle 0xFFFFFFFF that host1 changes is overwritten
    under it, as for any handle.
    """
    handle = 0xFFFFFFFF
    R1 = record(4, handle=handle)
    R2 = record(4, handle=handle, version=2)

    rediscover(hosts, answers([A, R1]), answers([A, R2]))

    check_cache(hosts, [A, R2, D])


@config
@pytest.mark.parametrize("to_handles", [True, False], ids=["gains", "loses"])
def test_sdp_cache_handles_gained_or_lost(hosts, to_handles):
    """
    host1 returns the same records with a handle each after it returned
    them without, or the other way round. The records of the first
    discovery stay cached under their keys, as records host1 stops
    returning, next to those of the second.
    """
    without = answers([A, C])
    with_handles = answers(
        [record(1, handle=0x00010001), record(3, handle=0x00010003)],
        [pnp(handle=0x00010004)],
    )
    first, second = (without, with_handles) if to_handles else (with_handles, without)

    before = rediscover(hosts, first, second)

    after = check_cache(hosts, all_records(first) + all_records(second))
    check_kept(before, after, all_records(first))


#
# Many records
#


@config
def test_sdp_cache_many_records(hosts):
    """
    bluetoothd does not take longer to handle a response of many records
    without handle than one of as many records with a handle each: it is
    busy for that time, and the device chooses the number of its records.
    """
    host0, host1 = hosts
    times = {}

    find_and_trust(hosts)

    for with_handle in (True, False):
        l2cap = [
            record(1, handle=0x00010000 + v if with_handle else None, version=v)
            for v in range(MANY_RECORDS)
        ]
        discover(hosts, answers(l2cap))

        # All of them are different records
        assert host0.call(cached_count, host1.bdaddr) == MANY_RECORDS + 1

        # From the response to the L2CAP search to the PnP Information search
        times[with_handle] = host1.sdp_peer.get_handling_times()[0]

        if with_handle:
            remove_and_find_again(hosts)

    assert times[False] <= 2 * times[True], times


#
# The Public Browse Group search
#


def discover_public_browse_group(hosts, records):
    """
    Let bluetoothd on host0 discover the services of host1, which returns
    the given records. bluetoothd only searches for the Public Browse Group
    when the L2CAP search returns no record, and only keeps records of the
    service class 0x1002 from it, as for the PnP Information search.
    """
    host0, host1 = hosts
    host1.sdp_peer.configure(records)

    host0.agent.device_method(host1.bdaddr, "Connect")

    done_uuid = BASE_UUID % PUBLIC_BROWSE_GROUP
    wait_until(
        lambda: done_uuid in host0.call(device_properties, host1.bdaddr)["UUIDs"]
    )
    host0.agent.expect("org.bluez.Device1.Connect:error")

    assert host1.sdp_peer.get_steps() == [CONNECTING, SEARCH1, SEARCH2, "search3"]


@config
@pytest.mark.parametrize("with_pnp", [False, True], ids=["alone", "after-pnp"])
def test_sdp_cache_public_browse_group(hosts, with_pnp):
    """
    The records without handle of the Public Browse Group search are cached
    once each, also when the PnP Information search returned a record:
    bluetoothd handles the records of its last search twice.
    """
    X = record(6, svclass=PUBLIC_BROWSE_GROUP)
    Y = record(7, svclass=PUBLIC_BROWSE_GROUP, version=2)
    records = {PUBLIC_BROWSE_GROUP: [X, Y]}
    if with_pnp:
        records[PNP_INFO_UUID] = [D]

    find_and_trust(hosts)
    discover_public_browse_group(hosts, records)

    check_cache(hosts, [X, Y] + ([D] if with_pnp else []))

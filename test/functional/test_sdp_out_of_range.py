# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for what bluetoothd keeps of a BR/EDR device that goes out of range
while its services are being discovered over SDP, using VM instances

bluetoothd on host0 browses host1 with a Service Search Attribute request
for the L2CAP UUID and then one for the PnP Information UUID, both on the
same L2CAP channel. It gets the records of a search when the response is
complete, caches them right away, and adds the UUIDs of all of them to
the device once the last search is done. host1 can go down at one of:

  ``connecting``          while the SDP channel is being set up, before any
                          request. This is the only point at which
                          bluetoothd gets the error of the link itself,
                          and so the only one where it matters whether
                          host1 got out of range or was powered off: it
                          tries again in the latter case.
  ``search1``             after the first request, before any response.
  ``search1-continued``   after the first part of the first response, when
                          the rest of it is requested.
  ``search2``             after the first response, when the second
                          request is received.
  ``search2-continued``   after the first part of the second response.
  ``done``                after the last response, for reference.

"""

import configparser
import glob
import os
import socket
import struct
import subprocess
import threading
import time

import dbus
import pytest

from pytest_bluezenv import (
    host_config,
    Agent,
    Bluetoothd,
    HostPlugin,
    find_exe,
    run,
    wait_until,
    mainloop_wrap,
    get_dbus,
)

from .test_sdp import (
    SDP_PSM,
    SDP_SVC_SEARCH_ATTR_REQ,
    SDP_SVC_SEARCH_ATTR_RSP,
    SDP_DE_SEQ,
    SDP_DE_UUID,
    L2CAP_UUID,
    PNP_INFO_UUID,
    SWITCH2_RECORDS,
    KEY,
    bluetoothd_state_directory,
    de_span,
    record_attrs,
    split_records,
)

pytestmark = [pytest.mark.vm]

SOL_L2CAP = 6
L2CAP_CONNINFO = 0x02
SOL_BLUETOOTH = 274
BT_DEFER_SETUP = 7

HCI_COMMAND_PKT = 0x01
HCI_OP_DISCONNECT = 0x0406
HCI_ERROR_CONNECTION_TIMEOUT = 0x08

SDP_ATTR_RECORD_HANDLE = 0x0000

# Attribute list bytes host1 sends per response, so that a response fits
# in the default L2CAP MTU of 672
MAX_RSP_SIZE = 600
SDP_ATTR_SVCLASS_ID_LIST = 0x0001

BASE_UUID = "0000%04x-0000-1000-8000-00805f9b34fb"

CONNECTING = "connecting"
SEARCH1 = "search1"
SEARCH1_CONTINUED = "search1-continued"
SEARCH2 = "search2"
SEARCH2_CONTINUED = "search2-continued"
DONE = "done"

ERR_CREATE_SOCKET = "br-connection-create-socket"


def record_uuid(attrs):
    """
    First service class UUID of the record_attrs() of a record, which is
    the one bluetoothd adds to the UUIDs of a device.
    """
    dtype, items = dict(attrs)[SDP_ATTR_SVCLASS_ID_LIST]
    assert dtype == SDP_DE_SEQ and items[0][0] == SDP_DE_UUID
    return BASE_UUID % int.from_bytes(items[0][1], "big")


def join_records(records):
    attr_lists = b"".join(struct.pack(">BH", 0x36, len(r)) + r for r in records)

    if len(attr_lists) > 0xFFFF:
        return struct.pack(">BI", 0x37, len(attr_lists)) + attr_lists

    return struct.pack(">BH", 0x36, len(attr_lists)) + attr_lists


def add_handle(record, handle):
    return struct.pack(">BHBI", 0x09, SDP_ATTR_RECORD_HANDLE, 0x0A, handle) + record


def switch2_records():
    """
    Records host1 returns for each search of bluetoothd, as attribute
    lists: those of a Nintendo Switch 2, which have no ServiceRecordHandle.
    """
    return {
        uuid: split_records(SWITCH2_RECORDS[uuid])
        for uuid in (L2CAP_UUID, PNP_INFO_UUID)
    }


def search_request(params):
    """UUID16 values searched for by a request, and its continuation state"""
    _, start, end = de_span(params, 0)
    uuids = {
        struct.unpack(">H", params[i + 1 : i + 3])[0]
        for i in range(start, end - 2, 3)
        if params[i] == 0x19
    }

    # MaximumAttributeByteCount, AttributeIDList
    _, _, end = de_span(params, end + 2)

    return uuids, params[end + 1 : end + 1 + params[end]]


def search_attr_rsp(tid, attr_lists, cstate=b""):
    params = (
        struct.pack(">H", len(attr_lists)) + attr_lists + bytes([len(cstate)]) + cstate
    )
    return struct.pack(">BHH", SDP_SVC_SEARCH_ATTR_RSP, tid, len(params)) + params


class OutOfRangeSdpServer(HostPlugin):
    """
    SDP server without bluetoothd, whose host can go out of range at a
    given point of the service discovery of its peer.

    Out of range means that the peer stops hearing from this host, so
    that its controller reports the link as lost with Connection Timeout
    once the link supervision timeout expires, and that it can not be
    paged any more. btvirt has no link supervision timeout, so the
    Disconnection Complete event of the peer is produced right away
    instead, by disconnecting with that reason from here: btvirt passes
    the reason of a HCI Disconnect command on to the peer as it is.

    With power_off=True the host is powered off instead. The peer then
    sees Remote Device Terminated Connection due to Power Off, for which
    L2CAP reports ECONNRESET rather than ETIMEDOUT.
    """

    name = "sdp_peer"

    def presetup(self, config):
        try:
            self.btmgmt = find_exe("tools", "btmgmt")
        except FileNotFoundError as exc:
            pytest.skip(reason=f"btmgmt: {exc!r}")

    def setup(self, impl):
        self.records = {}
        self.down_at = None
        self.power_off = False
        self.is_down = threading.Event()
        self.conn = None
        self.out = None
        self.steps = []
        self.answered = []
        self.answered_at = None
        self.handling_times = []
        self.lock = threading.Lock()

        # Without the UUIDs an earlier bluetoothd may have left in the
        # extended inquiry response of this host, which the peer shows
        # for a device until its services are discovered
        for cmd in (
            ("clr-uuids",),
            ("connectable", "on"),
            ("power", "on"),
            ("discov", "yes"),
        ):
            self.mgmt(*cmd)

        self.sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP
        )
        self.sock.bind((socket.BDADDR_ANY, SDP_PSM))
        self.sock.listen(1)
        threading.Thread(target=self.serve, daemon=True).start()

    def mgmt(self, *cmd):
        run(
            [self.btmgmt, "--index", "0", *cmd],
            check=True,
            stdin=subprocess.DEVNULL,
        )

    def configure(self, records, down_at=None, power_off=False):
        """
        Set the records to return for each search, and the point of the
        next service discovery to go down at. With DONE this is left to
        go_down(). Starts get_steps(), get_answered() and
        get_handling_times() over.
        """
        self.records = records
        self.down_at = down_at
        self.power_off = power_off

        with self.lock:
            self.steps = []
            self.answered = []
            self.answered_at = None
            self.handling_times = []

        # Leave the L2CAP Connection Request of the peer pending
        self.sock.setsockopt(SOL_BLUETOOTH, BT_DEFER_SETUP, down_at == CONNECTING)

    def step(self, name):
        with self.lock:
            self.steps.append(name)

    def get_steps(self):
        """Points reached so far, and "down" once gone down"""
        with self.lock:
            return list(self.steps)

    def sent(self, records):
        with self.lock:
            self.answered.append(list(records))
            self.answered_at = time.monotonic()

    def searched(self):
        """Note how long the peer took from the last response to a request"""
        with self.lock:
            if self.answered_at is not None:
                self.handling_times.append(time.monotonic() - self.answered_at)
                self.answered_at = None

    def get_handling_times(self):
        """
        Seconds the peer took from each response sent in full to its next
        search, which is the time it took to handle the records of it
        """
        with self.lock:
            return list(self.handling_times)

    def get_answered(self):
        """Records of each response sent in full, as attribute lists"""
        with self.lock:
            return list(self.answered)

    def get_down(self):
        return self.is_down.is_set()

    def go_down(self):
        """Go out of range, or power off"""
        with self.lock:
            conn = self.conn

        if self.power_off:
            self.mgmt("power", "off")
        else:
            # Stop page scan first, so that there is no moment in which
            # the link is lost but the peer could connect again
            self.mgmt("connectable", "off")

            try:
                handle = struct.unpack(
                    "<H3s", conn.getsockopt(SOL_L2CAP, L2CAP_CONNINFO, 5)
                )[0]
            except (AttributeError, OSError):
                # No link left to lose
                handle = None

            if handle is not None:
                with socket.socket(
                    socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI
                ) as hci:
                    hci.bind((0,))
                    hci.send(
                        struct.pack(
                            "<BHBHB",
                            HCI_COMMAND_PKT,
                            HCI_OP_DISCONNECT,
                            3,
                            handle,
                            HCI_ERROR_CONNECTION_TIMEOUT,
                        )
                    )

            self.mgmt("power", "off")

        self.step("down")
        self.is_down.set()

    def at(self, point):
        """Note that a point was reached, go down if it is the one set"""
        self.step(point)

        if self.down_at != point:
            return False

        self.go_down()
        return True

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return

            with self.lock:
                self.conn = conn

            try:
                self.answer(conn)
            except Exception as exc:
                self.step(f"error: {exc!r}")

            # The connection is left open; closing it would tell the peer

    def answer(self, conn):
        search = 0
        rest = b""
        pending = []

        if self.at(CONNECTING):
            return

        while True:
            try:
                pdu = conn.recv(1024)
            except OSError:
                return

            if not pdu:
                return

            if len(pdu) < 6 or pdu[0] != SDP_SVC_SEARCH_ATTR_REQ:
                continue

            tid = struct.unpack(">H", pdu[1:3])[0]
            uuids, cstate = search_request(pdu[5:])

            if cstate:
                point = f"search{search}-continued"
                if self.down_at == point and self.at(point):
                    return

                part, rest = rest[:MAX_RSP_SIZE], rest[MAX_RSP_SIZE:]
                conn.send(search_attr_rsp(tid, part, b"\x01" if rest else b""))
                if not rest:
                    self.sent(pending)
                continue

            self.searched()

            search += 1
            if self.at(f"search{search}"):
                return

            records = []
            attr_lists = b"\x35\x00"
            for uuid in uuids:
                if uuid in self.records:
                    records = self.records[uuid]
                    attr_lists = join_records(records)

            if self.down_at == f"search{search}-continued":
                # Return the first half only, and ask to be asked for more
                half = len(attr_lists) // 2
                rest = attr_lists[half:]
                pending = records
                conn.send(search_attr_rsp(tid, attr_lists[:half], b"\x01"))
            else:
                # In parts, if it does not fit in one response
                part, rest = attr_lists[:MAX_RSP_SIZE], attr_lists[MAX_RSP_SIZE:]
                pending = records
                conn.send(search_attr_rsp(tid, part, b"\x01" if rest else b""))
                if not rest:
                    self.sent(records)

    def come_back(self):
        """
        Come back in range, or power on again, without going down at any
        point of a service discovery. Starts get_steps() over.
        """
        self.configure(self.records)
        self.mgmt("power", "on")
        self.mgmt("connectable", "on")

    def connect(self, address):
        """Bring up an ACL link by connecting to the SDP server of a peer"""
        self.out = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP
        )
        self.out.connect((address, SDP_PSM))

    def teardown(self):
        self.sock.close()

        if self.out is not None:
            self.out.close()

        with self.lock:
            if self.conn is not None:
                self.conn.close()


class BluetoothdRestart(HostPlugin):
    """
    Restarts the bluetoothd of the Bluetoothd host plugin, which keeps
    its state directory.
    """

    name = "bluetoothd_restart"
    depends = [Bluetoothd()]

    def setup(self, impl):
        self.impl = impl

    @mainloop_wrap
    def restart(self):
        bluetoothd = self.impl.plugins["bluetoothd"]
        agent = self.impl.plugins.get("agent")
        bus = get_dbus()

        old = bluetoothd.job
        old.terminate()
        old.wait()

        bus_daemon = dbus.Interface(
            bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus"),
            "org.freedesktop.DBus",
        )
        wait_until(lambda: not bus_daemon.NameHasOwner("org.bluez"))

        state_dir = os.path.join(bluetoothd.tmpdir.name, "state")
        bluetoothd.job = subprocess.Popen(
            old.args,
            env=dict(os.environ, STATE_DIRECTORY=state_dir),
            stdin=subprocess.DEVNULL,
            stdout=bluetoothd.log_stream.stream,
            stderr=subprocess.STDOUT,
        )

        def powered():
            try:
                adapter = dbus.Interface(
                    bus.get_object("org.bluez", "/org/bluez/hci0"),
                    "org.freedesktop.DBus.Properties",
                )
                return bool(adapter.Get("org.bluez.Adapter1", "Powered"))
            except dbus.DBusException:
                return False

        wait_until(powered)

        if agent is not None:
            # Expected to be registered when the Agent plugin is unloaded
            agent.manager = dbus.Interface(
                agent.bus.get_object("org.bluez", "/org/bluez"),
                "org.bluez.AgentManager1",
            )
            agent.manager.RegisterAgent(agent.path, agent.capability)


class ExperimentalBluetoothdRestart(BluetoothdRestart):
    """
    BluetoothdRestart for a bluetoothd with experimental interfaces, for
    Device1.GetServiceRecords. Has to come before Agent, so that Agent
    does not add a Bluetoothd of its own.
    """

    depends = [Bluetoothd(conf="[General]\nExperimental = true\n")]


def find_device(address):
    """Path and properties of the device object of bluetoothd, if any"""
    bus = get_dbus()
    manager = dbus.Interface(
        bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager"
    )

    for path, ifaces in manager.GetManagedObjects().items():
        device = ifaces.get("org.bluez.Device1")
        if device is not None and device["Address"].lower() == address.lower():
            return path, device

    return None, None


@mainloop_wrap
def device_properties(address):
    """Properties of the device object of bluetoothd, None without one"""
    _, device = find_device(address)
    if device is None:
        return None

    return {
        "UUIDs": sorted(str(uuid) for uuid in device.get("UUIDs", [])),
        "Connected": bool(device["Connected"]),
    }


@mainloop_wrap
def service_records(address):
    """Records bluetoothd returns from Device1.GetServiceRecords"""
    path, _ = find_device(address)
    device = dbus.Interface(
        get_dbus().get_object("org.bluez", path), "org.bluez.Device1"
    )

    return [bytes(r) for r in device.GetServiceRecords()]


def read_back(hosts, ordered=False):
    """
    Restart bluetoothd on host0 and return the records it then reads back
    from its cache for host1, as sorted record_attrs(), or with ordered in
    the order bluetoothd has them, which is the order of the cache file.
    host1 comes back and connects to host0 for that, which does not make
    host0 discover its services again.
    """
    host0, host1 = hosts

    host0.bluetoothd_restart.restart()
    wait_until(lambda: host0.call(device_properties, host1.bdaddr) is not None)

    host1.sdp_peer.come_back()
    host1.sdp_peer.connect(host0.bdaddr)
    wait_until(lambda: host0.call(device_properties, host1.bdaddr)["Connected"])

    records = host0.call(service_records, host1.bdaddr)
    assert host1.sdp_peer.get_steps() == []

    records = list(map(record_attrs, records))
    return records if ordered else sorted(records)


@mainloop_wrap
def trust_device(address):
    path, _ = find_device(address)
    props = dbus.Interface(
        get_dbus().get_object("org.bluez", path), "org.freedesktop.DBus.Properties"
    )
    props.Set("org.bluez.Device1", "Trusted", dbus.Boolean(True))


def cached_records(address):
    """
    Service records in the cache file bluetoothd keeps for a device, as
    list of (key, record). Empty if there is no cache file.
    """
    state_dir = bluetoothd_state_directory()
    paths = glob.glob(os.path.join(state_dir, "*", "cache", address.upper()))
    assert len(paths) <= 1, paths

    cache = configparser.ConfigParser(interpolation=None)
    cache.optionxform = str
    cache.read(paths)

    if not cache.has_section("ServiceRecords"):
        return []

    return list(cache["ServiceRecords"].items())


def find_and_trust(hosts):
    """Let bluetoothd on host0 find host1, and keep it"""
    host0, host1 = hosts

    host0.agent.adapter_method("StartDiscovery")
    host0.agent.expect("org.bluez.Adapter1.StartDiscovery:reply")

    wait_until(host0.agent.has_device, host1.bdaddr)

    host0.agent.adapter_method("StopDiscovery")
    host0.agent.expect("org.bluez.Adapter1.StopDiscovery:reply")

    # bluetoothd only keeps a device that is paired or trusted once its
    # link is lost: any other is made temporary again, and is removed
    # together with its cached records when its timer expires or when it
    # can not be paged.
    host0.call(trust_device, host1.bdaddr)

    before = host0.call(device_properties, host1.bdaddr)
    assert before["UUIDs"] == []
    assert host0.call(cached_records, host1.bdaddr) == []


def browse(hosts, down_at=None, done_uuid=None):
    """
    Let bluetoothd on host0 discover the services of host1. host1 goes
    down at the given point, with DONE once host0 has the done_uuid that
    only a complete discovery adds. Returns the error of Connect.
    """
    host0, host1 = hosts

    # Connecting browses the SDP records of host1
    host0.agent.device_method(host1.bdaddr, "Connect")

    if down_at in (None, DONE):
        # All UUIDs of a browse are added at once, when it is complete
        wait_until(
            lambda: done_uuid in host0.call(device_properties, host1.bdaddr)["UUIDs"]
        )

    if down_at == DONE:
        host1.sdp_peer.go_down()

    # host1 offers no service to connect, so Connect fails in any case
    error = host0.agent.expect("org.bluez.Device1.Connect:error").error

    if down_at is None:
        assert host1.sdp_peer.get_steps() == [CONNECTING, SEARCH1, SEARCH2]

        host0.agent.device_method(host1.bdaddr, "Disconnect")
        host0.agent.expect(
            (
                "org.bluez.Device1.Disconnect:reply",
                "org.bluez.Device1.Disconnect:error",
            )
        )
    else:
        wait_until(host1.sdp_peer.get_down)

    wait_until(lambda: not host0.call(device_properties, host1.bdaddr)["Connected"])

    if down_at is None:
        pass
    elif down_at == DONE:
        assert host1.sdp_peer.get_steps() == [CONNECTING, SEARCH1, SEARCH2, "down"]
    else:
        # host1 went down where it was supposed to, and was not reached again
        points = [CONNECTING, SEARCH1, SEARCH1_CONTINUED, SEARCH2, SEARCH2_CONTINUED]
        expected = [
            p
            for p in points[: points.index(down_at) + 1]
            if not p.endswith("-continued") or p == down_at
        ]
        assert host1.sdp_peer.get_steps() == expected + ["down"]

    return error.get_dbus_message()


def first_uuid(records):
    return record_uuid(record_attrs(records[L2CAP_UUID][0]))


def check_records(cached, records):
    """
    Check that the cache holds exactly the given records, each of them
    once, under a key of the documented format, and a record with a
    ServiceRecordHandle under it. Returns the key of each record, by
    record_attrs().
    """
    keys = {}
    for key, value in cached:
        assert KEY.fullmatch(key), key

        attrs = record_attrs(bytes.fromhex(value))
        assert attrs not in keys, f"{keys[attrs]} and {key} hold the same record"
        keys[attrs] = key

    assert sorted(keys) == sorted(record_attrs(r) for r in records)

    for attrs, key in keys.items():
        handle = dict(attrs).get(SDP_ATTR_RECORD_HANDLE)
        if handle is not None:
            assert key == "0x%08X" % int.from_bytes(handle[1], "big")

    return keys


#
# A device bluetoothd sees for the first time
#


@host_config([Agent()], [OutOfRangeSdpServer()])
def test_sdp_new_without_handle_down_before_second_response(hosts):
    """
    host1 goes down after bluetoothd has the response to its first search
    but not the one to its second: it caches the records of the first
    search, but adds no UUID as the discovery did not complete.
    """
    host0, host1 = hosts
    records = switch2_records()

    host1.sdp_peer.configure(records, SEARCH2)

    find_and_trust(hosts)
    message = browse(hosts, SEARCH2, first_uuid(records))

    props = host0.call(device_properties, host1.bdaddr)
    assert props is not None

    assert message == ERR_CREATE_SOCKET
    assert props["UUIDs"] == []
    check_records(host0.call(cached_records, host1.bdaddr), records[L2CAP_UUID])

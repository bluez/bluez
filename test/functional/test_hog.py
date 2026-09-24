# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for HID over GATT (HoG) using bluetoothctl in VM instances

The HID device (host1) registers a HID Service (HIDS) with bluetoothctl,
using client/scripts/hog-device.bt or client/scripts/hog-device-sci.bt,
and the HID host (host0) pairs with it and checks the service over GATT.
"""

import warnings

import pytest

from pytest_bluezenv import Bluetoothd, Pexpect, find_exe, host_config
from pytest_bluezenv.utils import bluez_src_dir

pytestmark = [pytest.mark.vm]

# The HID Service is claimed by the input plugin of the HID host, so it
# has to be exported read-write for bluetoothctl to write HID SCI Mode
HOG_CONF = """[General]
ControllerMode = le

[GATT]
ExportClaimedServices = read-write
"""

HIDS_UUID = "00001812-0000-1000-8000-00805f9b34fb"

# Local attributes registered by client/scripts/hog-device*.bt
LOCAL_REPORT = "/org/bluez/app/service0/chrc2"
LOCAL_SCI_MODE = "/org/bluez/app/service0/chrc5"

# Keyboard Input Reports: Modifiers, Reserved, then 6 Key Codes
REPORTS = [
    "00 00 04 00 00 00 00 00",  # a pressed
    "02 00 05 00 00 00 00 00",  # Left Shift + b pressed
    "00 00 00 00 00 00 00 00",  # released
]

# HID SCI Mode: Fast Mode
SCI_FAST_MODE = "03"

# LE Connection Rate parameters requested with mgmt.conn-subrate once in
# SCI Fast Mode: interval 1 ms to 2 ms (units of 0.125 ms), within the
# range given in HID SCI Information, no subrating, no latency and 5 s
# supervision timeout (units of 10 ms)
SCI_RATE = ["0x0008", "0x0010", "1", "1", "0", "0", "0x01f4"]

# Reported when an operation cannot complete, so a test does not have to
# wait for its timeout to know it is not going to
FAILURES = [
    r"(Failed to \w+[^\r\n]*)",
    r"(Device \S+ not available)",
    r"(No device connected)",
    r"(No attribute selected)",
]

# What a command reports is printed as it runs, unlike what the peers
# report over the air, so waiting the default timeout for it only makes
# a failure slower
REPLY_TIMEOUT = 5


def script(name):
    src = bluez_src_dir()
    if src is None:
        pytest.skip("BlueZ source directory not known")

    path = src / "client" / "scripts" / name
    if not path.exists():
        pytest.skip(f"{path} not found")

    return str(path)


def spawn_bluetoothctl(host, init_script=None):
    exe = find_exe("client", "bluetoothctl")
    # Accept pairing and authorize services without prompting, with a
    # capability pairing Just Works, as there is no one to answer the
    # entry of a passkey
    args = [exe, "-a", "auto:NoInputNoOutput"]
    if init_script:
        args += ["--init-script", script(init_script)]
    return host.pexpect.spawn(args)


def expect(ctl, patterns, **kwargs):
    """
    Expect one of the patterns, failing as soon as one of the failures
    shows up. Return the index of the pattern matched and its groups.
    """
    if isinstance(patterns, str):
        patterns = [patterns]

    idx, m = ctl.expect(FAILURES + list(patterns), **kwargs)
    if idx < len(FAILURES):
        raise AssertionError(m[0].decode("utf-8") if m else "failed")

    return idx - len(FAILURES), m


def expect_all(ctl, patterns, **kwargs):
    """Expect all the given patterns, in any order."""
    pending = list(patterns)

    while pending:
        idx, _ = expect(ctl, pending, **kwargs)
        pending.pop(idx)


def pair_le(host0, ctl0, host1, ctl1):
    ctl0.send("scan on\n")
    expect(ctl0, f"Controller {host0.bdaddr.upper()} Discovering: yes")

    ctl1.send("advertise on\n")
    expect(ctl1, "Advertising object registered")

    expect(ctl0, f"Device {host1.bdaddr.upper()}")
    ctl0.send(f"pair {host1.bdaddr.upper()}\n")

    # See test_bluetoothctl_pair_le: passkey confirmation is handled by
    # the auto agent, but legacy passkey entry still needs an answer
    legacy = r"\[agent\].*Passkey:.*m(\d+)"
    pending = [
        r"Pairing successful",
        f"Device {host1.bdaddr.upper()} ServicesResolved: yes",
    ]

    while pending:
        idx, m = expect(ctl0, [legacy] + pending)
        if idx == 0:
            warnings.warn(
                "BUG: we got passkey authentication, bluetoothd/kernel "
                "should be fixed"
            )
            ctl1.expect(r"\[agent\] Enter passkey \(number in 0-999999\):")
            ctl1.send(f"{m[0].decode('utf-8')}\n")
            continue
        pending.pop(idx - 1)

    ctl0.send("scan off\n")


def read_attribute(ctl, uuid):
    """Read the given remote attribute, returning its value as hex string."""
    ctl.send(f"gatt.select-attribute {uuid}\n")
    ctl.send("gatt.read\n")
    expect(ctl, r"Attempting to read \S+", timeout=REPLY_TIMEOUT)
    return expect_hexdump(ctl)


def hexbytes(value):
    """Turn a hex string into the format taken by gatt.write."""
    return " ".join(f"0x{byte}" for byte in value.split())


def expect_hexdump(ctl, **kwargs):
    """Expect a value printed by bluetoothctl, returning it as hex string."""
    _, m = expect(ctl, r"((?: [0-9a-f]{2})+)  ", **kwargs)
    return m[0].decode("utf-8").strip()


def expect_notification(ctl):
    """Expect a notification of the remote attribute, returning its value."""
    expect(ctl, rf"CHG.*? Attribute /\S+ Value:")
    return expect_hexdump(ctl)


def enable_notifications(ctl, device, uuid, local):
    """Enable notifications of the given attribute, on the HID host."""
    ctl.send(f"gatt.select-attribute {uuid}\n")
    ctl.send("gatt.notify on\n")
    expect(ctl, r"Notify started", timeout=REPLY_TIMEOUT)
    # Either subscribed with StartNotify, or with AcquireNotify as done by
    # the input plugin of the HID host for the Input Reports
    expect(
        device,
        rf"Attribute {local} (\S+ )?(notifications enabled|Notify sock acquired)",
    )


def notify(device, local, value):
    """Notify the given value of a local attribute, on the HID device."""
    device.send(f"gatt.select-attribute local {local}\n")
    device.send(f'gatt.write "{hexbytes(value)}"\n')
    expect(device, rf"Attribute {local} .*written", timeout=REPLY_TIMEOUT)


@host_config(
    [Bluetoothd(conf=HOG_CONF), Pexpect()],
    [Bluetoothd(conf=HOG_CONF), Pexpect()],
)
@pytest.mark.parametrize(
    "init_script, flags, sci",
    [
        ("hog-device.bt", "02", None),
        ("hog-device-sci.bt", "06", ("00", "08 01 08 00 50 00 08 00")),
    ],
    ids=["no-sci", "sci"],
)
def test_hog(hosts, init_script, flags, sci):
    host0, host1 = hosts

    device = spawn_bluetoothctl(host1, init_script)
    expect(device, "Application registered")

    ctl = spawn_bluetoothctl(host0)
    pair_le(host0, ctl, host1, device)

    ctl.send(f"info {host1.bdaddr.upper()}\n")
    expect(ctl, rf"Human Interface Device\s+\({HIDS_UUID}\)", timeout=REPLY_TIMEOUT)

    # HID Information: bcdHID 1.11, bCountryCode 0x00 and Flags
    assert read_attribute(ctl, "2a4a") == f"11 01 00 {flags}"

    # Input Reports: the HID device notifies a few key presses
    enable_notifications(ctl, device, "2a4d", LOCAL_REPORT)

    for report in REPORTS:
        notify(device, LOCAL_REPORT, report)
        assert expect_notification(ctl) == report

    if sci is None:
        return

    mode, info = sci
    assert read_attribute(ctl, "2c39") == mode
    assert read_attribute(ctl, "2c3a") == info

    # SCI mode change: the HID host writes the new mode to the HID device
    enable_notifications(ctl, device, "2c39", LOCAL_SCI_MODE)

    ctl.send(f'gatt.write "{hexbytes(SCI_FAST_MODE)}"\n')
    expect(device, rf"\[{LOCAL_SCI_MODE} .*\] WriteValue:")
    assert expect_hexdump(device) == SCI_FAST_MODE

    # The HID host, as central, changes the connection rate accordingly
    ctl.send(f"mgmt.conn-subrate {host1.bdaddr} {' '.join(SCI_RATE)}\n")
    # The connection rate may change before the command completes, so the
    # event may be printed before the reply
    rate = rf"{{}} type .* connection subrate interval {SCI_RATE[0]}"
    expect_all(
        ctl,
        [r"Connection Subrate loaded successfully", rate.format(host1.bdaddr.upper())],
    )
    expect(device, rate.format(host0.bdaddr.upper()))

    # Then the HID device confirms the mode has been changed
    notify(device, LOCAL_SCI_MODE, SCI_FAST_MODE)
    assert expect_notification(ctl) == SCI_FAST_MODE

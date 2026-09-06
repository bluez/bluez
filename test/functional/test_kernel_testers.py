# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for the test suite itself
"""

import re
import sys
import subprocess
import warnings
from pathlib import Path

import pytest

from pytest_bluezenv import find_exe, host_config, run
from pytest_bluezenv.utils import DEFAULT_TIMEOUT

# Testers that can reuse the VM instance
TESTERS = [
    "mgmt-tester",
    "smp-tester",
    "l2cap-tester",
    "rfcomm-tester",
    "sco-tester",
    "iso-tester",
    "mesh-tester",
    "ioctl-tester",
    "bnep-tester",
    "userchan-tester",
    "6lowpan-tester",
]

XFAIL = {
    "mesh-tester": {
        # Always fail:
        "Mesh - Send cancel - 1",
        "Mesh - Send cancel - 2",
    },
    "mgmt-tester": {
        # Always fail:
        "Read Exp Feature - Success",
        # Flaky, randomly fail:
        "LL Privacy - Add Device 1 (Add to AL)",
        "LL Privacy - Add Device 2 (2 Devices to AL)",
        "LL Privacy - Add Device 3 (AL is full)",
        "LL Privacy - Set Device Flag 1 (Device Privacy)",
        "LL Privacy - Set Flags 1 (Add to RL)",
        "LL Privacy - Set Flags 2 (Enable RL)",
        "LL Privacy - Set Flags 3 (2 Devices to RL)",
        "LL Privacy - Set Flags 4 (RL is full)",
        "LL Privacy - Set Flags 5 (Multi Adv)",
        "LL Privacy - Set Flags 6 (Multi Dev and Multi Adv)",
        "LL Privacy - Start Discovery 2 (Disable RL)",
    },
}

host_setup = host_config([], controller=False, reuse=True)


def run_tester(hosts, tester):
    (host,) = hosts
    xfails = set(XFAIL.get(tester, ()))

    tester = find_exe("tools", tester)
    res = host.call(
        run,
        [tester],
        stdout=subprocess.PIPE,
        timeout=2 * DEFAULT_TIMEOUT + 60,
        encoding="utf-8",
        errors="surrogateescape",
    )

    passed, failed, not_run = _parse_tester_output(res.stdout)
    xfailed = []

    for name in list(failed):
        if name in xfails:
            failed.remove(name)
            xfailed.append(name)
            xfails.remove(name)

    assert failed == [], failed

    if xfails:
        warnings.warn("XPASS: " + ", ".join(xfails))

    if xfailed:
        pytest.xfail(reason=", ".join(xfailed))


@pytest.mark.tester
@pytest.mark.parametrize("tester", TESTERS)
@host_setup
def test_kernel_tester(hosts, tester):
    run_tester(hosts, tester)


@host_setup
def test_kernel_selftest(hosts):
    (host,) = hosts

    tester = find_exe("tools", "check-selftest")
    res = host.call(
        run,
        [tester],
        stdout=subprocess.PIPE,
        timeout=2 * DEFAULT_TIMEOUT + 60,
        encoding="utf-8",
        errors="surrogateescape",
    )
    assert res.returncode == 0

    if not res.stdout.strip():
        pytest.skip("CONFIG_BT_SELFTEST not enabled")

    assert "PASS" in res.stdout, res.stdout
    assert "FAIL" not in res.stdout, res.stdout


def _parse_tester_output(output):
    total_count = 0
    passed_count = 0
    failed_count = 0
    not_run_count = 0

    passed = []
    failed = []
    not_run = []

    in_summary = False
    for line in output.splitlines():
        line = line.strip()

        if "Test Summary" in line:
            in_summary = True
            continue
        if not in_summary:
            continue
        if "----" in line or "Overall execution time" in line or not line:
            continue

        m = re.search(
            r"Total: (\d+).*Passed: (\d+).*Failed: (\d+).*Not Run: (\d+)", line
        )
        if m:
            total_count += int(m.group(1))
            passed_count += int(m.group(2))
            failed_count += int(m.group(3))
            not_run_count += int(m.group(4))
            continue

        m = re.match(r"^([\x20-\xff]+)\s+.*(Passed|Failed|Not Run|Timed out)", line)
        assert m, line

        name = m.group(1).strip()
        verdict = m.group(2).strip().lower()

        if verdict == "passed":
            passed.append(name)
        elif verdict in ("failed", "timed out"):
            failed.append(name)
        elif verdict == "not run":
            not_run.append(name)
        else:
            raise ValueError("Unknown {verdict=!r}")

    # Check we parsed everything
    if len(passed) != passed_count:
        raise ValueError(f"Invalid {passed_count=}, {passed=}")
    if len(failed) != failed_count:
        raise ValueError(f"Invalid {failed_count=}, {failed=}")
    if len(not_run) != not_run_count:
        raise ValueError(f"Invalid {not_run_count=}, {not_run=}")
    if total_count == 0:
        raise RuntimeError(f"No tests ran")

    return passed, failed, not_run

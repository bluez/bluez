# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for btmgmt using VM instances
"""
import sys
import pytest
import subprocess
import tempfile

from pytest_bluez import host_config, find_exe, run

pytestmark = [pytest.mark.vm]

btmgmt = find_exe("tools", "btmgmt")


@host_config([])
def test_btmgmt_info(hosts):
    (host,) = hosts

    result = host.call(
        run,
        [btmgmt, "--index", "0", "info"],
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        encoding="utf-8",
    )
    assert result.returncode == 0
    assert f"addr {host.bdaddr.upper()}" in result.stdout

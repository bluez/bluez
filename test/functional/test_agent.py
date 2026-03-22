# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for bluetoothctl using VM instances
"""
import sys
import re
import pytest
import subprocess
import tempfile

import time
import logging


from pytest_bluez import host_config, Agent, wait_until

pytestmark = [pytest.mark.vm]


@host_config([Agent()], [Agent()])
@pytest.mark.parametrize("success", [True, False], ids=["accept", "reject"])
def test_agent_pair_bredr(hosts, success):
    host0, host1 = hosts

    host0.agent.adapter_method("StartDiscovery")
    host0.agent.expect("org.bluez.Adapter1.StartDiscovery:reply")

    host1.agent.adapter_set("Pairable", True)
    host1.agent.adapter_set("Discoverable", True)

    wait_until(host0.agent.has_device, host1.bdaddr)

    host0.agent.device_method(host1.bdaddr, "Pair")

    confirm_0 = host0.agent.expect("org.bluez.Agent1.RequestConfirmation")
    confirm_1 = host1.agent.expect("org.bluez.Agent1.RequestConfirmation")
    assert confirm_0.passkey == confirm_1.passkey
    host0.agent.reply()

    if success:
        host1.agent.reply()
        host0.agent.expect("org.bluez.Device1.Pair:reply")
    else:
        host1.agent.reply_error()
        host0.agent.expect("org.bluez.Device1.Pair:error")

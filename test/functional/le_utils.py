# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generic LE helpers for functional tests."""

from pytest_bluezenv import (
    Bluetoothd,
    wait_until,
)


def host_setup_is_le(host_setup):
    """True if the hosts run bluetoothd in LE-only mode."""
    return any(
        "ControllerMode = le" in (p.conf or "")
        for plugins in host_setup["setup"]
        for p in plugins
        if isinstance(p, Bluetoothd)
    )


def pair_le(client, server):
    """
    Pair Just Works over LE: client initiates and server authorizes, so
    only a single RequestAuthorization is expected.
    """
    server.agent.adapter_set("Pairable", True)

    client.agent.adapter_method("StartDiscovery")
    client.agent.expect("org.bluez.Adapter1.StartDiscovery:reply")
    wait_until(client.agent.has_device, server.bdaddr)

    client.agent.device_method(server.bdaddr, "Pair")
    server.agent.expect("org.bluez.Agent1.RequestAuthorization")
    server.agent.reply()
    client.agent.expect("org.bluez.Device1.Pair:reply")

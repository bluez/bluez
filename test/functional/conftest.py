# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import re
from pathlib import Path
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--list",
        action="store_true",
        default=None,
        help=("List tests"),
    )


def pytest_configure(config):
    if config.option.list:
        config.option.reportchars = "A"
        config.option.no_header = True
        config.option.verbose = -2


COLLECT_ERRORS = []


def pytest_collectreport(report):
    if report.outcome != "passed":
        COLLECT_ERRORS.append((report.outcome, report.fspath))


def pytest_collection_finish(session):
    if session.config.option.list:
        cwd = Path(".").resolve()
        root = session.config.rootpath.absolute()

        regex = re.compile(r"\[.*")
        names = set(
            (root.joinpath(item.location[0]), regex.sub("", item.location[2]))
            for item in session.items
        )

        for path, name in sorted(names):
            print(f"{path.resolve().relative_to(cwd, walk_up=True)}::{name}")
        for outcome, name in COLLECT_ERRORS:
            print(f"{outcome.upper()} {name}")
        print()
        os._exit(0)


@pytest.hookimpl()
def pytest_collection_modifyitems(session, config, items):
    sa_re = re.compile(r"_GHSA_...._...._....")

    for item in items:
        callspec = getattr(item, "callspec", None)

        # Add vm mark to VM-using tests
        if callspec is not None and callspec.params.get("vm_setup", None) is not None:
            item.add_marker(pytest.mark.vm)

        # Add security advisory marks based on test name
        if sa_re.search(item.name):
            item.add_marker(pytest.mark.sa)


@pytest.fixture
def paired_hosts_bredr(hosts):
    from .test_agent import test_agent_pair_bredr

    if hosts[0].agent.has_device(hosts[1].bdaddr):
        return hosts

    test_agent_pair_bredr(hosts, True)
    return hosts

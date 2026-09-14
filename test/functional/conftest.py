# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import re
import sys
import threading
import time
from pathlib import Path
import pytest

from pytest_bluezenv import rpc, utils

from .le_utils import host_setup_is_le, pair_le


def pytest_addoption(parser):
    parser.addoption(
        "--list",
        action="store_true",
        default=None,
        help=("List tests"),
    )
    parser.addoption(
        "--progress",
        action="store",
        default=None,
        choices=["yes", "no"],
        help=("Show what a test is waiting for (default: yes on a tty)"),
    )


# Wait for this long before reporting what a call is waiting for, so the
# calls that complete right away do not produce any output
PROGRESS_DELAY = 1.0
PROGRESS_INTERVAL = 0.25

# When the line cannot be updated in place the report is repeated at this
# interval instead, and only once the call is taking clearly too long
PROGRESS_LINE_DELAY = 5.0
PROGRESS_LINE_INTERVAL = 10.0

PROGRESS_STREAM = None


class Status:
    """
    Status line telling what a test is waiting for, updated in place by
    the terminal reporter of pytest so the report it writes itself is
    left alone.
    """

    def __init__(self, reporter):
        self.reporter = reporter
        self.shown = False

    def show(self, text):
        # Leave the line pytest is on, so what it reports there is not
        # overwritten by the status. Nothing is written when the line
        # is already one of ours.
        if not self.shown:
            self.reporter.ensure_newline()
            self.shown = True

        self.reporter.rewrite(text, erase=True, light=True)

    def clear(self):
        if not self.shown:
            return

        self.reporter.rewrite("", erase=True)
        self.shown = False


def _progress_desc(name, method, a):
    """
    Describe what a call is waiting for, e.g.

        host.0.1: pexpect.expect 'Pairing successful'
    """
    if method == "call_plugin" and len(a) > 1:
        plugin, func, args = a[0], a[1], a[2:]

        # Drop the identifier of the spawned process, if any
        if args and isinstance(args[0], int):
            args = args[1:]

        desc = f"{plugin}.{func}"
    else:
        desc, args = str(method), a

    if args:
        arg = args[0]
        # Calls running something on a host pass the function itself
        arg = getattr(arg, "__name__", None) or str(arg)
        if len(arg) > 60:
            arg = arg[:57] + "..."
        desc = f"{desc} {arg!r}"

    return f"{name}: {desc}" if name else desc


def _progress_status(elapsed, timeout):
    if timeout:
        left = max(0.0, timeout - elapsed)
        return f"{elapsed:.0f}s, {left:.0f}s left"

    return f"{elapsed:.0f}s"


def _progress_run(status, desc, timeout, done, stream=None, prefix=""):
    start = time.monotonic()
    next_line = PROGRESS_LINE_DELAY

    while not done.wait(PROGRESS_INTERVAL if status else 0.5):
        elapsed = time.monotonic() - start

        if status:
            if elapsed < PROGRESS_DELAY:
                continue

            status.show(f"waiting {desc} [{_progress_status(elapsed, timeout)}]")
            continue

        # The line cannot be updated in place, so report it as it goes
        if elapsed < next_line:
            continue

        next_line = elapsed + PROGRESS_LINE_INTERVAL
        stream.write(
            f"{prefix}waiting {desc}" f" [{_progress_status(elapsed, timeout)}]\n"
        )
        stream.flush()

    if status:
        status.clear()


def _progress_call(orig, status=None, stream=None, prefix=""):
    def call(self, method, *a, **kw):
        # The timeout of the calls waiting for something on a host is the
        # one used by the plugin serving them
        timeout = kw.get("timeout")
        if not timeout and method == "call_plugin" and "expect" in a[:2]:
            timeout = utils.DEFAULT_TIMEOUT

        name = getattr(self.log, "name", "")
        name = name[len("rpc.") :] if name.startswith("rpc.") else ""

        done = threading.Event()
        progress = threading.Thread(
            target=_progress_run,
            args=(status, _progress_desc(name, method, a), timeout, done),
            kwargs={"stream": stream, "prefix": prefix},
            daemon=True,
        )
        progress.start()

        try:
            return orig(self, method, *a, **kw)
        finally:
            done.set()
            progress.join()

    return call


def _setup_progress(config):
    """
    Report what a test is waiting for, so it is possible to tell when one
    is taking longer than it should.
    """
    global PROGRESS_STREAM

    if config.option.progress == "no":
        return

    # The workers of pytest-xdist run in their own process and share the
    # terminal with each other and with the controller reporting the
    # results, so none of them can update a line of its own: report the
    # calls taking too long as whole lines instead
    worker = getattr(config, "workerinput", None)

    if not worker:
        reporter = config.pluginmanager.get_plugin("terminalreporter")

        # No markup means no terminal to update a line on, e.g. when the
        # output is redirected or under CI
        if not reporter or not reporter.hasmarkup:
            return

        rpc.Connection.call = _progress_call(
            rpc.Connection.call, status=Status(reporter)
        )
        return

    # The output of a worker is captured at file descriptor level and
    # forwarded to the controller, so it goes to the terminal directly
    try:
        PROGRESS_STREAM = open("/dev/tty", "w", buffering=1)
    except OSError:
        # Not running from a terminal, e.g. under CI
        return

    rpc.Connection.call = _progress_call(
        rpc.Connection.call,
        stream=PROGRESS_STREAM,
        prefix=f"[{worker['workerid']}] ",
    )


def pytest_configure(config):
    _setup_progress(config)

    if config.option.list:
        config.option.reportchars = "A"
        config.option.no_header = True
        config.option.verbose = -2


def pytest_unconfigure(config):
    global PROGRESS_STREAM

    if PROGRESS_STREAM:
        PROGRESS_STREAM.close()
        PROGRESS_STREAM = None


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
def is_le(host_setup):
    """True if the current host configuration runs bluetoothd in LE-only mode."""
    return host_setup_is_le(host_setup)


@pytest.fixture
def paired_hosts(hosts, is_le):
    """
    Two hosts, paired over the bearer their host configuration uses.
    """
    from .test_agent import test_agent_pair_bredr

    host0, host1 = hosts

    if host0.agent.has_device(host1.bdaddr):
        return hosts

    if is_le:
        pair_le(host0, host1)
    else:
        test_agent_pair_bredr([host0, host1], True)

    return hosts

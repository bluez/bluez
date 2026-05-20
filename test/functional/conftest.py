# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import re
from pathlib import Path


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

#!/usr/bin/python3 -P
# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
import sys
from pathlib import Path
from importlib.machinery import PathFinder


class SelfImport(PathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "pytest_bluez":
            path = [str(Path(__file__).parent / "..")]
        return super().find_spec(fullname, path, target)


sys.meta_path.insert(0, SelfImport())

import pytest_bluez.env

sys.exit(pytest_bluez.env._main_runner())

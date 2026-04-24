# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for the test suite itself
"""
import sys
import subprocess
import warnings
from pathlib import Path

import pytest


def test_formatting():
    pytest.importorskip("black")

    result = subprocess.run(
        [sys.executable, "-mblack", "--check", "--diff", "-q", Path(__file__).parent],
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )
    if result.returncode != 0:
        warnings.warn(f"Formatting incorrect:\n{result.stdout}")

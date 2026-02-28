# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
"""
Utilities for end-to-end testing.

"""
import os
import io
import re
import logging
import subprocess
import shlex
import shutil
import threading
import time
from pathlib import Path

__all__ = ["run", "find_exe", "get_bdaddr", "quoted", "LogStream"]


SRC_DIR = (Path(__file__).parent / ".." / ".." / "..").absolute()
BUILD_DIR = None

_LOG_LOCK = threading.Lock()

log = logging.getLogger(f"run")

OUT = 5
logging.addLevelName(OUT, "OUT")


def find_exe(subdir, name):
    """
    Find executable, either in BlueZ build tree or system
    """
    paths = [
        SRC_DIR / "builddir" / subdir / name,
        SRC_DIR / "build" / subdir / name,
        SRC_DIR / subdir / name,
        shutil.which(name),
    ]
    if BUILD_DIR is not None:
        paths.insert(0, BUILD_DIR / subdir / name)
    for exe in paths:
        exe = str(exe)
        if exe and os.path.isfile(exe):
            return os.path.normpath(exe)

    raise FileNotFoundError(name)


def run(*args, input=None, capture_output=False, timeout=None, check=False, **kwargs):
    """
    Same as subprocess.run() but log output while running.
    """
    if input is not None:
        if kwargs.get("stdin") is not None:
            raise ValueError("stdin and input arguments may not both be used.")
        kwargs["stdin"] = subprocess.PIPE

    if capture_output:
        if kwargs.get("stdout") is not None or kwargs.get("stderr") is not None:
            raise ValueError(
                "stdout and stderr arguments may not be used " "with capture_output."
            )
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE

    stdout = kwargs.get("stdout", None)
    stderr = kwargs.get("stderr", None)
    encoding = kwargs.pop("encoding", None)
    errors = kwargs.pop("errors", "strict")

    stdout_buf = None
    stderr_buf = None

    if stdout == subprocess.PIPE:
        stdout = stdout_buf = io.BytesIO()
    elif isinstance(stdout, int):
        stdout = None

    stdout_log = LogStream("run.out", tee=stdout)
    kwargs["stdout"] = stdout_log.stream

    if stderr == subprocess.STDOUT:
        stderr_log = None
    else:
        if stderr == subprocess.PIPE:
            stderr = stderr_buf = io.BytesIO()
        elif isinstance(stderr, int):
            stderr = None

        stderr_log = LogStream("run.err", tee=stderr)
        kwargs["stderr"] = stderr_log.stream

    log.info("    $ {}".format(quoted(args[0])))

    with subprocess.Popen(*args, **kwargs) as process:
        try:
            stdout, stderr = process.communicate(input, timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        except:
            process.kill()
            raise
        finally:
            stdout_log.close()
            if stderr_log is not None:
                stderr_log.close()

        if stdout_buf is not None:
            stdout = stdout_buf.getvalue()
            if encoding not in ("bytes", None):
                stdout = stdout.decode(encoding=encoding, errors=errors)

        if stderr_buf is not None:
            stderr = stderr_buf.getvalue()
            if encoding not in ("bytes", None):
                stderr = stderr.decode(encoding=encoding, errors=errors)

        retcode = process.poll()
        if check and retcode:
            raise subprocess.CalledProcessError(
                retcode, process.args, output=stdout, stderr=stderr
            )

    log.info(f"(return code {retcode})")

    return subprocess.CompletedProcess(process.args, retcode, stdout, stderr)


def wait_files(jobs, paths, timeout=2):
    """
    Wait for subprocess.Popen instances until `paths` have been created.
    """
    start = time.time()

    for path in paths:
        while True:
            if time.time() > start + timeout:
                raise TimeoutError(f"Jobs {jobs} timed out")
            for job in jobs:
                if job.poll() is not None:
                    raise RuntimeError("Process exited unexpectedly")
            try:
                if os.stat(path):
                    break
            except OSError:
                time.sleep(0.25)


def get_bdaddr(index=0):
    """
    Get bdaddr of controller with given index
    """
    btmgmt = find_exe("tools", "btmgmt")
    res = subprocess.run(
        [btmgmt, "--index", str(index), "info"],
        stdout=subprocess.PIPE,
        check=True,
        encoding="utf-8",
    )
    m = re.search("addr ([A-Z0-9:]+) ", res.stdout)
    if not m:
        hciconfig = find_exe("tools", "hciconfig")
        res = subprocess.run(
            [hciconfig, f"hci{index}"],
            stdout=subprocess.PIPE,
            check=True,
            encoding="utf-8",
        )
        m = re.search("BD Address: ([A-Z0-9:]+)", res.stdout)
        if not m:
            raise ValueError("Can't find bdaddr")

    return m.group(1).lower()


def quoted(args):
    """
    Quote shell command
    """
    return " ".join(shlex.quote(arg) for arg in args)


class LogStream:
    """
    Logger that forwards input from a stream to logging, and
    optionally tees to another stream.  The input pipe is in
    `LogStream.stream`.

    """

    def __init__(self, name, pattern=None, tee=None):
        if pattern is not None:
            self._logger_pattern = (pattern, name)
            self.log = None
        else:
            self._logger_pattern = None
            self.log = logging.getLogger(name)
        self._ifd, self._ofd = os.pipe()
        self.stream = os.fdopen(self._ofd, "wb", buffering=0)
        self._pipeout = os.fdopen(self._ifd, "rb")
        self._tee = tee
        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _run(self):
        while True:
            line = self._pipeout.readline()
            if not line:
                break

            fmt_line = line.decode(errors="surrogateescape")
            fmt_line = self._filter(fmt_line)

            with _LOG_LOCK:
                log = self.log
                level = OUT
                if log is None:
                    m = re.match(self._logger_pattern[0], fmt_line)
                    if m:
                        name = "{}.{}".format(self._logger_pattern[1], m.group(1))
                        fmt_line = fmt_line[: m.start()] + fmt_line[m.end() :]
                        try:
                            level = int(m.group(2))
                        except ValueError:
                            pass
                    else:
                        name = self._logger_pattern[1]
                    log = logging.getLogger(name)

                log.log(level, fmt_line)

                if self._tee is not None:
                    self._tee.write(line)

        self._pipeout.close()

    def _filter(self, text):
        # Filter out problematic ANSI codes etc
        text = re.sub(r"\u001b\[=[0-9]+[hl]", r"", text)
        text = re.sub(r"\u001b\[\?7l", r"", text)
        text = re.sub(r"\u001b\[2J", r"", text)
        text = re.sub(r"\u001bc", r"", text)
        text = text.replace("\r", "")
        text = text.rstrip("\n")
        return text

    def error(self, *a, **kw):
        pass

    def close(self):
        if self._thread is not None:
            self.stream.close()
            self._thread.join()
            self._thread = None

    def __del__(self):
        self.close()

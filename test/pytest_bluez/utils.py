# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Utilities for end-to-end testing.

"""
import os
import sys
import io
import re
import logging
import subprocess
import shlex
import shutil
import threading
import time
import socket
import struct
import time
import select
import fnmatch
import heapq
import tempfile
import queue
import functools
from pathlib import Path

from gi.repository import GLib

__all__ = [
    "run",
    "find_exe",
    "wait_until",
    "get_bdaddr",
    "quoted",
    "mainloop_invoke",
    "mainloop_wrap",
    "mainloop_assert",
    "LogStream",
]


BUILD_DIR = None
SRC_DIR = None
DEFAULT_TIMEOUT = 20
SIMPLE_LOG_HANDLER = None

log = logging.getLogger(f"run")

OUT = 5
logging.addLevelName(OUT, "OUT")


def quoted(args):
    """
    Quote shell command
    """
    return " ".join(shlex.quote(arg) for arg in args)


def bluez_src_dir():
    if SRC_DIR is not None:
        return SRC_DIR

    src_dir = Path(__file__).parent / ".." / ".."
    if (src_dir / "src" / "org.bluez.service").exists():
        return src_dir

    return None


def find_exe(subdir, name):
    """
    Find executable, either in BlueZ build tree or system
    """
    src = bluez_src_dir()
    paths = [
        src and src / "builddir" / subdir / name,
        src and src / "build" / subdir / name,
        src and src / subdir / name,
        shutil.which(name),
        src and src / subdir / name,
        f"/usr/libexec/bluetooth/{name}",
    ]
    if BUILD_DIR is not None:
        paths.insert(0, BUILD_DIR / subdir / name)
    for exe in paths:
        if exe is None:
            continue
        exe = str(exe)
        if exe and os.path.isfile(exe):
            return os.path.normpath(exe)

    raise FileNotFoundError(name)


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


def wait_until(predicate, *a, timeout=None, **kw):
    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    count = max(20, round(timeout))
    for j in range(count):
        if predicate(*a, **kw):
            break
        time.sleep(timeout / count)
    else:
        raise TimeoutError("Timeout reached")


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


def mainloop_invoke(func, *a, **kw):
    """
    Blocking invoke of `func` in GLib main loop.

    Note:

        GLib main loop is only available for VM host plugins, not in tester.

    Example:

        value = mainloop_invoke(lambda: 123)
        assert value == 123

    Warning:
        dbus-python **MUST** be used only from the GLib main loop,
        as the library has concurrency bugs. All functions using it
        **MUST** either run from GLib main loop eg. via mainloop_wrap
    """
    waits = queue.SimpleQueue()

    def call():
        value = None
        try:
            value = func(*a, **kw)
        except BaseException as exc:
            value = exc
        finally:
            waits.put(value)
        return False

    context = GLib.MainContext.default()
    context.invoke_full(0, call)
    result = waits.get()

    if isinstance(result, BaseException):
        raise result

    return result


def mainloop_wrap(func):
    """
    Wrap function to run in GLib main loop thread

    Note:

        GLib main loop is only available for VM host plugins, not in tester.

    Example:

        @mainloop_wrap
        def func():
            bus = dbus.SystemBus()
    """

    @functools.wraps(func)
    def wrapper(*a, **kw):
        return mainloop_invoke(func, *a, **kw)

    return wrapper


def mainloop_assert(func):
    """
    Wrap function to assert it runs from GLib main loop

    Note:

        GLib main loop is only available for VM host plugins, not in tester.

    Example:

        @mainloop_assert
        def func():
            bus = dbus.SystemBus()
    """

    @functools.wraps(func)
    def wrapper(*a, **kw):
        context = GLib.MainContext.default()
        if not context.is_owner():
            raise AssertionError("Function not called from GLib mainloop")
        return func(*a, **kw)

    return wrapper


class TmpDir(tempfile.TemporaryDirectory):
    """Temporary directory in /run; with Python < 3.10 support"""

    def __init__(self, *a, **kw):
        kw.setdefault("dir", "/run")
        if sys.version_info >= (3, 10):
            kw.setdefault("ignore_cleanup_errors", True)
        super().__init__(*a, **kw)

    def cleanup(self):
        try:
            super().cleanup()
        except:
            pass


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


class LogStream:
    """
    Logger that forwards input from a stream to logging, and
    optionally tees to another stream.  The input pipe is in
    `LogStream.stream`.

    """

    TS_STRUCT = struct.Struct("@qq")
    LOG_THREAD = None
    LOG_THREAD_LOCK = threading.Lock()
    LOG_QUEUE = queue.SimpleQueue()

    def __init__(self, name, pattern=None, tee=None, stream=None):
        if pattern is not None:
            self._logger_pattern = (re.compile(pattern), name)
            self.log = None
        else:
            self._logger_pattern = None
            self.log = logging.getLogger(name)

        self._filter_re = re.compile(
            r"\u001b\[=[0-9]+[hl] | \u001b\[\?7l | \u001b\[2J | \u001bc | \n | \r",
            flags=re.X,
        )

        # Use SEQPACKET socketpair: this allows obtaining log
        # timestamps, which is important as we want as close to ns
        # precision as possible.  Read and log data in separate
        # threads to decouple if output is slow/blocking.

        if stream is None:
            self._in, self._out = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            self.stream = self._in.makefile("wb")
        else:
            self.stream = None
            self._in = None
            self._out = stream

        self._tee = tee
        self._nsec = None
        self._start_log_thread()
        self._read_thread = threading.Thread(target=self._run_read)
        self._read_thread.start()
        self._flush_event = threading.Event()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _run_read(self):
        buf = b""
        anc = new_anc = None

        try:
            # Enable timestamping
            cmsg_size = socket.CMSG_SPACE(self.TS_STRUCT.size)
            SO_TIMESTAMPNS_NEW = 64
            res = self._out.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS_NEW, 1)

            # Read data
            while True:
                data, new_anc, _, _ = self._out.recvmsg(4096, cmsg_size)
                while b"\n" not in data:
                    block = self._out.recv(4096)
                    if not block:
                        break
                    data += block

                if not data:
                    break

                buf += data

                # Log full lines
                while b"\n" in buf:
                    if anc is None:
                        anc = new_anc
                    j = buf.index(b"\n")
                    self.LOG_QUEUE.put((self, buf[: j + 1], anc))
                    buf = buf[j + 1 :]
                    anc = new_anc if buf else None
        finally:
            self._out.close()

            while b"\n" in buf:
                j = buf.index(b"\n")
                self.LOG_QUEUE.put((self, buf[: j + 1], new_anc))
                buf = buf[j + 1 :]
            if buf:
                self.LOG_QUEUE.put((self, buf, new_anc))

            self.LOG_QUEUE.put((self, None, None))

    @staticmethod
    def _start_log_thread():
        with LogStream.LOG_THREAD_LOCK:
            if LogStream.LOG_THREAD is not None:
                return

            LogStream.LOG_THREAD = threading.Thread(
                target=LogStream._run_log, daemon=True
            )
            LogStream.LOG_THREAD.start()

    @staticmethod
    def _run_log():
        # Read data

        while True:
            logger, data, new_anc = LogStream.LOG_QUEUE.get()
            if data is None:
                logger._flush_event.set()
                continue

            if logger._tee:
                logger._tee.write(data)

            if data[-2:] == b"\n":
                data = data[:-1]

            logger._do_log(data, new_anc)

    def _get_time(self, line, anc):
        if anc:
            cmsg_data = anc[0][2]
            sec, nsec = self.TS_STRUCT.unpack(cmsg_data)
            nsec = sec * 1_000_000_000 + nsec
        else:
            nsec = time.time_ns()

        # Force monotonic time
        if self._nsec is None or self._nsec < nsec:
            self._nsec = nsec
        else:
            self._nsec += 1
            nsec = self._nsec

        return nsec

    def _do_log(self, line, anc):
        nsec = self._get_time(line, anc)

        fmt_line = line.decode(errors="surrogateescape")
        fmt_line = self._filter_re.sub("", fmt_line)

        log = self.log
        level = OUT
        if log is None:
            m = self._logger_pattern[0].match(fmt_line)
            if m:
                name = "{}.{}".format(self._logger_pattern[1], m.group(1))
                fmt_line = fmt_line[: m.start()] + fmt_line[m.end() :]
                try:
                    level = int(m.group(2))
                    nsec = int(m.group(3))
                except ValueError:
                    pass
            else:
                name = self._logger_pattern[1]
        else:
            name = log.name

        if SIMPLE_LOG_HANDLER is not None:
            SIMPLE_LOG_HANDLER.emit_simple(name, level, fmt_line, nsec)
            return

        if log is None:
            log = logging.getLogger(name)

        record = _OutputLogRecord(log.name, level, fmt_line, nsec)
        log.handle(record)

    def close(self, flush=True):
        if self._read_thread is not None:
            if self._in is not None:
                self.stream.close()
                self._in.shutdown(socket.SHUT_RDWR)
                self._in.close()
            else:
                try:
                    self._out.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            self._read_thread.join()
            self._read_thread = None
            self._flush_event.wait()

    def __del__(self):
        self.close()


class _OutputLogRecord(logging.LogRecord):
    """Minimal (faster) log record for output lines"""

    def __init__(self, name, level, msg, nsec):
        self.args = ()
        self.pathname = ""
        self.filename = ""
        self.module = ""
        self.exc_info = None
        self.exc_text = None
        self.stack_info = None
        self.lineno = 0
        self.funcName = ""
        self.thread = None
        self.threadName = None
        self.processName = None
        self.taskName = None
        self.relativeCreated = None

        self.name = name
        self.msg = msg
        self.levelname = logging.getLevelName(level)
        self.levelno = level
        self.nsec = nsec
        self.created = nsec / 1e9
        self.msecs = (nsec % 1_000_000_000) / 1_000_000 + 0.0


class LogNameFilter(logging.Filter):
    """
    Filter based on fnmatch deny/allow patterns on logger name
    """

    def __init__(self, allow=(), deny=()):
        if allow:
            allow_re = "|".join(self._re(x) for x in allow)
            self.allow = re.compile(allow_re)
        else:
            self.allow = None

        if deny:
            deny_re = "|".join(self._re(x) for x in deny)
            self.deny = re.compile(deny_re)
        else:
            self.deny = None

    def _re(self, name):
        pat = fnmatch.translate(name)
        return f"{pat}$|{pat}\\."

    def filter(self, record):
        if self.deny is not None and self.deny.match(record.name):
            return False
        if self.allow is not None and not self.allow.match(record.name):
            return False
        return True

    @classmethod
    def enable(cls, filterers, allow=(), deny=()):
        """
        Enable filter for all of the filterers
        """
        f = cls(allow, deny)

        for h in filterers:
            if any(isinstance(f, cls) for f in h.filters):
                continue
            h.addFilter(f)

    @classmethod
    def disable(cls, filterers):
        """
        Disable filter for all of the filterers
        """
        for h in filterers:
            for f in list(h.filters):
                if isinstance(f, cls):
                    h.removeFilter(f)


class LogReorderFilter(logging.Filter):
    """
    Reorder handler's log records based on timestamp
    """

    FLUSH_THREAD = None
    FLUSH_ITEMS = []
    FLUSH_END = threading.Event()

    def __init__(self, handler):
        self._handler = handler
        self._queue = []
        self._records = {}
        self._pos = time.time_ns()
        self._delay = 1000_000_000
        self._lock = threading.Lock()

    def filter(self, record):
        if getattr(record, "reordered", False):
            return True
        self._push(record)
        self._flush()
        return False

    def _push(self, record):
        ts = getattr(record, "nsec", int(record.created * 1e9))
        with self._lock:
            heapq.heappush(self._queue, (ts, id(record)))
            self._records[id(record)] = record
            self._pos = max(self._pos, ts)

        self._delay = max(self._delay, 2 * (time.time_ns() - ts))

    def _flush(self, force=False):
        with self._lock:
            while self._queue and (
                self._queue[0][0] + self._delay < self._pos or force
            ):
                ts, rid = heapq.heappop(self._queue)
                record = self._records.pop(rid)
                record.reordered = True
                self._handler.handle(record)

    @classmethod
    def flush_all(cls):
        """
        Flush all log reorder filters added via enable()
        """
        for f in cls.FLUSH_ITEMS:
            f._flush(force=True)

    @classmethod
    def enable(cls, filterers):
        """
        Enable reordering for all of the filterers
        """
        for h in filterers:
            if any(isinstance(f, cls) for f in h.filters):
                continue

            f = cls(h)
            cls.FLUSH_ITEMS.append(f)
            h.addFilter(f)

        if cls.FLUSH_THREAD is None and cls.FLUSH_ITEMS:
            cls.FLUSH_END.clear()
            cls.FLUSH_THREAD = threading.Thread(target=cls._flush_thread, daemon=True)
            cls.FLUSH_THREAD.start()

    @classmethod
    def disable(cls, filterers):
        """
        Disable reordering for all of the filterers
        """
        for h in filterers:
            for f in list(h.filters):
                if not isinstance(f, cls):
                    continue

                cls.FLUSH_ITEMS.remove(f)
                h.removeFilter(f)
                f._flush(force=True)

        if cls.FLUSH_THREAD is not None and cls.FLUSH_ITEMS:
            cls.FLUSH_END.set()
            cls.FLUSH_THREAD.join()

    @classmethod
    def _flush_thread(cls):
        # Timed flushing
        while not cls.FLUSH_END.wait(1.0):
            for f in cls.FLUSH_ITEMS:
                f._flush()

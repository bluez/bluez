# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
"""
Test environment:

- one or more qemu instances running Linux kernel + BlueZ + other stack
- connected by btvirt, or real USB Bluetooth controllers
- Python RPC connection to each via unix socket <-> qemu chardev

"""
import sys
import os
import signal
import re
import pwd
import time
import shlex
import argparse
import shutil
import threading
import tempfile
import operator
import logging
import socket
import pickle
from pathlib import Path
from subprocess import Popen, DEVNULL, PIPE, run

from . import rpc, utils

__all__ = ["HostPlugin", "Environment"]

log = logging.getLogger(__name__)


class HostPlugin:
    value = None
    depends = None

    def __init__(self):
        """Configure plugin (runs on host-side)"""
        pass

    def setup(self, impl: Implementation):
        """VM-side setup"""
        pass

    def teardown(self):
        """VM-side teardown"""
        pass


class HostProxy:
    """
    Parent-side proxy for VM host: load plugins, RPC calls to plugins
    """

    def __init__(self, path, timeout, name):
        self._path = path
        self._active_conn = None
        self._timeout = timeout
        self._plugins = {}
        self._name = name

    def load(self, plugin: HostPlugin):
        self.start_load(plugin)
        self.wait_load()

    def start_load(self, plugin: HostPlugin):
        if plugin.name in self._plugins:
            # Already loaded
            return
        self._conn.call_noreply("start_load", plugin)
        self._plugins[plugin.name] = None

    def wait_load(self):
        for name, value in self._conn.call("wait_load").items():
            if value is None:
                value = _PluginProxy(name, self._active_conn)
            self._plugins[name] = value

    @property
    def _conn(self):
        if self._active_conn is None:
            self._active_conn = rpc.client_unix_socket(
                self._path, timeout=self._timeout, name=self._name
            )
        return self._active_conn

    def __getattr__(self, name):
        if name not in self._plugins:
            raise AttributeError(name)
        return self._plugins[name]

    def close(self):
        self._plugins = {}
        if self._active_conn is not None:
            self._active_conn.close()
            self._active_conn = None


class _PluginProxy:
    """
    Host-side proxy for a plugin: RPC calls
    """

    def __init__(self, name, conn):
        self._name = name
        self._conn = conn

    def __call__(self, *a, **kw):
        return self._conn.call("call_plugin", self._name, "__call__", *a, **kw)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a, **kw: self._conn.call(
            "call_plugin", self._name, name, *a, **kw
        )


class Implementation:
    """
    VM-side main instance: setup/teardown plugins, plugin RPC server side
    """

    def __init__(self):
        self.plugins = {}
        self.plugin_order = []
        self.load_error = False

    def start_load(self, plugin):
        try:
            log.info(f"Plugin {plugin.name} load")
            plugin.setup(self)
        except:
            self.load_error = True
            raise
        self.plugins[plugin.name] = plugin
        self.plugin_order.append(plugin.name)
        log.info(f"Plugin {plugin.name} ready")

    def wait_load(self):
        if self.load_error:
            raise RuntimeError("load failed")
        log.debug(f"Plugins ready")
        return {p.name: getattr(p, "value", None) for p in self.plugins.values()}

    def unload(self, name):
        self.plugin_order.remove(name)
        p = self.plugins.pop(name)
        method = getattr(p, "teardown", None)
        if method is not None:
            try:
                method()
            except BaseException as exc:
                log.error(f"plugin teardown error: {exc}")

    def call_plugin(self, name, method, *a, **kw):
        return getattr(self.plugins[name], method)(*a, **kw)

    def teardown(self):
        while self.plugin_order:
            self.unload(self.plugin_order[-1])


def _find_rpc_vport():
    """
    Find RPC control virtio port
    """
    for port in Path("/sys/class/virtio-ports").iterdir():
        with open(port / "name", "rb") as f:
            name = f.read(64)
            if name == b"bluez-func-test-rpc\n":
                return f"/dev/{port.name}"

    return None


def _main_runner_instance():
    """
    VM-side tester main instance
    """
    dev = _find_rpc_vport()
    if dev is not None:
        print(f"Test RPC server on {dev}", file=sys.stderr)
        rpc.server_file(dev, Implementation())
        return

    import termios
    import tty

    with open(sys.argv[1], "r+b", buffering=0) as f:
        mode = termios.tcgetattr(f.fileno())
        tty.cfmakeraw(mode)
        mode = termios.tcsetattr(f.fileno(), termios.TCSANOW, mode)
        rpc.server_stream(f, Implementation())


class _RunnerLogHandler(logging.Handler):
    def flush(self):
        sys.stderr.flush()

    def emit(self, record):
        try:
            msg = record.getMessage()
            if record.exc_info:
                msg += "\n"
                msg += traceback.format_exception(*record.exc_info)
            name = record.name
            levelno = record.levelno
            for line in msg.splitlines():
                sys.stderr.write(f"\x00{name}\x01{levelno}\x02{line}\n")
            self.flush()
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)


def _main_runner():
    """
    VM-side tester supervisor
    """
    logging.basicConfig(level=0, handlers=[_RunnerLogHandler()])

    # Preload libraries
    import dbus
    import pexpect

    # Keep one instance running
    while True:
        log.info("Starting test instance")

        pid = os.fork()
        if pid == 0:
            os.setpgid(0, 0)
            _main_runner_instance()
            os._exit(0)
        else:
            status = 1

            try:
                _, status = os.waitpid(pid, 0)
            except ChildProcessError:
                pass

            log.info("Terminating test instance")

            for sig in [signal.SIGTERM, signal.SIGCONT, signal.SIGKILL]:
                try:
                    os.kill(-pid, sig)
                    time.sleep(0.5 if sig == signal.SIGCONT else 0.1)
                except ProcessLookupError:
                    break

            if status != 0:
                time.sleep(0.1)


ENV_INDEX = -1


class Environment:
    def __init__(self, kernel, num_hosts, usb_indices=None, virtio=True, timeout=20):
        if Path(kernel).is_dir():
            self.kernel = str(Path(kernel) / "arch" / "x86" / "boot" / "bzImage")
        else:
            self.kernel = str(kernel)

        self.num_hosts = operator.index(num_hosts)
        self.jobs = []
        self.log_streams = []
        self.hosts = []
        self.virtio = bool(virtio)
        self.timeout = float(timeout)
        self.path = None

        if usb_indices is None:
            self.usb_indices = None
        elif usb_indices is not None and self.num_hosts <= len(usb_indices):
            self.usb_indices = tuple(usb_indices)
        else:
            raise ValueError(
                "USB redirection enabled, but not enough controllers for each host"
            )

        if sys.version_info >= (3, 12):
            self.runner = [sys.executable, "-P"]
        else:
            self.runner = [sys.executable]
        self.runner += [str((Path(__file__).parent / "runner.py").absolute())]

        try:
            self.stdbuf = [utils.find_exe("", "stdbuf"), "-o", "L", "-e", "L"]
        except FileNotFoundError:
            self.stdbuf = []

    def start(self):
        self.path = Path(tempfile.mkdtemp(prefix="bluez-func-test-"))

        if self.usb_indices is None:
            args = self._start_btvirt()
        else:
            args = self._start_usb()

        paths, names = self._start_runners(args)
        self._start_hosts(paths, names)

    def stop(self):
        for job in self.jobs:
            if job.poll() is not None:
                continue
            job.terminate()

        while self.jobs:
            job = self.jobs.pop()
            if job.poll() is None:
                job.wait()

        while self.log_streams:
            self.log_streams.pop().close()

        while self.hosts:
            self.hosts.pop().close()

        # Clean up tmpdir (btvirt, own sockets, rmdir)
        if self.path is not None:
            for f in list(self.path.iterdir()):
                if f.name.startswith("bt-server-"):
                    f.unlink()
                if f.name.startswith("bluez-func-test-rpc-"):
                    f.unlink()

            self.path.rmdir()
            self.path = None

    def _add_log(self, *a, **kw):
        f = utils.LogStream(*a, **kw)
        self.log_streams.append(f)
        return f.stream

    def _start_btvirt(self):
        exe = utils.find_exe("emulator", "btvirt")
        logger = self._add_log("btvirt")

        cmd = self.stdbuf + [exe, f"--server={self.path}"]
        log.info("Starting btvirt: {}".format(utils.quoted(cmd)))

        job = Popen(
            cmd,
            stdout=logger,
            stderr=logger,
            stdin=DEVNULL,
        )
        self.jobs.append(job)

        socket = self.path / "bt-server-bredrle"
        utils.wait_files([job], [socket])
        return [[f"-u{socket}"]] * self.num_hosts

    @classmethod
    def check_controller(cls, name):
        subsys = Path("/sys/class/bluetooth") / name / "device" / "subsystem"
        if subsys.resolve() != Path("/sys/bus/usb"):
            raise ValueError(f"{devname} is not an USB device")

        devpath = Path(f"/sys/class/bluetooth/{name}/device/../")
        with open(devpath / "busnum", "r") as f:
            busnum = "{:03}".format(int(f.read().strip()))
        with open(devpath / "devnum", "r") as f:
            devnum = "{:03}".format(int(f.read().strip()))

        devname = f"/dev/bus/usb/{busnum}/{devnum}"
        if not Path(devname).exists():
            raise ValueError(f"{devname} does not exist")

        try:
            with open(devname, "wb") as f:
                pass
        except IOError:
            user = pwd.getpwuid(os.getuid()).pw_name.strip()
            message = (
                f"error: cannot open {devname} for {name} USB redirection. "
                f"Run: 'sudo setfacl -m user:{user}:rw- {devname}' "
                f"to grant the permission"
            )
            raise ValueError(message)

        return busnum, devnum

    def _start_usb(self):
        args = []

        for index in self.usb_indices[: self.num_hosts]:
            busnum, devnum = self.check_controller(index)
            args.append(["-U", f"usb-host,hostbus={busnum},hostaddr={devnum}"])

        return args

    def _start_runners(self, args):
        global ENV_INDEX

        test_runner = utils.find_exe("tools", "test-runner")

        socket_paths = []
        host_names = []

        ENV_INDEX += 1

        for idx, arg in enumerate(args):
            socket_path = str(self.path / f"bluez-func-test-rpc-{idx}")
            socket_paths.append(socket_path)

            qemu_args = [
                "-chardev",
                f"socket,id=ser0,path={socket_path},server=on,wait=off",
            ]
            if self.virtio:
                qemu_args += [
                    "-device",
                    "virtio-serial",
                    "-device",
                    "virtserialport,chardev=ser0,name=bluez-func-test-rpc",
                ]
            else:
                qemu_args += [
                    "-device",
                    "pci-serial,chardev=ser0",
                ]

            extra_args = []
            for q in qemu_args:
                extra_args += ["-o", q]

            extra_args += ["-H"]

            tty = 1
            if self.usb_indices is None:
                tty += 1

            cmd = (
                [test_runner, f"--kernel={self.kernel}"]
                + arg
                + extra_args
                + ["--"]
                + self.runner
                + [f"/dev/ttyS{tty}"]
            )

            log.info("Starting host: {}".format(utils.quoted(cmd)))

            host_names.append(f"host.{ENV_INDEX}.{idx}")

            logger = self._add_log(
                host_names[-1],
                pattern=".*\x00([^\x00-\x03]+)\x01([^\x00-\x03]+)\x02",
            )
            self.jobs.append(Popen(cmd, stdout=logger, stderr=logger, stdin=DEVNULL))

        utils.wait_files(self.jobs, socket_paths)
        return socket_paths, host_names

    def _start_hosts(self, socket_paths, host_names):
        if len(socket_paths) != self.num_hosts:
            raise RuntimeError("Wrong number of sockets")

        for path, name in zip(socket_paths, host_names):
            host = HostProxy(path, timeout=self.timeout, name=name)
            host._conn
            self.hosts.append(host)

    def __del__(self):
        self.stop()

    def __enter__(self):
        try:
            self.start()
        except:
            self.stop()
            raise
        return self

    def __exit__(self, type, value, tb):
        self.stop()

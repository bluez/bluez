# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
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
import traceback
import resource
import warnings
import subprocess
from pathlib import Path
from subprocess import Popen, DEVNULL, PIPE, run

from gi.repository import GLib

from . import rpc, utils

__all__ = ["HostPlugin", "HostProxy"]

log = logging.getLogger("env")


class HostPlugin:
    """
    Plugin to insert code to VM host side.

    Attributes:
        name (str): unique name for the plugin
        depends (tuple[HostPlugin]): plugins to be loaded before this one
        value (object): object to appear as HostProxy attribute on parent side.
            If None, the plugin is represented by a proxy object that does RPC
            calls. Otherwise, must be a serializable value.

    """

    name = None
    depends = ()
    value = None

    def __init__(self):
        """
        Configure plugin (runs on parent host side).  This is
        called at test discovery time, so should mainly store static
        data.

        """
        pass

    def presetup(self, config):
        """
        Parent host-side setup, before VM environment is started.  May
        use pytest.skip() to skip tests in case plugin cannot be set up.

        Args:
            config (pytest.Config): pytest configuration object
        """
        pass

    def setup(self, impl):
        """
        VM-side setup

        Args:
            impl (Implementation): plugin host object
        """
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
        """
        Load given plugin to the VM host synchronously.
        """
        self.start_load(plugin)
        self.wait_load()

    def set_instance_name(self, name):
        self.instance_name = name
        self._conn.call_noreply("set_instance_name", name)

    def start_load(self, plugin: HostPlugin):
        """
        Initiate loading the given plugin to the VM host.  Use
        `wait_load` to wait for completion and make loaded plugins
        usable.

        """
        if plugin.name in self._plugins:
            # Already loaded
            return
        self._conn.call_noreply("start_load", plugin)
        self._plugins[plugin.name] = None

    def wait_load(self, timeout=None):
        """
        Wait for plugin loads to complete, and make plugins available.
        """
        for name, value in self._conn.call("wait_load", timeout=timeout).items():
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
        """
        Shutdown this VM host tester instance.
        """
        self._plugins = {}
        if self._active_conn is not None:
            self._active_conn.close()
            self._active_conn = None

    def _close_start(self):
        self._plugins = {}
        if self._active_conn is not None:
            self._active_conn.close_start()

    def _close_finish(self, force=False):
        if self._active_conn is not None:
            self._active_conn.close_finish(force=force)
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

    def _call_noreply(self, name, *a, **kw):
        self._conn.call_noreply("call_plugin", self._name, name, *a, **kw)


class Implementation:
    """
    VM-side main instance: setup/teardown plugins, plugin RPC server side
    """

    def __init__(self):
        self.plugins = {}
        self.plugin_order = []
        self.load_error = False

    def set_instance_name(self, name):
        self.instance_name = name
        socket.sethostname(name)

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

    def _unload(self, name):
        self.plugin_order.remove(name)
        p = self.plugins.pop(name)
        method = getattr(p, "teardown", None)
        if method is not None:
            try:
                method()
            except BaseException as exc:
                tb = traceback.format_exc()
                log.error(f"Plugin {name} teardown error: {exc}\n{tb}")
                return False
        return True

    def call_plugin(self, name, method, *a, **kw):
        return getattr(self.plugins[name], method)(*a, **kw)

    def teardown(self):
        success = True
        while self.plugin_order:
            name = self.plugin_order[-1]
            log.info(f"Plugin {name} teardown")
            if not self._unload(name):
                success = False
            log.info(f"Plugin {name} teardown done")
        if not success:
            raise RuntimeError("teardown failure")


def _find_vport(target_name):
    """
    Find RPC control virtio port
    """
    for port in Path("/sys/class/virtio-ports").iterdir():
        with open(port / "name", "rb") as f:
            name = f.read(64)
            if name == target_name:
                return f"/dev/{port.name}"

    raise RuntimeError(f"No virtio port {target_name} found")


class _RunnerLogHandler(logging.Handler):
    def __init__(self, stream):
        super().__init__()
        self.stream = stream

    def flush(self):
        self.stream.flush()

    def emit_simple(self, name, levelno, line, nsec):
        self.stream.write(f"\x00{name}\x01{levelno}\x02{nsec}\x03{line}\n")

    def emit(self, record):
        try:
            msg = record.getMessage()
            if record.exc_info:
                msg += "\n"
                msg += traceback.format_exception(*record.exc_info)
            name = record.name
            levelno = record.levelno
            nsec = getattr(record, "nsec", None)
            if nsec is None:
                nsec = int(record.created * 1e9)
            for line in msg.splitlines():
                self.emit_simple(name, levelno, msg, nsec)
            self.stream.flush()
        except RecursionError:
            raise
        except Exception:
            self.handleError(record)

    def start(self):
        self.flush_thread = threading.Thread(target=self._flush_thread, daemon=True)
        self.flush_thread.start()

    def _flush_thread(self):
        while True:
            time.sleep(0.5)
            self.stream.flush()


def _main_runner_instance():
    """
    VM-side tester main instance
    """
    from dbus.mainloop.glib import DBusGMainLoop

    # Start GLib mainloop early: dbus-python needs it
    loop = GLib.MainLoop()
    dbus_loop = DBusGMainLoop(set_as_default=True)
    loop_thread = threading.Thread(target=loop.run, daemon=True)
    loop_thread.start()

    utils.SIMPLE_LOG_HANDLER.start()
    try:
        dev = _find_vport(b"bluez-func-test-rpc\n")
        log.info(f"Test RPC server on {dev}")
        rpc.server_file(dev, Implementation())
    finally:
        utils.SIMPLE_LOG_HANDLER.flush()
        loop.quit()


def _setup_vm_instance():
    # Mount shared path
    path = Path("/run/shared")
    if not path.is_dir():
        path.mkdir()
        run(["mount", "-t", "9p", "/dev/shared", str(path)], check=True)

    # Setup sys.path
    with open("/run/shared/sys.path", "rb") as f:
        (sys.path,) = pickle.load(f)

    # Set up core dumps
    with open("/proc/sys/kernel/core_pattern", "w") as f:
        f.write("|/usr/bin/env tee /run/shared/test-functional-%h-%e-%t.core")

    resource.setrlimit(
        resource.RLIMIT_CORE, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
    )

    # Start (a)getty
    try:
        exe = utils.find_exe("", "agetty")
    except FileNotFoundError:
        log.warning("agetty not available")
        exe = None
    try:
        setsid = utils.find_exe("", "setsid")
    except FileNotFoundError:
        log.warning("setsid not available")
        setsid = None

    if exe is not None and setsid is not None:
        # Use shell script for restarting getty: uses less memory than Python
        script = Path("/tmp/getty.script")
        with open(script, "w") as f:
            f.write(
                f'#!/bin/sh\nwhile true; do "{setsid}" "{exe}" -n -h -L -l /bin/bash ttyS1; done'
            )

        os.chmod(script, 0o755)

        pid = os.fork()
        if pid == 0:
            os.setsid()
            os.execv(script, [script])
            os._exit(1)

    _start_chronyd()


def _start_chronyd():
    global _CHRONYD

    try:
        exe = utils.find_exe("", "chronyd")
    except FileNotFoundError:
        log.warning("chronyd not available")
        return

    if not Path("/dev/ptp0").exists():
        log.warning("/dev/ptp0 not available")
        return

    tmpdir = tempfile.mkdtemp(prefix=f"chronyd-")
    config = Path(tmpdir) / "chronyd.conf"

    with open(config, "w") as f:
        text = f"makestep 0.1 3\nrefclock PHC /dev/ptp0 poll -2\n"
        f.write(text)

    cmd = [exe, "-n", "-f", str(config), "-q"]
    log.debug("Synchronizing clock: {}".format(utils.quoted(cmd)))
    subprocess.run(cmd, check=True)

    cmd = [exe, "-n", "-f", str(config)]
    log.debug("Starting chronyd: {}".format(utils.quoted(cmd)))
    _CHRONYD = subprocess.Popen(cmd)


def _reset_vm_instance():
    # Power cycle controller to reset it between tests
    btmgmt = utils.find_exe("tools", "btmgmt")
    run([btmgmt, "power", "off"], check=True)
    run([btmgmt, "power", "on"], check=True)


def _main_runner():
    """
    VM-side tester supervisor
    """
    log_port = _find_vport(b"bluez-func-test-log\n")
    log_stream = open(log_port, "w", encoding="utf-8", errors="surrogateescape")
    utils.SIMPLE_LOG_HANDLER = _RunnerLogHandler(log_stream)
    logging.basicConfig(level=0, handlers=[utils.SIMPLE_LOG_HANDLER])

    # Basic VM setup
    _setup_vm_instance()

    # Preload libraries
    import dbus
    import pexpect

    # Keep one instance running
    while True:
        log.info("Starting test instance")

        _reset_vm_instance()

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

            done = False

            while not done:
                for sig in [signal.SIGTERM, signal.SIGCONT, signal.SIGKILL]:
                    try:
                        os.kill(-pid, sig)
                        time.sleep(0.5 if sig == signal.SIGCONT else 0.1)
                    except ProcessLookupError:
                        done = True
                        break

            if status != 0:
                time.sleep(0.1)


ENV_INDEX = -1


class Environment:
    def __init__(self, kernel, num_hosts, usb_indices=None, timeout=20):
        if Path(kernel).is_dir():
            self.kernel = str(Path(kernel) / "arch" / "x86" / "boot" / "bzImage")
        else:
            self.kernel = str(kernel)

        self.num_hosts = operator.index(num_hosts)
        self.jobs = []
        self.log_streams = []
        self.hosts = []
        self.timeout = float(timeout)
        self.path = None
        self.reuse_group = None

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
            try:
                self.hosts.pop().close()
            except rpc.RemoteError:
                # error already logged
                pass

        # Clean up tmpdir (btvirt, own sockets, rmdir)
        if self.path is not None:
            for f in list(self.path.iterdir()):
                if f.name.startswith("bt-server-"):
                    f.unlink()
                if f.name.startswith("shared-"):
                    shutil.rmtree(f.resolve(), ignore_errors=True)
                    continue
                if f.name.startswith("bluez-func-test-"):
                    f.unlink()

            self.path.rmdir()
            self.path = None

    def close_hosts(self):
        try:
            for h in self.hosts:
                h._close_start()
        finally:
            success = True
            for h in self.hosts:
                try:
                    h._close_finish(force=not success)
                except:
                    log.error(traceback.format_exc())
                    success = False

            if not success:
                raise RuntimeError("Error closing hosts")

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

            tty_path = str(self.path / f"bluez-func-test-tty-{idx}")
            log_path = str(self.path / f"bluez-func-test-log-{idx}")

            shared_path = self.path / f"shared-{idx}"
            shared_path.mkdir()

            # Python import paths
            with open(shared_path / "sys.path", "wb") as f:
                pickle.dump((sys.path,), f)

            # RPC socket
            qemu_args = [
                "-chardev",
                f"socket,id=ser0,path={socket_path},server=on,wait=off",
            ]

            qemu_args += [
                "-device",
                "virtio-serial",
                "-device",
                "virtserialport,chardev=ser0,name=bluez-func-test-rpc",
            ]

            # Separate TTY access
            qemu_args += [
                "-chardev",
                f"socket,id=ser1,path={tty_path},server=on,wait=off",
            ]

            qemu_args += [
                "-device",
                "pci-serial,chardev=ser1",
            ]

            # Log socket
            qemu_args += [
                "-chardev",
                f"socket,id=ser2,path={log_path},server=on,wait=on",
            ]

            qemu_args += [
                "-device",
                "virtio-serial",
                "-device",
                "virtserialport,chardev=ser2,name=bluez-func-test-log",
            ]

            # Shared filesystem
            qemu_args += [
                "-fsdev",
                f"local,id=fsdev-shared,path={shared_path},readonly=off,security_model=none,multidevs=remap",
                "-device",
                "virtio-9p-pci,fsdev=fsdev-shared,mount_tag=/dev/shared",
            ]

            extra_args = []
            for q in qemu_args:
                extra_args += ["-o", q]

            extra_args += ["-H"]

            cmd = (
                [test_runner, f"--kernel={self.kernel}"]
                + arg
                + extra_args
                + ["--"]
                + self.runner
            )

            log.info("Starting host: {}".format(utils.quoted(cmd)))
            log.info(f"TTY: socat {tty_path} STDIO,rawer")

            host_names.append(f"host.{ENV_INDEX}.{idx}")

            logger = self._add_log(host_names[-1])
            self.jobs.append(Popen(cmd, stdout=logger, stderr=logger, stdin=DEVNULL))

            # Start log reader
            utils.wait_files(self.jobs, [log_path])

            log_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            log_sock.connect(log_path)
            self._add_log(
                host_names[-1],
                pattern=".*\x00([^\x00-\x03]+)\x01([^\x00-\x03]+)\x02([^\x00-\x03]+)\x03",
                stream=log_sock,
            )

        utils.wait_files(self.jobs, socket_paths)

        return socket_paths, host_names

    def _start_hosts(self, socket_paths, host_names):
        if len(socket_paths) != self.num_hosts:
            raise RuntimeError("Wrong number of sockets")

        for path, name in zip(socket_paths, host_names):
            host = HostProxy(path, timeout=self.timeout, name=name)
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

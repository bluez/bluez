# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import re
import shutil
import logging
import warnings
from pathlib import Path

import pytest

from . import utils, env, build_kernel
from .btmon import Btmon


__all__ = [
    # hooks:
    "pytest_addoption",
    "pytest_configure",
    "pytest_collectreport",
    "pytest_collection_finish",
    "pytest_collection_modifyitems",
    "pytest_sessionstart",
    "pytest_sessionfinish",
    "pytest_runtest_logstart",
    "pytest_runtest_setup",
    "pytest_runtest_call",
    "pytest_runtest_teardown",
    "pytest_report_teststatus",
    "pytest_runtest_logfinish",
    # fixtures:
    "kernel",
    "usb_indices",
    "host_setup",
    "vm_setup",
    "vm",
    "hosts",
    "vm_once",
    "hosts_once",
]

# For logging test status messages to test-functional.log
status_log = logging.getLogger("pytest")
status_log_seen = set()


def pytest_addoption(parser):
    group = parser.getgroup("pytest_bluez", "bluez test options")

    group.addoption(
        "--kernel",
        action="store",
        default=None,
        help=("Kernel image to use"),
    )
    group.addoption(
        "--usb",
        action="store",
        default=None,
        help=("USB HCI devices to use, e.g. 'hci0,hci1'"),
    )
    group.addoption(
        "--force-usb",
        action="store_true",
        default=None,
        help=("Force tests to run with USB controllers instead of btvirt"),
    )
    group.addoption(
        "--bluez-build-dir",
        action="store",
        default=None,
        type=Path,
        help=("Build directory to find BlueZ development binaries"),
    )
    group.addoption(
        "--bluez-src-dir",
        action="store",
        default=None,
        type=Path,
        help=("Directory to find BlueZ sources"),
    )
    group.addoption(
        "--list",
        action="store_true",
        default=None,
        help=("List tests"),
    )
    group.addoption(
        "--log-filter",
        action="append",
        default=None,
        help=(
            "Enable/disable loggers by name. Can be passed multiple times. Example: +host.0,-rpc"
        ),
    )
    group.addoption(
        "--no-log-reorder",
        action="store_true",
        default=False,
        help="Don't reorder logs to timestamp order",
    )

    group.addoption(
        "--vm-timeout",
        action="store",
        default=None,
        type=float,
        help="Timeout in seconds for waiting for RPC reply with VM (default: 30 s)",
    )
    parser.addini(
        "vm_timeout", "Default timeout for communication with VM etc.", default="30"
    )
    group.addoption(
        "--btmon",
        action="store_true",
        help="Launch btmon on all hosts to log events, and dump traffic to test-functional-*.btsnoop",
    )

    # host_plugins.Rcvbuf:
    parser.addini(
        "host_plugins.rcvbuf.default",
        "Set default SO_RCVBUF (/proc/sys/net/core/rmem_default) on hosts",
        default="1048576",
    )

    # Kernel build
    group.addoption(
        "--kernel-build",
        action="store",
        choices=("no", "use", "auto", "force"),
        nargs="?",
        default="use",
        const="auto",
        help="Build and cache a suitable kernel image if none given (no/use/auto/force)",
    )
    group.addoption(
        "--kernel-upstream",
        action="store",
        default=None,
        help="For building kernels: kernel upstream Git url",
    )
    group.addoption(
        "--kernel-branch",
        action="store",
        default=None,
        help="For building kernels: kernel upstream Git branch",
    )

    parser.addini(
        "kernel_upstream", "Kernel upstream Git url to use for building kernels"
    )
    parser.addini(
        "kernel_branch",
        "Kernel upstream Git branch /  commit to use for building custom kernel",
    )


def pytest_configure(config):
    if config.option.list:
        config.option.reportchars = "A"
        config.option.no_header = True
        config.option.verbose = -2

    if config.option.bluez_build_dir is not None:
        utils.BUILD_DIR = config.option.bluez_build_dir
    if config.option.bluez_src_dir is not None:
        utils.SRC_DIR = config.option.bluez_src_dir

    utils.DEFAULT_TIMEOUT = config.option.vm_timeout or float(
        config.getini("vm_timeout")
    )

    worker_id = os.environ.get("PYTEST_XDIST_WORKER")
    logfile = config.getini("log_file")
    if worker_id is not None and logfile:
        logfile = logfile.replace(".log", f"-{worker_id}.log")
        with open(logfile, "wb"):
            pass

        logging.basicConfig(
            format=config.getini("log_format"),
            filename=logfile,
            level=config.getini("log_file_level"),
        )

    if config.option.kernel_build == "force":
        config.option.kernel = _build_kernel(config)
    elif (
        config.option.kernel_build in ("auto", "use")
        and config.option.kernel is None
        and not os.environ.get("FUNCTIONAL_TESTING_KERNEL", None)
    ):
        cache_path = config.cache.mkdir("kernel")
        kernel = cache_path / "bzImage"

        if kernel.is_file():
            config.option.kernel = kernel
        elif config.option.kernel_build == "auto":
            config.option.kernel = _build_kernel(config)


def _build_kernel(config):
    cache_path = config.cache.mkdir("kernel")
    kernel = cache_path / "bzImage"

    upstream = config.getoption("kernel_upstream") or config.getini("kernel_upstream")
    branch = config.getoption("kernel_branch") or config.getini("kernel_branch")

    capturemanager = config.pluginmanager.getplugin("capturemanager")
    with capturemanager.global_and_fixture_disabled():
        print(f"\n\n=== Building kernel in {cache_path} ===\n")
        new_kernel = build_kernel.build_kernel(cache_path, upstream, branch)
        print(f"\n\n=== Kernel build done ===\n")

    os.rename(new_kernel, kernel)
    return kernel


COLLECT_ERRORS = []


def pytest_collectreport(report):
    if report.outcome != "passed":
        COLLECT_ERRORS.append((report.outcome, report.fspath))


def pytest_collection_finish(session):
    if session.config.option.list:
        regex = re.compile(r"\[.*")
        names = set(regex.sub("", item.nodeid) for item in session.items)
        for name in sorted(names):
            print(f"test/{name}")
        for outcome, name in COLLECT_ERRORS:
            print(f"{outcome.upper()} test/{name}")
        print()
        os._exit(0)


def _get_item_vm_host_setup(item):
    callspec = getattr(item, "callspec", None)
    if callspec is not None:
        return (
            callspec.params.get("vm_setup", None),
            callspec.params.get("host_setup", None),
        )
    return None, None


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(session, config, items):
    # Sort VM-using tests to minimize VM setup/teardown
    def sort_key(item):
        vm_setup, host_setup = _get_item_vm_host_setup(item)
        key = ()
        if vm_setup:
            key += tuple(sorted(vm_setup.items()))
        if host_setup:
            key += (host_setup["name"],)
        return key

    if not config.option.list:
        items.sort(key=sort_key)

    # Specify default groups for pytest-xdist --dist loadgroup
    if config.pluginmanager.has_plugin("xdist"):
        for item in items:
            if item.get_closest_marker("xdist_group") is not None:
                continue

            _, host_setup = _get_item_vm_host_setup(item)
            if not host_setup or not host_setup["reuse"]:
                continue

            xdist_group = "reuse-{}".format(host_setup["name"])
            item.add_marker(pytest.mark.xdist_group(xdist_group))


#
# Logging customization:
#
# - pattern-based log filtering
# - log entry reordering to timestamp order
# - logging test stages and outcomes to test log file
#


def pytest_sessionstart(session):
    _enable_log_filters(session.config)


def _enable_log_filters(config, handlers=None):
    if handlers is None:
        handlers = logging.root.handlers

    allow = set()
    deny = set()

    if config.option.log_filter is not None:
        for item in config.option.log_filter:
            for name in item.split(","):
                if name.startswith("+"):
                    allow.add(name[1:])
                elif name.startswith("-"):
                    deny.add(name[1:])
                else:
                    allow.add(name)

        utils.LogNameFilter.enable(handlers, allow, deny)

    if not config.option.no_log_reorder:
        utils.LogReorderFilter.enable(handlers)

    for handler in handlers:
        fmt = getattr(handler, "formatter", None)
        if hasattr(fmt, "add_color_level"):
            fmt.add_color_level(utils.OUT, "white")


def pytest_sessionfinish(session):
    utils.LogNameFilter.disable(logging.root.handlers)
    utils.LogReorderFilter.disable(logging.root.handlers)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_logstart(nodeid, location):
    utils.LogReorderFilter.flush_all()
    yield


def status_log_stage(name, stage):
    status_log.info(f"\n\n==== {name}: {stage} ====")

    try:
        yield
    except:
        utils.LogReorderFilter.flush_all()
        raise


@pytest.hookimpl(wrapper=True)
def pytest_runtest_setup(item):
    _enable_log_filters(item.session.config, logging.root.handlers[-1:])
    yield from status_log_stage(item.nodeid, "setup")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    yield from status_log_stage(item.nodeid, "call")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_teardown(item, nextitem):
    yield from status_log_stage(item.nodeid, "teardown")
    utils.LogReorderFilter.flush_all()


@pytest.hookimpl(wrapper=True)
def pytest_report_teststatus(report, config):
    if not isinstance(report, pytest.TestReport):
        return (yield)

    key = (report.nodeid, report.when)
    if key not in status_log_seen:
        status_log_seen.add(key)
        outcome = (
            report.outcome.upper() if report.when == "call" or report.failed else "done"
        )
        status_log.info(f"\n==== {report.nodeid}: {report.when} {outcome} ====\n")
        if report.failed:
            status_log.error(str(report.longrepr))
            for header, content in report.sections:
                if header.startswith("Captured log"):
                    continue
                status_log.error(f"--- {header} ---\n{content}")
                status_log.error(f"---")

    return (yield)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_logfinish(nodeid, location):
    utils.LogReorderFilter.flush_all()
    yield


#
# Fixtures
#


@pytest.fixture(scope="session")
def kernel(pytestconfig):
    """
    Fixture for kernel image. Skips tests if no kernel available.

    Yields:
        kernel (str): path to the kernel image
    """
    kernel = pytestconfig.getoption("kernel")

    if kernel is None:
        kernel = os.environ.get("FUNCTIONAL_TESTING_KERNEL")

    if not kernel:
        pytest.skip("No kernel image")

    if Path(kernel).is_dir():
        kernel = str(Path(kernel) / "arch" / "x86" / "boot" / "bzImage")

    if not Path(kernel).is_file():
        pytest.skip("no kernel image")

    return kernel


@pytest.fixture(scope="session")
def usb_indices(pytestconfig):
    """
    Fixture for available HW USB controllers. Skips tests if not available.

    Yields:
        usb_indices: list of usb controller names (hci0, hci1, ...)
        messages: error messages associated with each
    """
    usb_indices = pytestconfig.getoption("usb")

    if usb_indices is None:
        usb_indices = os.environ.get("FUNCTIONAL_TESTING_CONTROLLERS")

    if usb_indices is None:
        usb_indices = [item.name for item in Path("/sys/class/bluetooth").iterdir()]
    else:
        usb_indices = usb_indices.replace(",", " ").split()

    messages = []
    for name in list(usb_indices):
        subsys = Path("/sys/class/bluetooth") / name / "device" / "subsystem"
        if subsys.resolve() != Path("/sys/bus/usb"):
            usb_indices.remove(name)
            continue

        try:
            env.Environment.check_controller(name)
            messages.append("")
        except ValueError as exc:
            usb_indices.remove(name)
            messages.append(str(exc))

    return usb_indices, messages


@pytest.fixture(scope="session")
def host_setup(request):
    """
    Host setup configuration

    Yields:
        dict[setup: tuple[HostPlugin], name: str, reuse: bool]
    """
    if getattr(request, "param", None) is None:
        raise pytest.fail("host setup not specified")

    for plugins in request.param.get("setup", ()):
        for plugin in plugins:
            plugin.presetup(request.session.config)

    return request.param


@pytest.fixture(scope="session")
def vm_setup(request):
    """
    VM setup configuration

    Yields:
        (num_hosts: int, hw_controllers: bool)
    """
    if getattr(request, "param", None) is None:
        raise pytest.fail("env setup not specified")

    return request.param


def _vm_impl(request, kernel, num_hosts, hw):
    config = request.session.config

    if hw or config.option.force_usb:
        usb_indices, messages = request.getfixturevalue("usb_indices")
        if len(usb_indices) < num_hosts:
            message = "\n".join(m for m in messages[:num_hosts] if m)
            pytest.skip(reason=f"Not enough USB controllers: {message}")
    else:
        usb_indices = None

    with env.Environment(
        kernel, num_hosts, usb_indices=usb_indices, timeout=utils.DEFAULT_TIMEOUT
    ) as vm:
        yield vm

        _close_hosts(request, vm, vm.reuse_group)


def _hosts_impl(request, vm, setup, name, reuse):
    vm_timeout = utils.DEFAULT_TIMEOUT
    timeout = vm_timeout

    # Start VM if it was stopped
    if vm.path is None:
        vm.start()

    if not reuse or vm.reuse_group != name:
        _close_hosts(request, vm, vm.reuse_group)

    for idx, (h, plugins) in enumerate(zip(vm.hosts, setup)):
        timeout = max(vm_timeout * len(plugins) ** 0.5, timeout)

        h.set_instance_name(f"{name}.{idx}")

        if request.session.config.option.btmon:
            plugins = (Btmon(),) + plugins

        for p in plugins:
            h.start_load(p)

    for h in vm.hosts:
        h.wait_load(timeout=timeout)

    yield vm.hosts

    if not reuse:
        _close_hosts(request, vm, name)

    vm.reuse_group = name if reuse else None


def _close_hosts(request, vm, name):
    if name is None:
        return

    try:
        if request.session.config.option.btmon and name is not None:
            for h in vm.hosts:
                if hasattr(h, "btmon"):
                    h.btmon._call_noreply("teardown")
    finally:
        success = True
        try:
            vm.close_hosts()
        except:
            success = False
            raise
        finally:
            _copy_host_files(vm)

            # Stop VM if tester is not responding
            if not success:
                vm.stop()


def _copy_host_files(vm):
    for j, h in enumerate(vm.hosts):
        path = Path(h._path).parent / f"shared-{j}"
        for f in path.iterdir():
            if f.name.startswith("test-functional-"):
                shutil.copyfile(f, f.name)
                os.unlink(f)
                if f.name.endswith(".core"):
                    warnings.warn(f"Core dump: {f.name}")


@pytest.fixture(scope="package")
def vm(request, kernel, vm_setup):
    """
    Session-scope virtual machine fixture. Used internally by `hosts`.

    Yields:
        env.Environment
    """
    yield from _vm_impl(request, kernel, **vm_setup)


@pytest.fixture
def hosts(request, vm, host_setup):
    """
    Session-scope fixture that expands to a list of VM host proxies
    (`HostProxy`), with configuration as specified in `host_config`. The
    VM instances used may be reused by other tests.  The userspace test
    runner is torn down between tests.

    Example:

        def test_something(hosts):
            host0 = hosts[0]
            host1 = hosts[1]
    """
    yield from _hosts_impl(request, vm, **host_setup)


# Same with single-test scope:


@pytest.fixture
def vm_once(request, kernel, vm_setup):
    """
    Function-scope virtual machine fixture. Used internally by `hosts_once`.

    Yields:
        env.Environment
    """
    yield from _vm_impl(request, kernel, **vm_setup)


@pytest.fixture
def hosts_once(request, vm_module, host_setup):
    """
    Function-scope fixture. Same as `hosts`, but spawn separate VM
    instances for this test only.

    Example:

        def test_something(hosts_once):
            host0 = hosts_once[0]
            host1 = hosts_once[1]
    """
    yield from _hosts_impl(request, vm_module, **host_setup)

# -*- coding: utf-8; mode: python; eval: (blacken-mode); -*-
import os
import re
import logging
import fnmatch
import pytest
from pathlib import Path


def pytest_addoption(parser):
    parser.addoption(
        "--kernel",
        action="store",
        default=None,
        help=("Kernel image to use"),
    )
    parser.addoption(
        "--usb",
        action="store",
        default=None,
        help=("USB HCI devices to use, e.g. 'hci0,hci1'"),
    )
    parser.addoption(
        "--force-usb",
        action="store_true",
        default=None,
        help=("Force tests to run with USB controllers instead of btvirt"),
    )
    parser.addoption(
        "--build-dir",
        action="store",
        default=None,
        type=Path,
        help=("Build directory to find development binaries"),
    )
    parser.addoption(
        "--list",
        action="store_true",
        default=None,
        help=("List tests"),
    )
    parser.addoption(
        "--log-filter",
        action="append",
        default=None,
        help=(
            "Enable/disable loggers by name. Can be passed multiple times. Example: +host.0,-rpc"
        ),
    )
    parser.addoption(
        "--vm-timeout",
        action="store",
        default=20,
        type=float,
        help="Timeout in seconds for waiting for RPC reply with VM (default: 20 s)",
    )


def pytest_configure(config):
    from .lib import utils

    if config.option.build_dir is not None:
        utils.BUILD_DIR = config.option.build_dir


def pytest_report_collectionfinish(config, start_path, items):
    if config.option.list:
        print()
        for item in items:
            print(f"unit/{item.nodeid}")
        print()
        os._exit(0)


def pytest_collection_modifyitems(session, config, items):
    # Sort VM-using tests to minimize VM setup/teardown

    def sort_key(item):
        for m in item.own_markers:
            setup = item.callspec.params.get("vm_setup", None)
            if setup is not None:
                return tuple(sorted(setup.items()))
        return ()

    if not config.option.list:
        items.sort(key=sort_key)


def pytest_sessionstart(session):
    from .lib import utils

    config = session.config

    if config.option.log_filter is not None:
        allow = set()
        deny = set()
        for item in config.option.log_filter:
            for name in item.split(","):
                if name.startswith("+"):
                    allow.add(name[1:])
                elif name.startswith("-"):
                    deny.add(name[1:])
                else:
                    allow.add(name)

        filter = _LogFilter(allow, deny)

        for handler in logging.root.handlers:
            if any(type(f) == _LogFilter for f in handler.filters):
                continue

            handler.addFilter(filter)

    for handler in logging.root.handlers:
        fmt = getattr(handler, "formatter", None)
        if hasattr(fmt, "add_color_level"):
            fmt.add_color_level(utils.OUT, "yellow")


@pytest.fixture(autouse=True)
def setup_logging(pytestconfig, caplog):
    caplog.set_level(0)


class _LogFilter(logging.Filter):
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
        if self.allow is not None and self.allow.match(record.name):
            return True
        return self.allow is None


@pytest.fixture(scope="session")
def kernel(pytestconfig):
    """
    Fixture for kernel image
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
    Fixture for available USB controllers
    """
    from .lib import env

    usb_indices = pytestconfig.getoption("usb")

    if usb_indices is None:
        usb_indices = os.environ.get("FUNCTIONAL_TESTING_CONTROLLERS")

    if usb_indices is None:
        usb_indices = [item.name for item in Path("/sys/class/bluetooth").iterdir()]
    else:
        usb_indices = usb_indices.split(", ")

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
    if getattr(request, "param", None) is None:
        raise pytest.fail("host setup not specified")

    return request.param


@pytest.fixture(scope="session")
def vm_setup(request):
    if getattr(request, "param", None) is None:
        raise pytest.fail("env setup not specified")

    return request.param


def _vm_impl(request, kernel, num_hosts, hw):
    from .lib import Environment

    config = request.session.config

    if hw or config.option.force_usb:
        usb_indices, messages = request.getfixturevalue("usb_indices")
        if len(usb_indices) < num_hosts:
            message = "\n".join(m for m in messages[:num_hosts] if m)
            pytest.skip(reason=f"Not enough USB controllers: {message}")
    else:
        usb_indices = None

    with Environment(
        kernel, num_hosts, usb_indices=usb_indices, timeout=config.option.vm_timeout
    ) as vm:
        yield vm


def _hosts_impl(request, vm, setup):
    from .lib import Bdaddr, Call

    for h, plugins in zip(vm.hosts, setup):
        for p in plugins:
            h.start_load(p)

    for h in vm.hosts:
        h.wait_load()

    yield vm.hosts

    for h in vm.hosts:
        h.close()


@pytest.fixture(scope="package")
def vm(request, kernel, vm_setup):
    yield from _vm_impl(request, kernel, **vm_setup)


@pytest.fixture
def hosts(request, vm, host_setup):
    yield from _hosts_impl(request, vm, **host_setup)


# Same with single-test scope:


@pytest.fixture
def vm_once(request, kernel, vm_setup):
    yield from _vm_impl(request, kernel, **vm_setup)


@pytest.fixture
def hosts_once(request, vm_module, host_setup):
    yield from _hosts_impl(request, vm_module, **host_setup)

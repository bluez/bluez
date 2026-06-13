===============
test-functional
===============

**test-functional** [*OPTIONS*]

DESCRIPTION
===========

**test-functional(1)** is used for functional testing of BlueZ and
kernel using multiple virtual machine environments, connected by real
or virtual controllers.

It uses https://pypi.org/project/pytest-bluezenv as VM-based test
framework. For details, see its documentation.

QUICK EXAMPLE
=============

Install `qemu-system-x86_64` first. Then,

.. code-block::

   $ ./configure --enable-functional-testing --enable-testing --enable-tools
   $ make -j8
   $ python3 -mpip install -r test/functional/requirements.txt
   $ test/test-functional --kernel-build -v

OPTIONS
=======

The `test-functional` script simply runs `Pytest
<https://pytest.org>`__ which can take the following options:
https://docs.pytest.org/en/stable/reference/reference.html#command-line-flags

The following additional options apply:

``--list``
	Output brief lists of existing tests.

``--kernel=<image>``
        Kernel image (or built Linux source tree root) to
	use.  See **test-runner(1)** and `tester.config` for required
	kernel config.

	If not provided, value from `FUNCTIONAL_TESTING_KERNEL`
	environment variable is used. If none, no image is used.

``--usb=hci0,hci1``
        USB controllers to use in tests that require use of
	real controllers.

	If not provided, value from `FUNCTIONAL_TESTING_CONTROLLERS`
	environment variable is used. If none, all USB controllers
	with suitable permissions are considered.

``--force-usb``
        Force tests to use USB controllers instead of `btvirt`.

``--bluez-build-dir=<path>``
        Path to build directory where to search for BlueZ
        executables.

``--bluez-src-dir=<path>``
        Path to build BlueZ source directory.

``--log-filter=[+-]<pattern>,[+-]<pattern>,...``
        Allow/deny lists
	for filtering logging output. The pattern is a shell glob matching
	to the logger names.

``--no-log-reorder``
	Don't reorder logs to timestamp order.

``--vm-timeout=<seconds>``
        Specify timeout for communication with VM hosts.

``--btmon``
        Launch btmon on all hosts to log events, and dump traffic to
	test-bluezenv-\*.btsnoop

``--kernel-build=no/use/auto/force``
        Build a suitable kernel image from source.

``--kernel-upstream=<GIT_URL>``
        URL for Git clone of kernel sources.

``--kernel-branch=<GIT_BRANCH>``
        Git branch to build from.


Tests that require kernel image or USB controllers are skipped if none
are available. Normally, tests use `btvirt`.

VM instances share a directory ``/run/shared`` with host machine,
located on host usually in ``/tmp/bluez-func-test-*/shared-*``.  Core
dumps etc. are copied out from it before test instance is shut down.

REQUIREMENTS
============

General
-------

The following are needed:

- QEmu (x86_64)
- ``dbus-daemon`` available

Recommended:

- KVM-enabled x86_64 host system
- Preferably built BlueZ source tree
- ``chronyd`` available
- ``util-linux`` tools available
- ``agetty`` available

Python
------

The following Python packages are required:

.. code-block::

	pytest>=8
	pytest-bluezenv==0.1.6

To install them via pip::

	python3 -m pip install -r test/functional/requirements.txt

On Fedora / RHEL, the dependencies aside from `pytest-bluezenv` can be
installed via::

	sudo dnf install python3-pytest python3-pexpect python3-dbus

Kernel
------

The **test-functional(1)** tool requires a kernel image with similar
config as **test-runner(1)**.  If given `--kernel-build` option, a
suitable image is built from sources downloaded under
`test/.pytest_cache`.

Simplest setup is

.. code-block::

	cp ../bluez/doc/tester.config .config
	make olddefconfig
	make -j8

To get log timestamps right, the kernel should have the following
configuration enabled:

.. code-block::

	CONFIG_HYPERVISOR_GUEST=y
	CONFIG_PARAVIRT=y
	CONFIG_KVM_GUEST=y

	CONFIG_PTP_1588_CLOCK=y
	CONFIG_PTP_1588_CLOCK_KVM=y
	CONFIG_PTP_1588_CLOCK_VMCLOCK=y

USB
---

Some tests may require a hardware controller instead of the virtual `btvirt` one.

EXAMPLES
========

Run all tests
-------------

.. code-block::

	$ test/test-functional --kernel=/pathto/bzImage

	$ export FUNCTIONAL_TESTING_KERNEL=/pathto/bzImage
	$ test/test-functional

Test output is logged in ``test-functional.log``.

Show output during run
----------------------

.. code-block::

	$ test/test-functional --log-cli-level=0

Show only specific loggers:

.. code-block::

	$ test/test-functional --log-cli-level=0 --log-filter=rpc,host

	$ test/test-functional --log-cli-level=0 --log-filter=*.bluetoothctl

Filter out loggers:

.. code-block::

	$ test/test-functional --log-cli-level=0 --log-filter=-host

	$ test/test-functional --log-cli-level=0 --log-filter=host,-host.*.1

Run selected tests
------------------

.. code-block::

	$ test/test-functional test/functional/test_cli_simple.py::test_bluetoothctl_script_show

	$ test/test-functional -k test_bluetoothctl_script_show

	$ test/test-functional -k 'test_btmgmt or test_bluetoothctl'

Don't run tests with a given marker:

.. code-block::

	$ test/test-functional -m "not pipewire"

Don't run known-failing tests:

.. code-block::

	$ test/test-functional -m "not xfail"

Note that otherwise known-failing tests would be run, but with
failures suppressed.

Run previously failed and stop on failure
-----------------------------------------

.. code-block::

	$ test/test-functional -x --ff

List all tests
--------------

.. code-block::

	$ test/test-functional --list

Show errors from know-failing test
----------------------------------

.. code-block::

	$ test/test-functional --runxfail -k test_btmgmt_info

Redirect USB devices
--------------------

.. code-block::

	$ test/test-functional --usb=hci0,hci1

	$ export FUNCTIONAL_TESTING_CONTROLLERS=hci0,hci1
	$ test/test-functional -vv

This does not require running as root. Changing device permissions is
sufficient. In verbose mode (``-vv``) some instructions are printed.

Run all tests using the USB controllers:

.. code-block::

	$ test/test-functional --usb=hci0,hci1 --force-usb

Run tests in parallel
---------------------

pytest-xdist is required for parallel execution. To run:

.. code-block::

	$ test/test-functional -n auto --dist loadgroup

Logging in to a test VM instance
--------------------------------

While test is running:

.. code-block::

	$ test/test-functional-attach

For this to be useful, usually, you need to pause the test
e.g. by running with ``--trace`` option.

To do it manually, when starting the tester will log a line like::

	TTY: socat /tmp/bluez-func-test-q658swgi/bluez-func-test-tty-0 STDIO,rawer

with the location of the socket where the serial is connected to.

WRITING TESTS
=============

The functional tests are written in files (test modules) names
`test/functional/test_*.py`.  They are written using standard Pytest
style.  See https://docs.pytest.org/en/stable/getting-started.html

See https://pypi.org/project/pytest-bluezenv/ for documentation of
how to write VM-using tests.

Use `Black <https://black.readthedocs.io/en/stable/>`__ to autoformat
Python test code.

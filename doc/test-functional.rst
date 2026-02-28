===============
test-functional
===============

**test-functional** [*OPTIONS*]

DESCRIPTION
===========

**test-functional(1)** is used for functional testing of BlueZ and
kernel using multiple virtual machine environments, connected by real
or virtual controllers.

OPTIONS
=======

The `test-functional` script simply runs `Pytest
<https://pytest.org>`__ which can take the following options:
https://docs.pytest.org/en/stable/reference/reference.html#command-line-flags

The following additional options apply:

:--kernel=<image>: Kernel image (or built Linux source tree root) to
	use.  See **test-runner(1)** and `tester.config` for required
	kernel config.

	If not provided, value from `FUNCTIONAL_TESTING_KERNEL`
	environment variable is used. If none, no image is used.

:--usb=hci0,hci1: USB controllers to use in tests that require use of
	real controllers.

	If not provided, value from `FUNCTIONAL_TESTING_CONTROLLERS`
	environment variable is used. If none, all USB controllers
	with suitable permissions are considered.

:--force-usb: Force tests to use USB controllers instead of `btvirt`.

:--vm-timeout=<seconds>: Specify timeout for communication with VM hosts.

:--log-filter=[+-]<pattern>,[+-]<pattern>,...: Allow/deny lists
	for filtering logging output. The pattern is a shell glob matching
	to the logger names.

:--build-dir=<path>: Path to build directory where to search for BlueZ
        executables.

:--list: Output brief lists of existing tests.

Tests that require kernel image or USB controllers are skipped if none
are available. Normally, tests use `btvirt`.


REQUIREMENTS
============

Python
------

The following Python packages are required:

.. code-block::

   pytest
   pexpect
   dbus-python

To install them via pip::

	python3 -m pip install -r unit/func_test/requirements.txt

On Fedora / RHEL::

	sudo dnf install python3-pytest python3-pexpect python3-dbus


Kernel
------

The **test-functional(1)** tool requires a kernel image with similar
config as **test-runner(1)**.  Simplest setup is

.. code-block::

	cp ../bluez/doc/tester.config .config
	make olddefconfig
	make -j8

USB
---

Some tests may require a hardware controller instead of the virtual `btvirt` one.


EXAMPLES
========

Run all tests
-------------

.. code-block::

	$ unit/test-functional --kernel=/pathto/bzImage

	$ export FUNCTIONAL_TESTING_KERNEL=/pathto/bzImage
	$ unit/test-functional

Show output during run
----------------------

.. code-block::

	$ unit/test-functional --log-cli-level=0

Show only specific loggers:

.. code-block::

	$ unit/test-functional --log-cli-level=0 --log-filter=rpc,host

	$ unit/test-functional --log-cli-level=0 --log-filter=*.bluetoothctl

Filter out loggers:

.. code-block::

	$ unit/test-functional --log-cli-level=0 --log-filter=-host

	$ unit/test-functional --log-cli-level=0 --log-filter=host,-host.*.1

Run selected tests
------------------

.. code-block::

	$ unit/test-functional unit/func_test/test_cli_simple.py::test_bluetoothctl_script_show

	$ unit/test-functional -k test_bluetoothctl_script_show

	$ unit/test-functional -k 'test_btmgmt or test_bluetoothctl'

Don't run tests with a given marker:

.. code-block::

	$ unit/test-functional -m "not pipewire"

Don't run known-failing tests:

.. code-block::

	$ unit/test-functional -m "not xfail"

Note that otherwise known-failing tests would be run, but with
failures suppressed.

Run previously failed and stop on failure
-----------------------------------------

.. code-block::

	$ unit/test-functional -x --ff

List all tests
--------------

.. code-block::

	$ unit/test-functional --list

Show errors from know-failing test
----------------------------------

.. code-block::

	$ unit/test-functional --runxfail -k test_btmgmt_info

Redirect USB devices
--------------------

.. code-block::

	$ unit/test-functional --usb=hci0,hci1

	$ export FUNCTIONAL_TESTING_CONTROLLERS=hci0,hci1
	$ unit/test-functional


WRITING TESTS
=============

The functional tests are written in files (test modules) names
`unit/func_test/test_*.py`.  They are written using standard Pytest
style.  See https://docs.pytest.org/en/stable/getting-started.html

Example: Virtual machines
-------------------------

.. code-block:: python

   from .lib import host_config, Bluetoothd, Bluetoothctl

   @host_config(
       [Bluetoothd(), Bluetoothctl()],
       [Bluetoothd(), Bluetoothctl()],
   )
   def test_bluetoothctl_pair(hosts):
       host0, host1 = hosts

       host0.bluetoothctl.send("show\n")
       host0.bluetoothctl.expect("Powered: yes")

       host1.bluetoothctl.send("show\n")
       host1.bluetoothctl.expect("Powered: yes")

       host0.bluetoothctl.send("scan on\n")
       host0.bluetoothctl.expect(f"Controller {host0.bdaddr.upper()} Discovering: yes")

       host1.bluetoothctl.send("pairable on\n")
       host1.bluetoothctl.expect("Changing pairable on succeeded")
       host1.bluetoothctl.send("discoverable on\n")
       host1.bluetoothctl.expect(f"Controller {host1.bdaddr.upper()} Discoverable: yes")

       host0.bluetoothctl.expect(f"Device {host1.bdaddr.upper()}")
       host0.bluetoothctl.send(f"pair {host1.bdaddr}\n")

       idx, m = host0.bluetoothctl.expect(r"Confirm passkey (\d+).*:")
       key = m[0].decode("utf-8")

       host1.bluetoothctl.expect(f"Confirm passkey {key}")

       host0.bluetoothctl.send("yes\n")
       host1.bluetoothctl.send("yes\n")

       host0.bluetoothctl.expect("Pairing successful")

The test declares a VM setup with two Qemu instances, where both hosts
run bluetoothd and start a bluetoothctl process.  The Qemu instances
have `btvirt` virtual BT controllers and can see each other.

The test itself runs on the parent host.

The `host0/1.bluetoothctl.*` commands invoke RPC calls to one of the
the two VM instances. In this case, they are controlling the
`bluetoothctl` process using `pexpect` library to deal with its
command line.

When the test body finishes executing, the test passes. Or, it fails
if any ``assert`` statement fails or an error is raised. For example,
above ``RemoteError`` due to bluetoothctl not proceeding as expected
in pairing is possible.

The host configuration (bluetoothd + bluetoothctl above) is torn down
between test (SIGTERM/SIGKILL sent etc.).

By default the VM instance itself continues running, and may be used
for other tests that share the same VM setup.

Generally, the framework automatically orders the tests so that the VM
setup does not need to be restarted unless needed.


Example host plugin
-------------------

The `host.bluetoothctl` implementation used above is as follows:

.. code-block:: python

   from .lib import HostPlugin

   class Bluetoothctl(HostPlugin):
       # Declare a unique name:

       name = "bluetoothctl"

       # Declare dependencies on other plugins

       depends = [Bluetoothd()]

       # The following is to be run on parent host outside VMs:

       def __init__(self):
           self.exe = utils.find_exe("client", "bluetoothctl")

       # These run inside VM on plugin setup / teardown:

       def setup(self, impl):
           self.logger = utils.LogStream("bluetoothctl")
           self.ctl = pexpect.spawn(self.exe, logfile=self.logger.stream)

       def teardown(self):
           self.ctl.terminate()
           self.ctl.wait()

       # These declare the custom RPC-callable methods of the plugin:

       def expect(self, *a, **kw):
           ret = self.ctl.expect(*a, **kw)
           log.debug("pexpect: found")
           return ret, self.ctl.match.groups()

       def expect_prompt(self):
           prompt = "\\[[a-zA-Z0-9. -]+\\]>"
           return self.expect(prompt)

       def send(self, *a, **kw):
           return self.ctl.send(*a, **kw)

Host plugins are for injecting code to run on the VM side test hosts.
The host plugins have scope of one test.  The VM side test framework
sends SIGTERM and SIGKILL to all processes in the test process group
to reset the state between each test.

The plugins are declared by inheriting from `HostPlugin`. Their
`__init__()` is supposed to only store declarative configuration on
`self` and runs on parent side early in the test discovery phase. The
`setup()` and `teardown()` methods run on VM-side at host environment
start and end.  All other methods can be invoked via RPC by the parent
tester, and any values returned by them are passed via RPC back to the
parent.

To load a plugin to a VM host, pass it to `host_config()` in the
declaration of a given test.

Reference
---------

In addition to standard Pytest features, the following items are
available in the `.lib` submodule.

TODO: not complete

host_config
~~~~~~~~~~~

.. code-block::

   def host_config(*host_setup, hw=False)

Declare host configuration.

- \*host_setup: each argument is a list of plugins to be loaded on a host.
  The number of arguments specifies the number of hosts.

- hw (bool): whether to require hardware BT controller

find_exe
~~~~~~~~

.. code-block::

   from .lib import find_exe
   bluetoothctl = find_exe("client", "bluetoothctl")

Find absolute path to the given executable, either within BlueZ build
directory or on host.

RemoteError
~~~~~~~~~~~

.. code-block::

   from .lib import RemoteError

   try:
       host.call(foo)
   except RemoteError as exc:
       print("    ".join(exc.traceback))
       original_exception = exc.exc

Exception raised on the VM side, passed through RPC. Properties:
`traceback` is a list of traceback lines and `exc` is the original
exception instance raised on the remote side.

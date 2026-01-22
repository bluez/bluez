=====
btmon
=====

-----------------
Bluetooth monitor
-----------------

:Authors: - Marcel Holtmann <marcel@holtmann.org>
          - Tedd Ho-Jeong An <tedd.an@intel.com>
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Version: BlueZ
:Date: April 2021
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**btmon** [*OPTIONS* ...]

DESCRIPTION
===========

The  btmon(1) command  provides  access  to the Bluetooth subsystem monitor
infrastructure for reading HCI traces.

OPTIONS
=======

-r FILE, --read FILE        Read traces in btsnoop format from *FILE*.
-w FILE, --write FILE       Save traces in btsnoop format to *FILE*.
-a FILE, --analyze FILE     Analyze traces in btsnoop format from *FILE*.
                            It displays the devices found in the *FILE* with
			    its packets by type. If gnuplot is installed on
			    the system it also attempts to plot packet latency
			    graph.
-s SOCKET, --server SOCKET  Start monitor server socket.
-p PRIORITY, --priority PRIORITY  Show only priority or lower for user log.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1

   * - *PRIORITY*
     - NAME

   * - **3**
     - Error

   * - **4**
     - Warning

   * - **6**
     - Information (Default)

   * - **7**
     - Debug. **debug** can be used.

-i NUM, --index NUM         Show only specified controller. *hciNUM* is also
                            acceptable. This is useful to capture the traces
                            from the specific controller when the multiple
                            controllers are presented.

-d TTY, --tty TTY           Read data from *TTY*.

-B SPEED, --rate SPEED      Set TTY speed. The default *SPEED* is 115300

-V COMPID, --vendor COMPID  Set the default company identifier. The *COMPID* is
                            a unique number assigned by the Bluetooth SIG to
                            a member company and can be found/searched from the
                            Bluetooth SIG webpage.

                            For example, Intel is 2 and Realtek is 93.

-M, --mgmt                  Open channel for mgmt events.

-K, --kernel                Open kmsg for kernel messages.

-t, --time                  Show a time instead of time offset.

-T, --date                  Show a time and date information instead of
                            time offset.

-S, --sco                   Dump SCO traffic in raw hex format.

-A, --a2dp                  Dump A2DP stream traffic in a raw hex format.

-E IP, --ellisys IP         Send Ellisys HCI Injection.

-P, --no-pager              Disable pager usage while reading the log file.

-J OPTIONS, --jlink OPTIONS     Read data from RTT.  Each options are comma(,)
                                separated without spaces.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1

   * - *OPTIONS*
     - Description

   * - **DEVICE**
     - Required. Set the target device.

   * - **SERIALNO**
     - (Optional) Set the USB serial number. Default is **0**.

   * - **INTERFACE**
     - (Optional) Target interface. Default is **swd**.

   * - **SPEED**
     - (Optional) Set target interface speed in kHz. Default is **1000**.

-R OPTIONS, --rtt OPTIONS   RTT control block parameters. Each options are
                            comma(,) separated without spaces.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1

   * - *OPTIONS*
     - Description

   * - **ADDRESS**
     - (Optional) Address of RTT buffer. Default is **0x00**

   * - **AREA**
     - (Optional) Size of range to search in RTT buffer. Default is **0**

   * - **NAME**
     - (Optional) Buffer name. Default is **btmonitor**

-C WIDTH, --columns WIDTH   Output width if not a terminal

-c MODE, --color MODE       Set output color. The possible *MODE* values are:
                            **auto|always|never**.

                            Default value is **auto**

-v, --version               Show version

-h, --help                  Show help options

EXAMPLES
========

Capture the traces from hci0 to hcidump.log file
------------------------------------------------

.. code-block::

   $ btmon -i hci0 -w hcidump.log

Open the trace file
-------------------

.. code-block::

   $ btmon -r hcidump.log


RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

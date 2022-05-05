=======
isotest
=======

-----------
ISO testing
-----------

:Authors: - Luiz Augusto Von Dentz <luiz.von.dentz@intel.com>
:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: May 4, 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**isotest** <*MODE*> [*OPTIONS*] [*bdaddr*] [*bdaddr1*]...

DESCRIPTION
===========

**isotest(1)** is used to test Isochronous (CIS/BIS) communications on the
BlueZ stack

MODES
=====

-d, --dump=[FILE]        Listen and dump incoming data
                         (CIS server/BIS broadcaster) and optionally save the
			 contents to *FILE*.

-c, --reconnect          Reconnect (CIS client).

-m, --multiple           Multiple connects (CIS client).

-r, --receive=[FILE]     Receive (CIS server/BIS broadcast receiver) and
                         optionally save the contents to *FILE*.

-s, --send=[FILE]        Connect and send (CIS client/BIS broadcaster), can
                         optionally use contents from *FILE*.

-n, --silent             Connect and be silent (CIS client/BIS broadcaster).

OPTIONS
=======

-b, --bytes=<SIZE>      Send or Receive packet size

-i, --index=<NUM>        Select the specified HCI device index. *hciNUM* is
                         also acceptable.

-j, --jitter=<JITTER>    Socket jitter buffer.

-h, --help

-q, --quiet              Disables packet logging.

-t, --timeout=<USEC>     Socket send timeout.

-C, --continue           Continuously send packets starting over in case of a
                         file.

-W, --defer=<SEC>        Enable deferred setup.

-M, --mtu=<SDU>          Socket QoS SDU.

-S, --sca/adv-interval=<SCA/INTERVAL>
                         Socket QoS CIS SCA/BIS advertising interval.

-P, --packing=<PACKING>  Socket QoS Packing.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1
   :align: left

   * - *PACKING*
     - Description

   * - **0x00**
     - Sequential

   * - **0x01**
     - Interleaved

-F, --framing=<FRAMING>  Socket QoS Framing.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1
   :align: left

   * - *FRAMING*
     - Description

   * - **0x00**
     - Unframed

   * - **0x01**
     - Framed

-I, --interval=<USEC>    Socket QoS Interval.

-L, --latency=<MSEC>     Socket QoS Latency.

-Y, --phy=<PHY>          Socket QoS PHY.

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1
   :align: left

   * - *PHY*
     - Description

   * - **0x01**
     - LE 1M

   * - **0x02**
     - LE 2M

   * - **0x03**
     - LE Coded

-R, --rtn=<NUM>          Socket QoS retransmissions.

-B, --preset=<PRESET>    Socket QoS preset.

-G, --CIG/BIG=<ID>       Socket QoS CIG/BIG ID.

-T, --CIS/BIS=<ID>       Socket QoS CIS/BIS ID.

-V, --type=<TYPE>        Socket destination address type:

.. list-table::
   :header-rows: 1
   :widths: auto
   :stub-columns: 1
   :align: left

   * - *TYPE*
     - Description

   * - **le_public**
     - LE Public Address

   * - **le_random**
     - LE Random Address

EXAMPLES
========

Unicast Central
---------------

.. code-block::

    $ tools/isotest -s XX:XX:XX:XX:XX:XX

Unicast Central connecting to 2 peers using CIG 0x01
----------------------------------------------------

.. code-block::

    $ tools/isotest -G 0x01 -s XX:XX:XX:XX:XX:XX YY:YY:YY:YY:YY:YY

Unicast Peripheral
------------------

.. code-block::

    $ tools/isotest -d

Broadcaster
-----------

.. code-block::

    $ tools/isotest -s 00:00:00:00:00:00

Broadcast Receiver using hci1
-----------------------------

.. code-block::

    $ tools/isotest -i hci1 -d XX:XX:XX:XX:XX:XX

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

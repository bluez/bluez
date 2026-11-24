================
functional-avrcp
================

DESCRIPTION
===========

AVRCP functional tests, `test/functional/test_avrcp.py`. See
**functional-testing(7)** for the conventions used here, and
**test-functional(1)** for how to run the suite.

SETUP
=====

Two hosts, connected over BR/EDR:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |     BR/EDR      | host1                  |
	| victim                 | --------------> | attacker               |
	| bluetoothd             |                 | bluetoothd -P avrcp    |
	| AVRCP Controller       |  AVCTP PSM 0x17 | malicious AVRCP Target |
	|                        | <============== | (org.bluez.Profile1)   |
	+------------------------+                 +------------------------+

	--> connection is initiated by      ==> malicious response is sent by

TEST CASES
==========

test_avrcp_GHSA_m2vx_pw5f_rc8v
------------------------------

:Setup: Two hosts paired over BR/EDR. host1 runs `bluetoothd` with the
	`avrcp` plugin and registers a malicious AVRCP Target through
	``org.bluez.ProfileManager1``: a server role profile on the AVCTP
	PSM (0x17) with its own SDP record, which receives the accepted
	AVCTP file descriptor through ``Profile1.NewConnection``.

:Steps:
	1. host0 connects the AVRCP Controller UUID
	   (``0000110c-0000-1000-8000-00805f9b34fb``) with
	   ``org.bluez.Device1.ConnectProfile``.
	2. The AVRCP Target answers ``GetCapabilities``, and answers
	   ``ListPlayerAttributes`` with an attribute count of 255.
	3. host0 calls ``org.bluez.Device1.Disconnect``.

:Expected:
	1. ``ConnectProfile`` replies.
	2. The target reports that it answered
	   ``ListPlayerAttributes``.
	3. `bluetoothd` on host0 has not crashed and still answers D-Bus,
	   so ``Disconnect`` replies.

:Notes: Regression test for NN-2026-0145. The response is parsed by
	``avrcp_list_player_attributes_rsp()``
	(`profiles/audio/avrcp.c`), which collects the attributes into a
	buffer of ``AVRCP_ATTRIBUTE_LAST`` bytes without bounding the
	count, and then passes that count to
	``avrcp_get_current_player_value()``, which copies it into a
	similarly sized buffer. With 255 valid attributes both overflow.

	Marked ``sa``.

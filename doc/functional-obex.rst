===============
functional-obex
===============

DESCRIPTION
===========

OBEX functional tests, `test/functional/test_obex.py`. See
**functional-testing(7)** for the conventions used here, and
**test-functional(1)** for how to run the suite.

SETUP
=====

Two hosts, connected over BR/EDR:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |     BR/EDR      | host1                  |
	| FTP client             | --------------> | FTP server             |
	| bluetoothd, obexd      |                 | bluetoothd, obexd      |
	| org.bluez.obex client, |    OBEX FTP     | OBEX agent,            |
	| or obexctl             | <============== | files in /run/obex     |
	+------------------------+                 +------------------------+

	--> connection is initiated by      ==> files are transferred towards

Two hosts paired over BR/EDR, both running `obexd`:

host0
	Acts as File Transfer client, through the **org.bluez.obex** API
	or through **obexctl(1)**.

host1
	Acts as server, with an OBEX agent registered, and serves the
	files in ``/run/obex``.

The session is created with
``org.bluez.obex.Client1.CreateSession`` using the ``ftp`` target,
which the agent of host1 has to authorize.

TEST CASES
==========

test_obex_ftp_list
------------------

:Setup: As above.

:Steps:
	1. Create the FTP session from host0 and authorize it on host1.
	2. Write a file named ``test`` with 4 bytes of content on host1.
	3. host0 calls
	   ``org.bluez.obex.FileTransfer1.ListFolder``.

:Expected:
	1. host1 receives ``org.bluez.Agent1.AuthorizeService`` for the
	   FTP UUID, and ``CreateSession`` replies.
	2. ``ListFolder`` returns a single entry, with ``Type`` ``file``,
	   ``Name`` ``test`` and ``Size`` 4.

test_obex_ftp_get
-----------------

:Setup: As above.

:Steps:
	1. Write a file named ``test`` with the content ``1234`` on host1.
	2. host0 calls ``org.bluez.obex.FileTransfer1.GetFile``.

:Expected:
	1. The transfer object reaches ``Status`` ``complete``, tracked
	   through ``PropertiesChanged`` on the
	   ``org.bluez.obex.Transfer1`` object.
	2. The received file has the content ``1234``.

test_obexctl_list
-----------------

:Setup: As above, with the client driven through **obexctl(1)**.

:Steps:
	1. host0: ``connect <host1 bdaddr> <FTP UUID>``.
	2. host1 authorizes the service.
	3. host0: ``select <session>`` then ``ls``.

:Expected:
	1. ``Connection successful``.
	2. ``ls`` prints ``Type: file``, ``Name: test`` and ``Size: 4``.

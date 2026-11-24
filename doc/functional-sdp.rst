==============
functional-sdp
==============

DESCRIPTION
===========

SDP client functional tests, `test/functional/test_sdp.py`,
`test/functional/test_sdp_out_of_range.py` and
`test/functional/test_sdp_cache.py`, covering the service discovery of
**bluetoothd(8)** over BR/EDR and the SDP records it caches. See
**functional-testing(7)** for the conventions used here, and
**test-functional(1)** for how to run the suite.

SETUP
=====

Two hosts, connected over BR/EDR. host0 runs **bluetoothd(8)** with an
agent. host1 runs no bluetoothd: `btmgmt` makes it connectable and
discoverable, and it answers SDP on PSM 1 itself:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |      BR/EDR     | host1                  |
	| bluetoothd, agent      | --------------> | SDP server, PSM 1      |
	| discovers, browses     |                 | no bluetoothd          |
	+------------------------+                 +------------------------+

	--> connection is initiated by

host0 discovers the services of host1 as follows:

1. host0 calls ``org.bluez.Adapter1.StartDiscovery`` until it has a
   device object for host1, then ``StopDiscovery``.
2. host0 sets ``Trusted`` on it, as bluetoothd only keeps a device that
   is paired or trusted once its link is lost.
3. host0 calls ``org.bluez.Device1.Connect``, which browses the SDP
   records of host1 with a Service Search Attribute request for the
   L2CAP UUID, and then one for the PnP Information UUID. ``Connect``
   returns an error, as host1 offers no service to connect.

bluetoothd caches the records in the ``ServiceRecords`` group of the
cache file of host1, using their handle as key (see
`doc/settings-storage.txt`). A record without the ServiceRecordHandle
attribute has no handle, so bluetoothd chooses a key for it.

The tests in `test_sdp_cache.py` have host1 return these records:

A, B, C, E
	Records of the service classes 0x7001, 0x7002, 0x7003 and 0x7005,
	which no profile of bluetoothd handles, as ``Connect`` only
	discovers the services of a known device again if it finds no
	service to connect. Returned for the L2CAP search, without handle
	unless a test says otherwise.

D
	A PnP Information record without handle, returned for the PnP
	Information search unless a test says otherwise.

A changed record is the same record with attribute 0x0200 set to
another value.

Unless a test says otherwise, it checks that the cache holds exactly
the records named, each of them once, that every key is ``0x``
followed by 8 uppercase hexadecimal digits, and that a record with a
handle is cached under it.

Some tests run **bluetoothd(8)** with ``Experimental = true``, for
``org.bluez.Device1.GetServiceRecords``, which returns the records
bluetoothd has in memory. host1 connects to host0 first, as the method
requires a connected device, which does not make host0 discover its
services again.

TEST CASES
==========

test_sdp_records_without_handle[switch2]
----------------------------------------

:Setup: As above, host1 answers with the records of a Nintendo Switch
	2, none of which has the ServiceRecordHandle attribute: Audio
	Source, A/V Remote Control and A/V Remote Control Target for the
	L2CAP search, and PnP Information for the PnP Information search.

:Steps:
	1. host0 calls ``org.bluez.Adapter1.StartDiscovery`` until it has a
	   device object for host1, then ``StopDiscovery``.
	2. host0 calls ``org.bluez.Device1.Connect``.
	3. Wait until ``org.bluez.Device1.UUIDs`` of host1 contains the
	   Audio Source UUID of its first record.

:Expected:
	1. ``UUIDs`` also contains the A/V Remote Control Target, A/V
	   Remote Control and PnP Information UUIDs of the other records.
	2. host1 sent the PnP Information record in its second response
	   only.
	3. The cache holds each of the 4 records once.

:Notes: Skipped if `btmgmt` is not built.

test_sdp_records_without_handle[duplicate]
------------------------------------------

:Setup: As above, but host1 also returns the PnP Information record
	for the L2CAP search.

:Steps: As above.

:Expected: As above, except host1 sent the PnP Information record in
	both responses. It is cached once.

test_sdp_new_without_handle_down_before_second_response
-------------------------------------------------------

:Setup: As for test_sdp_records_without_handle[switch2], except host1
	goes out of range when it receives the second request: it stops
	page scan, disconnects with the reason Connection Timeout and
	powers off.

:Steps: host0 discovers the services of host1.

:Expected:
	1. ``Connect`` returns ``br-connection-create-socket``.
	2. ``UUIDs`` of host1 is empty, as the discovery did not complete.
	3. The cache holds the 3 records of the first search.

:Notes: btvirt has no link supervision timeout, so host1 disconnects
	with that reason itself, which btvirt passes on to host0 as it is.

test_sdp_cache_same_record_twice
--------------------------------

:Setup: As above, host1 returns A, A and C for the L2CAP search.

:Steps: host0 discovers the services of host1.

:Expected: The cache holds A, C and D.

test_sdp_cache_in_memory_after_discovery
----------------------------------------

:Setup: As above, with ``Experimental = true``. host1 returns A, B and
	C.

:Steps:
	1. host0 discovers the services of host1.
	2. host1 connects to host0, and host0 calls
	   ``org.bluez.Device1.GetServiceRecords``.

:Expected: ``GetServiceRecords`` returns A, B, C and D, each once.

test_sdp_cache_in_memory_after_rediscovery
------------------------------------------

:Setup: As above, with ``Experimental = true``.

:Steps:
	1. host0 discovers the services of host1, which returns A, B and
	   C.
	2. host0 discovers them again, host1 returning A and C.
	3. host1 connects to host0, and host0 calls
	   ``org.bluez.Device1.GetServiceRecords``.

:Expected:
	1. ``GetServiceRecords`` returns A, C and D, each once.
	2. The cache holds A, B, C and D.

test_sdp_cache_same_records
---------------------------

:Setup: As above.

:Steps: host0 discovers the services of host1 twice, host1 returning
	A, B and C both times.

:Expected: The cache holds A, B, C and D, each under the key it had
	after the first discovery.

test_sdp_cache_records_in_other_order
-------------------------------------

:Setup: As above.

:Steps: As for test_sdp_cache_same_records, except host1 returns C, A
	and B the second time.

:Expected: As for test_sdp_cache_same_records.

test_sdp_cache_record_in_both_searches_again
--------------------------------------------

:Setup: As above.

:Steps: As for test_sdp_cache_same_records, except host1 returns A, B,
	C and D for the L2CAP search the second time.

:Expected: As for test_sdp_cache_same_records, and host1 sent D in
	both responses of the second discovery.

test_sdp_cache_fewer_records
----------------------------

:Setup: As above.

:Steps: As for test_sdp_cache_same_records, except host1 returns A and
	C the second time.

:Expected: As for test_sdp_cache_same_records: B stays cached, as
	bluetoothd keeps the records with a handle it no longer finds.

test_sdp_cache_changed_record_read_back
---------------------------------------

:Setup: As above, with ``Experimental = true``.

:Steps:
	1. host0 discovers the services of host1, which returns A, B and
	   C.
	2. host0 discovers them again, host1 returning A, B and a changed
	   C.
	3. **bluetoothd(8)** is restarted on host0, with the same state
	   directory.
	4. host1 connects to host0, and host0 calls
	   ``org.bluez.Device1.GetServiceRecords``.

:Expected: ``GetServiceRecords`` returns A, B, both versions of C and
	D, each once, the first version of C before the changed one.

:Notes: bluetoothd can not tell a changed record without handle from a
	new one. A lookup by UUID finds the first record of that UUID.

test_sdp_cache_changed_record_every_discovery
---------------------------------------------

:Setup: As above.

:Steps: host0 discovers the services of host1 four times. host1
	returns A, B and C, with C changed at each discovery.

:Expected: After each discovery the cache holds one more record, the
	new version of C, and every record cached before under the key it
	had.

test_sdp_cache_added_record[added-last]
---------------------------------------

:Setup: As above.

:Steps: As for test_sdp_cache_same_records, except host1 returns A, B,
	C and E the second time.

:Expected: The cache holds A, B, C, D and E. A, B, C and D have the key
	they had after the first discovery.

test_sdp_cache_added_record[added-first]
----------------------------------------

:Setup: As above.

:Steps: As above, except host1 returns E, A, B and C the second time.

:Expected: As above.

test_sdp_cache_added_record_down_before_second_response[added-last]
-------------------------------------------------------------------

:Setup: As above.

:Steps: As for test_sdp_cache_added_record[added-last], except host1
	goes out of range when it receives the second request of the
	second discovery.

:Expected: As for test_sdp_cache_added_record[added-last]: D, which
	host0 did not get again, stays cached.

test_sdp_cache_added_record_down_before_second_response[added-first]
--------------------------------------------------------------------

:Setup: As above.

:Steps: As above, except host1 returns E, A, B and C the second time.

:Expected: As above.

test_sdp_cache_written_without_fix
----------------------------------

:Setup: As above. Before the discovery, B is written to the cache file
	of host1 under ``0xFFFFFFFF``, as a bluetoothd that only keeps one
	record without handle caches it.

:Steps: host0 discovers the services of host1, which returns A, B and
	C.

:Expected: The cache holds A, B, C and D, B still under
	``0xFFFFFFFF``.

test_sdp_cache_value_no_record[first-key]
-----------------------------------------

:Setup: As above. Before the discovery, the value ``DEADBEEF``, which
	is no SDP record, is written to the cache file of host1 under
	``0xFFFFFFFF``.

:Steps: host0 discovers the services of host1, which returns A, B and
	C.

:Expected: The cache holds A, B, C and D, and the entry written before
	as it was.

test_sdp_cache_value_no_record[second-key]
------------------------------------------

:Setup: As above, but the value is written under ``0xFFFFFFFE``.

:Steps: As above.

:Expected: As above.

test_sdp_cache_value_no_record[empty]
-------------------------------------

:Setup: As for test_sdp_cache_value_no_record[first-key], but the
	value is empty.

:Steps: As above.

:Expected: As above.

test_sdp_cache_value_no_record[not-hex]
---------------------------------------

:Setup: As for test_sdp_cache_value_no_record[first-key], but the
	value is ``not hex``.

:Steps: As above.

:Expected: As above.

test_sdp_cache_read_back_after_restart
--------------------------------------

:Setup: As above, with ``Experimental = true``.

:Steps:
	1. host0 discovers the services of host1, which returns A, B and
	   C.
	2. host0 discovers them again, host1 returning A and C.
	3. **bluetoothd(8)** is restarted on host0, with the same state
	   directory.
	4. host1 connects to host0, and host0 calls
	   ``org.bluez.Device1.GetServiceRecords``.

:Expected: ``GetServiceRecords`` returns A, B, C and D, each once.

test_sdp_cache_handle_equal_to_key_same_search[first]
-----------------------------------------------------

:Setup: As above.

:Steps:
	1. host0 discovers the services of host1, which returns A and C,
	   and reads the key of C from the cache.
	2. host0 calls ``org.bluez.Adapter1.RemoveDevice`` on host1, and
	   finds it again.
	3. host0 discovers the services of host1, which returns R, A and
	   C. R is a record of service class 0x7004 with the key of C as
	   handle.

:Expected: The cache holds A, R, C and D, R under its handle.

:Notes: The key is read from an earlier discovery, so the test does
	not depend on how bluetoothd chooses the keys of records without
	handle.

test_sdp_cache_handle_equal_to_key_same_search[middle]
------------------------------------------------------

:Setup: As above.

:Steps: As above, except host1 returns A, R and C.

:Expected: As above.

test_sdp_cache_handle_equal_to_key_same_search[last]
----------------------------------------------------

:Setup: As above.

:Steps: As above, except host1 returns A, C and R, so R is found after
	C got that key.

:Expected: As above.

test_sdp_cache_handle_equal_to_key_later_search[key-of-first]
-------------------------------------------------------------

:Setup: As above.

:Steps:
	1. host0 discovers the services of host1, which returns A and C
	   and no PnP Information record, and reads the key of A from the
	   cache.
	2. host0 removes host1 and finds it again.
	3. host0 discovers the services of host1, which returns A and C,
	   and for the PnP Information search a PnP Information record R
	   with the key of A as handle.

:Expected: The cache holds A, C and R, R under its handle.

test_sdp_cache_handle_equal_to_key_later_search[key-of-second]
--------------------------------------------------------------

:Setup: As above.

:Steps: As above, with the key of C.

:Expected: As above.

test_sdp_cache_handle_equal_to_key_later_discovery[key-of-c-complete]
---------------------------------------------------------------------

:Setup: As above.

:Steps:
	1. host0 discovers the services of host1, which returns A, B and
	   C, and reads the key of C from the cache.
	2. host0 discovers them again, host1 returning A, B, C and R. R is
	   a record of service class 0x7004 with the key of C as handle.

:Expected: The cache holds A, B, C, D and R, R under its handle. C is
	cached under another key, and A, B and D have the key they had
	after the first discovery.

test_sdp_cache_handle_equal_to_key_later_discovery[key-of-c-down]
-----------------------------------------------------------------

:Setup: As above.

:Steps: As above, except host1 goes out of range when it receives the
	second request of the second discovery.

:Expected: As above.

test_sdp_cache_handle_equal_to_key_later_discovery[key-of-d-down]
-----------------------------------------------------------------

:Setup: As above.

:Steps: As above, with the key of D, which host0 does not get again.

:Expected: As above, D being the record cached under another key.

test_sdp_cache_handle_equal_to_key_later_discovery[key-of-d-first-down]
-----------------------------------------------------------------------

:Setup: As above.

:Steps: As above, except host1 returns R, A, B and C.

:Expected: As above.

test_sdp_cache_handle_equal_to_key_later_discovery[key-of-dropped-b]
--------------------------------------------------------------------

:Setup: As above.

:Steps: As for
	test_sdp_cache_handle_equal_to_key_later_discovery[key-of-c-complete],
	with the key of B, host1 returning A, C and R the second time.

:Expected: As above, B being the record cached under another key.

test_sdp_cache_key_equal_to_cached_handle[dropped]
--------------------------------------------------

:Setup: As above.

:Steps:
	1. host0 discovers the services of host1, which returns A and E
	   and no PnP Information record, and reads the key of E from the
	   cache.
	2. host0 removes host1 and finds it again.
	3. host0 discovers the services of host1, which returns A, and
	   for the PnP Information search a PnP Information record P with
	   the key of E as handle.
	4. host0 discovers them again, host1 returning A and E and no PnP
	   Information record.

:Expected: The cache holds A, E and P. A and P have the key they had
	after step 3.

test_sdp_cache_key_equal_to_cached_handle[down]
-----------------------------------------------

:Setup: As above.

:Steps: As above, except in step 4 host1 still returns P, and goes out
	of range when it receives the second request.

:Expected: As above.

test_sdp_cache_handle_0xffffffff
--------------------------------

:Setup: As above. R is a record of service class 0x7004 with the
	handle 0xFFFFFFFF.

:Steps: host0 discovers the services of host1, which returns B, R and
	C.

:Expected: The cache holds B, R, C and D, R under ``0xFFFFFFFF``.

:Notes: 0xFFFFFFFF is also the value the handle of a record without
	the ServiceRecordHandle attribute has in bluetoothd.

test_sdp_cache_same_handle_twice
--------------------------------

:Setup: As above. R1 and R2 are records of the service classes 0x7004
	and 0x7006, both with the handle 0xFFFFFFFF.

:Steps: host0 discovers the services of host1, which returns R1 and
	R2.

:Expected:
	1. The cache holds R1 and D.
	2. ``UUIDs`` of host1 contains the UUID of R1, and not the one of
	   R2.

:Notes: The second record is dropped as a duplicate of the first, as
	for any handle.

test_sdp_cache_same_handle_changed
----------------------------------

:Setup: As above. R is a record of service class 0x7004 with the
	handle 0xFFFFFFFF.

:Steps:
	1. host0 discovers the services of host1, which returns A and R.
	2. host0 discovers them again, host1 returning A and a changed R.

:Expected: The cache holds A, the changed R and D.

test_sdp_cache_handles_gained_or_lost[gains]
--------------------------------------------

:Setup: As above.

:Steps:
	1. host0 discovers the services of host1, which returns A and C.
	2. host0 discovers them again, host1 returning A, C and D with the
	   handles 0x00010001, 0x00010003 and 0x00010004.

:Expected: The cache holds the records of both discoveries, those of
	the first under the key they had.

test_sdp_cache_handles_gained_or_lost[loses]
--------------------------------------------

:Setup: As above.

:Steps: As above, with the two discoveries in the other order.

:Expected: As above.

test_sdp_cache_many_records
---------------------------

:Setup: As above.

:Steps:
	1. host0 discovers the services of host1, which returns 10000
	   records of service class 0x7001 for the L2CAP search, each with
	   a handle of its own and another value of attribute 0x0200.
	2. host0 removes host1 and finds it again.
	3. host0 discovers the services of host1, which returns the same
	   records without handle.

:Expected:
	1. The cache holds 10001 records after each discovery.
	2. host0 takes at most twice as long from the response to the
	   L2CAP search to its PnP Information search in step 3 as in
	   step 1.

:Notes: host1 sends a response that does not fit in the L2CAP MTU in
	parts of 600 bytes, with a continuation state. The time is taken
	on host1, so it does not include the transfer of the response.
	The keys and the records themselves are not checked.

test_sdp_cache_public_browse_group[alone]
-----------------------------------------

:Setup: As above. X and Y are records of service class 0x1002 without
	handle. host1 returns no record for the L2CAP and the PnP
	Information search, and X and Y for the Public Browse Group
	search.

:Steps: host0 discovers the services of host1.

:Expected:
	1. host1 received three searches.
	2. The cache holds X and Y.

:Notes: bluetoothd only searches for the Public Browse Group if the
	L2CAP search returns no record, and only keeps records of that
	service class from it. It handles the records of its last search
	twice.

test_sdp_cache_public_browse_group[after-pnp]
---------------------------------------------

:Setup: As above, but host1 returns D for the PnP Information search.

:Steps: As above.

:Expected: As above, the cache holding X, Y and D.

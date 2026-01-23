.. SPDX-License-Identifier: GPL-2.0-or-later
.. Copyright © 2025-2026 Collabora Ltd.

===============
SM test results
===============

:PTS version: 8.5.4

Setup
=====

- Remove PTS device from Bluetooth devices

- In IXIT update "TSPX_iut_device_name_in_adv_packet_for_random_address" to
  the IUT name

Tests
=====

The kernel and BlueZ versions represent the oldest version without backport
for which we know the test passed.

+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| Test name            | Result   | Kernel  | BlueZ |                                                                         |
+======================+==========+=========+=======+=========================================================================+
| SM/CEN/PROT/BV-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/JW/BV-05-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | 'Restart the wizard' on further connection requests                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/JW/BI-04-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/JW/BI-01-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/PKE/BV-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/PKE/BV-04-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/PKE/BI-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/PKE/BI-02-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/OOB/BV-05-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/OOB/BV-07-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/EKS/BV-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
|                      |          |         |       |                                                                         |
|                      |          |         |       | On connection request, re-connect to PTS                                |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/EKS/BI-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
|                      |          |         |       |                                                                         |
|                      |          |         |       | On connection request, re-connect to PTS                                |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/KDU/BV-05-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Enable privacy mode:                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt power off'                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt privacy on'                                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt power on'                                               |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Disable privacy mode:                                                 |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt power off'                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt privacy off'                                            |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt power on'                                               |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/KDU/BV-06-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
|                      |          |         |       |                                                                         |
|                      |          |         |       | On connection request, re-connect to PTS                                |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/KDU/BV-10-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Enable privacy mode:                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt power off'                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt privacy on'                                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt power on'                                               |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Disable privacy mode:                                                 |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt power off'                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt privacy off'                                            |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt power on'                                               |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/KDU/BI-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/SIP/BV-02-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/SCJW/BV-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/SCJW/BV-04-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/SCJW/BI-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/SCPK/BV-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run bluetoothctl                                                      |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - '[bluetooth]# agent off'                                            |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - '[bluetooth]# agent DisplayOnly'                                    |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/SCPK/BV-04-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/SCPK/BI-01-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection requests perform pairing with PTS                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Discard pairing dialog                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/CEN/SCPK/BI-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run bluetoothctl                                                      |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - '[bluetooth]# agent off'                                            |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - '[bluetooth]# agent DisplayOnly'                                    |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On connection request perform pairing with PTS                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | Disconnect on disconnection request                                     |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/PROT/BV-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/JW/BV-02-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/JW/BI-03-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/JW/BI-02-C    | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/PKE/BV-02-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - In a second terminal run to be able to see the requested passkey:     |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt                                                         |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/PKE/BV-05-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - l2test -r -J4 -AES -V le_public                                     |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/PKE/BI-03-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - In a second terminal run to be able to see the requested passkey:     |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt                                                         |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/OOB/BV-06-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/OOB/BV-08-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/EKS/BV-02-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/EKS/BI-02-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BV-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BV-02-C   | PASS     |     6.9 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# remove <bdaddr>                                        |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# power off                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# mgmt.privacy on                                        |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# power on                                               |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# advertise.name on                                      |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# power off                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# mgmt.privacy off                                       |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# power on                                               |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BV-03-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BV-07-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BV-08-C   | PASS     |     6.9 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run 'sudo bluetoothctl':                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# remove <bdaddr>                                        |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# power off                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# mgmt.privacy on                                        |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# power on                                               |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# advertise.name on                                      |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# power off                                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# mgmt.privacy off                                       |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - [bluetooth]# power on                                               |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BV-09-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BI-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BI-02-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/KDU/BI-03-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SIP/BV-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | On request run:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - btmgmt pair -c 0x03 -t 0x01 <addr>                                    |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SIE/BV-01-C   | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt io-cap 3                                                |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SCJW/BV-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SCJW/BV-03-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SCJW/BI-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SCPK/BV-02-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Remove PTS device from Bluetooth devices                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SCPK/BV-03-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - In a second terminal run to be able to see the requested passkey:     |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       |     - [mgmt]# io-cap 0                                                  |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SCPK/BI-03-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - In a second terminal run to be able to see the requested passkey:     |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - sudo btmgmt                                                         |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+
| SM/PER/SCPK/BI-04-C  | PASS     |     6.1 | 5.69  | Pre-condition:                                                          |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable on                              |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise on                                           |
|                      |          |         |       +-------------------------------------------------------------------------+
|                      |          |         |       | Post-condition:                                                         |
|                      |          |         |       |                                                                         |
|                      |          |         |       | - Run:                                                                  |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise.discoverable off                             |
|                      |          |         |       |                                                                         |
|                      |          |         |       |   - bluetoothctl advertise off                                          |
+----------------------+----------+---------+-------+-------------------------------------------------------------------------+

=================
bluetoothctl-mgmt
=================

------------------
Management Submenu
------------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: July 2023
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [mgmt.commands]

Mgmt Commands
=============

select
------

Select a different index

:Usage: **# select <index>**

revision
--------

Get the MGMT Revision

:Usage: **# revision**

commands
--------

List supported commands

:Usage: **# commands**

config
------

Show configuration info

:Usage: **# config**

info
----

Show controller info

:Usage: **# info**

extinfo
-------

Show extended controller info

:Usage: **# extinfo**

auto-power
----------

Power all available features

:Usage: **# auto-power**

power
-----

Toggle powered state

:Usage: **# power <on/off>**

discov
------

Toggle discoverable state

:Usage: **# discov <yes/no/limited> [timeout]**

connectable
-----------

Toggle connectable state

:Usage: **# connectable <on/off>**

fast-conn
---------

Toggle fast connectable state

:Usage: **# fast-conn <on/off>**

bondable
--------

Toggle bondable state

:Usage: **# bondable <on/off>**

pairable
--------

Toggle bondable state

:Usage: **# pairable <on/off>**

linksec
-------

Toggle link level security

:Usage: **# linksec <on/off>**

ssp
---

Toggle SSP mode

:Usage: **# spp <on/off>**

sc
--

Toggle SC support

:Usage: **# sc <on/off/only>**

hs
--

Toggle HS support

:Usage: **# hs <on/off>**

le
--

Toggle LE support

:Usage: **# le <on/off>**

advertising
-----------

Toggle LE advertising

:Usage: **# advertise <on/off>**

bredr
-----

Toggle BR/EDR support

:Usage: **# bredr <on/off>**

privacy
-------

Toggle privacy support

:Usage: **# privacy <on/off> [irk]**

class
-----

Set device major/minor class

:Usage: **# class <major> <minor>**

disconnect
----------

Disconnect device

:Usage: **# disconnect [-t type] <remote address>**

con
---

List connections

:Usage: **# con**

find
----

Discover nearby devices

:Usage: **# find [-l|-b] [-L]**

find-service
------------

Discover nearby service

:Usage: **# find-service [-u UUID] [-r RSSI_Threshold] [-l|-b]**

stop-find
---------

Stop discovery

:Usage: **# stop-find [-l|-b]**

name
----

Set local name

:Usage: **# name <name> [shortname]**

pair
----

Pair with a remote device

:Usage: **# pair [-c cap] [-t type] <remote address>**

cancelpair
----------

Cancel pairing

:Usage: **# cancelpair [-t type] <remote address>**

unpair
------

Unpair device

:Usage: **# unpair [-t type] <remote address>**

keys
----

Load Link Keys

:Usage: **keys**

ltks
----

Load Long Term Keys

:Usage: **# ltks**

irks
----

Load Identity Resolving Keys

:Usage: **# irks [--local index] [--file file path]**

block
-----

Block Device

:Usage: **# block [-t type] <remote address>**

unblock
-------

Unblock Device

:Usage: **# unblock [-t type] <remote address>**

add-uuid
--------

Add UUID

:Usage: **# add-uuid <UUID> <service class hint>**

rm-uuid
-------

Remove UUID

:Usage: **# rm-uuid <UUID>**

clr-uuids
---------

Clear UUIDs

:Usage: **# clear-uuids**

local-oob
---------

Local OOB data

:Usage: **# local-oob**

remote-oob
----------

Remote OOB data

:Usage: **# remote-oob [-t <addr_type>] [-r <rand192>] [-h <hash192>]
	[-R <rand256>] [-H <hash256>] <addr>**

did
---

Set Device ID

:Usage: **# did <source>:<vendor>:<product>:<version>**

static-addr
-----------

Set static address

:Usage: **# static-addr <address>**

public-addr
-----------

Set public address

:Usage: **# public-addr <address>**

ext-config
----------

External configuration

:Usage: **# ext-config <on/off>**

debug-keys
----------

Toggle debug keys

:Usage: **# debug-keys <on/off>**

conn-info
---------

Get connection information

:Usage: **# conn-info [-t type] <remote address>**

io-cap
------

Set IO Capability

:Usage: **# io-cap <cap>**

scan-params
-----------

Set Scan Parameters

:Usage: **# scan-params <interval> <window>**

get-clock
---------

Get Clock Information

:Usage: **# get-clock [address]**

add-device
----------

Add Device

:Usage: **# add-device [-a action] [-t type] <address>**

del-device
----------

Remove Device

:Usage: **# del-device [-t type] <address>**

clr-devices
-----------

Clear Devices

:Usage: **# clr-devices**

bredr-oob
---------

Local OOB data (BR/EDR)

:Usage: **# bredr-oob**

le-oob
------

Local OOB data (LE)

:Usage: **# le-oob**

advinfo
-------

Show advertising features

:Usage: **# advinfo**

advsize
-------

Show advertising size info

:Usage: **# advsize [options] <instance_id>**

add-adv
-------

Add advertising instance

:Usage: **# add-adv [options] <instance_id>**

rm-adv
------

Remove advertising instance

:Usage: **# rm-adv <instance_id>**

clr-adv
-------

Clear advertising instances

:Usage: **# clr-adv**

add-ext-adv-params
------------------

Add extended advertising params

:Usage: **# add-ext-adv-parms [options] <instance_id>**

add-ext-adv-data
----------------

Add extended advertising data

:Usage: **# add-ext-adv-data [options] <instance_id>**

appearance
----------

Set appearance

:Usage: **# appearance <appearance>**

phy
---

Get/Set PHY Configuration

:Usage: **# phy [LE1MTX] [LE1MRX] [LE2MTX] [LE2MRX] [LECODEDTX] [LECODEDRX]
	[BR1M1SLOT] [BR1M3SLOT] [BR1M5SLOT][EDR2M1SLOT] [EDR2M3SLOT]
	[EDR2M5SLOT][EDR3M1SLOT] [EDR3M3SLOT] [EDR3M5SLOT]**

wbs
---

Toggle Wideband-Speech support

:Usage: **# wbs <on/off>**

secinfo
-------

Show security information

:Usage: **# secinfo**

expinfo
-------

Show experimental features

:Usage: **# expinfo**

exp-debug
---------

Set debug feature

:Usage: **# exp-debug <on/off>**

exp-privacy
-----------

Set LL privacy feature

:Usage: **# exp-privacy <on/off>**

exp-quality
-----------

Set bluetooth quality report feature

:Usage: **# exp-quality <on/off>**

exp-offload
-----------

Toggle codec support

:Usage: **# exp-offload <on/off>**

read-sysconfig
--------------

Read System Configuration

:Usage: **# read-sysconfig**

set-sysconfig
-------------

Set System Configuration

:Usage: **# set-sysconfig <-v|-h> [options...]**

get-flags
---------

Get device flags


set-flags
---------

Set device flags

:Usage: **# set-flags [-f flags] [-t type] <address>**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

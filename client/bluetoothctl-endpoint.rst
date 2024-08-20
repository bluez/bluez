=====================
bluetoothctl-endpoint
=====================

----------------
Endpoint Submenu
----------------

:Version: BlueZ
:Copyright: Free use of this software is granted under ther terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: November 2022
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [endpoint.commands]

Endpoint Commands
=================

list
----

List available endpoints.

:Usage: **# list [local]**

show
----

Endpoint information.

:Usage: **# show <endpoint>**

register
--------

Register Endpoint.

:Usage: **# register <UUID> <codec[:company]> [capabilities...]**
:Example LC3 source:
	 | **#endpoint.register 00002bcb-0000-1000-8000-00805f9b34fb 0x06**
	 | **#Auto Accept (yes/no):** y
	 | **#Max Transports (auto/value):** a
	 | **#Locations:** a
	 | **#Supported Context (value):** 3
	 | **#Context (value):** 3
	 | **#CIG (auto/value):** a
	 | **#CIS (auto/value):** a
:Example LC3 since with extra capabilities:
	 | **#endpoint.register 00002bc9-0000-1000-8000-00805f9b34fb 0x06 "0x03 0xe5 0x03 0x00 0x02 0xe6 0x07"**
	 | **#Enter Metadata (value/no):** n
	 | **#Auto Accept (yes/no):** y
	 | **#Max Transports (auto/value):** a
	 | **#Locations:** a
	 | **#Supported Context (value):** 3
	 | **#Context (value):** 3
	 | **#CIG (auto/value):** a
	 | **#CIS (auto/value):** a

unregister
----------

Unregister Endpoint.

:Usage: **# unregister <UUID/object>**

config
------

Configure Endpoint.

:Usage: **# config <endpoint> <local endpoint> [preset]**

presets
-------

List available presets.

:Usage: **# presets <endpoint>/<UUID> [codec[:company]] [preset] [codec config] [metadata]**
:Example using endpoint:
	  | **#presets /local/endpoint/ep0 32_1_1**
	  | **#presets /local/endpoint/ep0**
	  | Preset 32_1_1
	  | Configuration.#0: len 0x02 type 0x01
          | Configuration.Sampling Frequency: 32 Khz (0x06)
          | Configuration.#1: len 0x02 type 0x02
          | Configuration.Frame Duration: 7.5 ms (0x00)
          | Configuration.#2: len 0x03 type 0x04
          | Configuration.Frame Length: 60 (0x003c)
:Example using UUID:
	  | **#presets 00002bc9-0000-1000-8000-00805f9b34fb 0x06 32_1_1**
	  | **#presets 00002bc9-0000-1000-8000-00805f9b34fb 0x06**
	  | ...
	  | ***32_1_1**
:Example setting up LC3 custom preset:
	  | **#presets 00002bc9-0000-1000-8000-00805f9b34fb 0x06 custom**
	  | **#[Codec] Enter frequency (Khz):** 48
	  | **#[Codec] Enter frame duration (ms):** 10
	  | **#[Codec] Enter channel allocation:** 3
	  | **#[Codec] Enter frame length:** 100
	  | **#[QoS] Enter Target Latency (Low, Balance, High):** Low
	  | **#[QoS] Enter SDU Interval (us):** 1000
	  | **#[QoS] Enter Framing (Unframed, Framed):** Unframed
	  | **#[QoS] Enter PHY (1M, 2M):** 2M
	  | **#[QoS] Enter Max SDU:** 200
	  | **#[QoS] Enter RTN:** 3
	  | **#[QoS] Enter Max Transport Latency (ms):** 10
	  | **#[QoS] Enter Presentation Delay (us):** 20000
	  | **#presets 00002bc9-0000-1000-8000-00805f9b34fb 0x06**
	  | ...
	  | ***custom**
:Example setting up LC3 custom preset with extra configuration:
	  | **#presets 00002bc9-0000-1000-8000-00805f9b34fb 0x06 custom "0x03 0xe8 0x00 0x00 0x02 0xe9 0x00"**
	  | **#[Codec] Enter frequency (Khz):** 48
	  | **#[Codec] Enter frame duration (ms):** 10
	  | **#[Codec] Enter channel allocation:** 3
	  | **#[Codec] Enter frame length:** 100
	  | **#[QoS] Enter Target Latency (Low, Balance, High):** Low
	  | **#[QoS] Enter SDU Interval (us):** 1000
	  | **#[QoS] Enter Framing (Unframed, Framed):** Unframed
	  | **#[QoS] Enter PHY (1M, 2M):** 2M
	  | **#[QoS] Enter Max SDU:** 200
	  | **#[QoS] Enter RTN:** 3
	  | **#[QoS] Enter Max Transport Latency (ms):** 10
	  | **#[QoS] Enter Presentation Delay (us):** 20000
	  | **#presets 00002bc9-0000-1000-8000-00805f9b34fb 0x06**
	  | ...
	  | ***custom**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

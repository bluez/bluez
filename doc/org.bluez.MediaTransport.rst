========================
org.bluez.MediaTransport
========================

--------------------------------------------
BlueZ D-Bus MediaTransport API documentation
--------------------------------------------

:Version: BlueZ
:Date: July 2024
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.MediaTransport1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/fd#

Methods
-------

fd, uint16, uint16 Acquire()
````````````````````````````

Acquire transport file descriptor and the MTU for read and write respectively.

Possible Errors:

:org.bluez.Error.NotAuthorized:
:org.bluez.Error.Failed:

fd, uint16, uint16 TryAcquire()
```````````````````````````````

Acquire transport file descriptor only if the transport is in "pending" state at
the time the message is received by BlueZ. Otherwise no request will be sent to
the remote device and the function will just fail with
**org.bluez.Error.NotAvailable**.

Possible Errors:

:org.bluez.Error.NotAuthorized:
:org.bluez.Error.Failed:
:org.bluez.Error.NotAvailable:

void Release()
``````````````

Releases file descriptor.

void Select()
`````````````

Applicable only for transports created by a broadcast sink. This moves the
transport from "idle" to "broadcasting".

This allows callers to select which BISes he wishes to sync to via a 2 step
process:

1. the user calls the method, changing the transport's state to broadcasting

2. the audio server detects that the transport is in the 'broadcasting' state
   and automatically acquires it

Possible Errors:

:org.bluez.Error.NotAuthorized:

void Unselect()
```````````````

Applicable only for transports created by a broadcast sink. This moves the
transport from "broadcasting" or "active" to "idle".

This allows callers to terminate the sync to a BIS to via a 2 step process:

1. the user calls this method, changing the transport's state to idle

2. the audio server detects this event and releases the transport

Possible Errors:

:org.bluez.Error.NotAuthorized:

Properties
----------

object Device [readonly]
````````````````````````

Device object which the transport is connected to.

string UUID [readonly]
``````````````````````

UUID of the profile which the transport is for.

byte Codec [readonly]
`````````````````````

Assigned number of codec that the transport support.

The values should match the profile specification which is indicated by the
UUID.

array{byte} Configuration [readonly]
````````````````````````````````````

Configuration blob, it is used as it is so the size and byte order must match.

string State [readonly]
```````````````````````

Indicates the state of the transport. Possible values are:

:"idle": not streaming
:"pending": streaming but not acquired
:"broadcasting":
	streaming but not acquired, applicable only for transports created by a
	broadcast sink
:"active": streaming and acquired

uint16 Delay [readwrite, optional]
``````````````````````````````````

Transport delay in 1/10 of millisecond, this property is only writeable when the
transport corresponds to a sink endpoint and it was acquired by the sender.

uint16 Volume [readwrite, optional]
```````````````````````````````````

Indicates volume level of the transport, this property is only writeable
when the transport was acquired by the sender.

Possible Values:

:0-127 (A2DP):
:0-255 (BAP):

object Endpoint [readonly, optional, experimental]
``````````````````````````````````````````````````

Endpoint object which the transport is associated with.

uint32 Location [readonly, ISO only, experimental]
``````````````````````````````````````````````````

Indicates transport Audio Location.

array{byte} Metadata [readwrite, ISO Only, experimental]
````````````````````````````````````````````````````````

Indicates transport Metadata.

array{object} Links [readonly, optional, CIS only, experimental]
````````````````````````````````````````````````````````````````

Linked transport objects which the transport is associated with.

array{object} Links [readwrite, BIS only, experimental]
```````````````````````````````````````````````````````

For a Broadcast Sink, the BIG sync procedure requires all desired streams to be
enumerated from the start and it cannot be later reconfigured by adding or
removing BISes.

To avoid terminating and recreating the BIG sync every time a new transport is
selected for acquire, all transports selected via **Select** need to be linked
together.

When the first transport is acquired via Transport.Acquire, all links are
included in the BIG sync command.

An acquired transport will create and set fds for all its links. Then, each link
needs to be acquired separately, to get the fd and start receiving audio.

dict QoS [readwrite, optional, ISO only, experimental]
``````````````````````````````````````````````````````

Only present when QoS is configured.

Possible values for Unicast:

:byte CIG:

	Indicates configured CIG.

	Possible values:

	:0x00 - 0xef:

		Valid ID range.

	:0xff:

		Auto allocate.

:byte CIS:

	Indicates configured CIS.

	Possible values:

	:0x00 - 0xef:

	Valid ID range.

	:0xff:

		Auto allocate.

:byte Framing:

	Indicates configured framing.

	Possible values:

	:0x00:

		Unframed.

	:0x01:

		Framed.

:uint32 PresentationDelay:

	Indicates configured transport presentation delay (us).

:byte TargetLatency:

	Indicates the requested target latency.

	Possible values:

	:0x01:

		Low Latency.

	:0x02:

		Balanced Latency/Reliability.

	:0x03:

		High Reliability.

Possible values for Broadcast:

:byte BIG:

	Indicates configured QoS BIG.

:byte BIS:

	Indicates configured BIS.

:byte SyncFactor:

	Indicates configured broadcast sync factor.

:byte Packing:

	Indicates configured packing.

:byte Framing:

	Indicates configured framing.

:array{byte} BCode:

	Indicates the string used for encryption/decryption.

:byte encryption:

	Indicates if the stream is encrypted.

:byte Options:

	Indicates configured broadcast options.

:uint16 Skip:

	Indicates configured broadcast skip.

:byte SyncTimeout:

	Indicates configured broadcast sync timeout.

:byte SyncType:

	Indicates configured broadcast sync CTE type.

:byte MSE:

	Indicates configured broadcast MSE.

:uint16 Timeout:

	Indicates configured broadcast timeout.

Possible values for both Unicast and Broadcast:

:uint32 Interval:

	Indicates configured ISO interval (us).

:uint16 Latency:

	Indicates configured transport latency (ms).

:uint16 SDU:

	Indicates configured maximum SDU.

:byte PHY:

	Indicates configured PHY.

	Possible values:

	:bit 0:

		LE 1M

	:bit 1:

		LE 2M

	:bit 2:

		LE Coded

:byte Retransmissions:

	Indicates configured retransmissions.

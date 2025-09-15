=======================
org.bluez.MediaEndpoint
=======================

-------------------------------------------
BlueZ D-Bus MediaEndpoint API documentation
-------------------------------------------

:Version: BlueZ
:Date: September 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	unique name (Server role)
		org.bluez (Client role)
:Interface:	org.bluez.MediaEndpoint1
:Object path:	freely definable (Server role)
		[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/sep# (Client role)

Methods
-------

.. _SetConfiguration:

void SetConfiguration(object transport, dict properties)
````````````````````````````````````````````````````````

Set configuration for the transport.


:object transport:

	Configured transport object.

:dict properties:

	Configured **org.bluez.MediaTransport(5)** properties.

For client role transport must be set with a server endpoint object which will
be configured and the properties must contain the following properties:

:array{byte} Capabilities [Mandatory]:

	See Capabilities property.

:array{byte} Metadata [ISO only]:

	See Metadata property.

:dict QoS [ISO only]:

	See **org.bluez.MediaTransport(5)** QoS property.

Possible errors for A2DP endpoints:
	:org.bluez.Error.A2DP.InvalidCodecType:
	:org.bluez.Error.A2DP.NotSupportedCodecType:
	:org.bluez.Error.A2DP.InvalidSamplingFrequency:
	:org.bluez.Error.A2DP.NotSupportedSamplingFrequency:
	:org.bluez.Error.A2DP.InvalidChannelMode:
	:org.bluez.Error.A2DP.NotSupportedChannelMode:
	:org.bluez.Error.A2DP.InvalidSubbands:
	:org.bluez.Error.A2DP.NotSupportedSubbands:
	:org.bluez.Error.A2DP.InvalidAllocationMethod:
	:org.bluez.Error.A2DP.NotSupportedAllocationMethod:
	:org.bluez.Error.A2DP.InvalidMinimumBitpoolValue:
	:org.bluez.Error.A2DP.NotSupportedMinimumBitpoolValue:
	:org.bluez.Error.A2DP.InvalidMaximumBitpoolValue:
	:org.bluez.Error.A2DP.NotSupportedMaximumBitpoolValue:
	:org.bluez.Error.A2DP.InvalidLayer:
	:org.bluez.Error.A2DP.NotSupportedLayer:
	:org.bluez.Error.A2DP.NotSupportedCRC:
	:org.bluez.Error.A2DP.NotSupportedMPF:
	:org.bluez.Error.A2DP.NotSupportedVBR:
	:org.bluez.Error.A2DP.InvalidBitRate:
	:org.bluez.Error.A2DP.NotSupportedBitRate:
	:org.bluez.Error.A2DP.InvalidObjectType:
	:org.bluez.Error.A2DP.NotSupportedObjectType:
	:org.bluez.Error.A2DP.InvalidChannels:
	:org.bluez.Error.A2DP.NotSupportedChannels:
	:org.bluez.Error.A2DP.InvalidVersion:
	:org.bluez.Error.A2DP.NotSupportedVersion:
	:org.bluez.Error.A2DP.NotSupportedMaximumSUL:
	:org.bluez.Error.A2DP.InvalidBlockLength:
	:org.bluez.Error.A2DP.InvalidCPType:
	:org.bluez.Error.A2DP.InvalidCPFormat:
	:org.bluez.Error.A2DP.InvalidCodecParameter:
	:org.bluez.Error.A2DP.NotSupportedCodecParameter:
	:org.bluez.Error.A2DP.InvalidDRC:
	:org.bluez.Error.A2DP.NotSupportedDRC:

array{byte} SelectConfiguration(array{byte} capabilities)
`````````````````````````````````````````````````````````

Select preferable configuration from the supported capabilities.

Returns a configuration which can be used to setup a transport, see
**org.bluez.MediaTransport(5)** for possible values.

Note: There is no need to cache the selected configuration since on success the
configuration is send back as parameter of SetConfiguration.

dict SelectProperties(dict capabilities)
````````````````````````````````````````

Select BAP unicast configuration from the supported capabilities:

:object Endpoint:

:array{byte} Capabilities:

:array{byte} Metadata:

:uint32 Locations:

:uint32_t ChannelAllocation:

:dict QoS:

	:byte Framing:
	:byte PHY:
	:uint16 MaximumLatency:
	:uint32 MinimumDelay:
	:uint32 MaximumDelay:
	:uint32 PreferredMinimumDelay:
	:uint32 PreferredMaximumDelay:

See `MediaEndpoint Properties`_ for their possible values.

Returns a configuration which can be used to setup a transport:

:array{byte} Capabilities:
:array{byte} Metadata [optional]:
:dict QoS:

See `SetConfiguration`_ for their possible values.

Note: There is no need to cache the selected properties since on success the
configuration is send back as parameter of SetConfiguration.

void ClearConfiguration(object transport)
`````````````````````````````````````````

Clear transport configuration.

**Server role:** [ISO only]

Close the stream associated with the given transport. If the path given is the
path of this endpoint, all its streams are closed.

void Reconfigure(dict properties)
`````````````````````````````````

[ISO only]

Reconfigure a BAP unicast endpoint. This closes all existing streams of the
endpoint, and restarts the configuration selection flow which e.g. triggers
calls to *SelectProperties* allowing the sound server to modify the
configuration.

The following arguments are taken in *properties*:

:boolean Defer [optional]:

	If True, mark endpoint for reconfiguration, but postpone it until a
	non-deferred *Reconfigure()* operation is made on an endpoint of the
	same device.

	This is necessary to use when reconfiguring source and sink streams with
	the intention that they be combined into the same CIG, possibly forming
	bidirectional CIS.

void Release()
``````````````

This method gets called when **bluetoothd(8)** unregisters the endpoint.

An endpoint can use it to do cleanup tasks. There is no need to unregister the
endpoint, because when this method gets called it has already been unregistered.

MediaEndpoint Properties
------------------------

string UUID [readonly, optional]
````````````````````````````````

UUID of the profile which the endpoint is for.

byte Codec [readonly, optional]
```````````````````````````````

Assigned number of codec that the endpoint implements.

The values should match the profile specification which is indicated by the
UUID.

uint32_t Vendor [readonly, Optional]
````````````````````````````````````

Vendor-specific Company ID, Codec ID tuple that the endpoint implements.

It shall be set to appropriate value when Vendor Specific Codec (0xff) is used.

array{byte} Capabilities [readonly, optional]
`````````````````````````````````````````````

Capabilities blob, it is used as it is so the size and byte order must match.

array{byte} Metadata [readonly, Optional]
`````````````````````````````````````````

Metadata blob, it is used as it is so the size and byte order must match.

object Device [readonly, optional]
``````````````````````````````````

Device object which the endpoint is belongs to.

bool DelayReporting [readonly, optional]
````````````````````````````````````````

Indicates if endpoint supports Delay Reporting.

uint32 Locations [readonly, optional, ISO only, experimental]
`````````````````````````````````````````````````````````````

Indicates endpoint supported locations.

uint16 SupportedContext [readonly, optional, ISO only, experimental]
````````````````````````````````````````````````````````````````````

Indicates endpoint supported audio context.

uint16 Context [readonly, optional, ISO only, experimental]
```````````````````````````````````````````````````````````

Indicates endpoint available audio context.

dict QoS [readonly, optional, ISO only, experimental]
`````````````````````````````````````````````````````

Indicates QoS capabilities.

:byte Framing:

	Indicates endpoint support framing.


	Possible Values:

	:0x00:

		Unframed PDUs supported.

	:0x01:

		Unframed PDUs not supported.

:byte PHY:

	Indicates endpoint preferred PHY.

	Possible values:

	:bit 0:

		LE 1M preferred.

	:bit 1:

		LE 2M preferred.

	:bit 2:

		LE Coded preferred.

:byte Retransmissions:

	Indicates endpoint preferred number of retransmissions.

:uint16 MaximumLatency:

	Indicates endpoint maximum latency.

:uint32 MinimumDelay:

	Indicates endpoint minimum presentation delay.

:uint32 MaximumDelay:

	Indicates endpoint maximum presentation delay.

:uint32 PreferredMinimumDelay:

	Indicates endpoint preferred minimum presentation delay.

:uint32 PreferredMaximumDelay:

	Indicates endpoint preferred maximum presentation delay.

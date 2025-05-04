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
		[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX/sepX
		(Client role)

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

	For client role transport must be set with a server endpoint
	object which will be configured and the properties must
	contain the following properties:

	:array{byte} Capabilities [Mandatory]:

		See Capabilities property.

	:array{byte} Metadata [ISO only]:

		See Metadata property.

	:dict QoS [ISO only]:

		See **org.bluez.MediaTransport(5)** QoS property.

array{byte} SelectConfiguration(array{byte} capabilities)
`````````````````````````````````````````````````````````

	Select preferable configuration from the supported capabilities.

	Returns a configuration which can be used to setup a transport, see
	**org.bluez.MediaTransport(5)** for possible values.

	Note: There is no need to cache the selected configuration since on
	success the configuration is send back as parameter of SetConfiguration.

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

	Note: There is no need to cache the selected properties since on
	success the configuration is send back as parameter of SetConfiguration.

void ClearConfiguration(object transport)
`````````````````````````````````````````

	Clear transport configuration.

	**Server role:** [ISO only]

	Close the stream associated with the given transport. If the
	path given is the path of this endpoint, all its streams are
	closed.

void Release()
``````````````

	This method gets called when the service daemon unregisters the
	endpoint. An endpoint can use it to do cleanup tasks. There is no need
	to unregister the endpoint, because when this method gets called it has
	already been unregistered.

MediaEndpoint Properties
------------------------

string UUID [readonly, optional]
````````````````````````````````

	UUID of the profile which the endpoint is for.

byte Codec [readonly, optional]
```````````````````````````````

	Assigned number of codec that the endpoint implements.
	The values should match the profile specification which is indicated by
	the UUID.

uint32_t Vendor [readonly, Optional]
````````````````````````````````````

	Vendor-specific Company ID, Codec ID tuple that the endpoint implements.

	It shall be set to appropriate value when Vendor Specific Codec (0xff)
	is used.

array{byte} Capabilities [readonly, optional]
`````````````````````````````````````````````

	Capabilities blob, it is used as it is so the size and byte order must
	match.

array{byte} Metadata [readonly, Optional]
`````````````````````````````````````````

	Metadata blob, it is used as it is so the size and byte order must
	match.

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

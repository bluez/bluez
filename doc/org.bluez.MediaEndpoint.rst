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

void SetConfiguration(object transport, dict properties)
````````````````````````````````````````````````````````

	Set configuration for the transport.

	For client role transport must be set with a server endpoint oject which
	will be configured and the properties must contain the following
	properties:

	:array{byte} Capabilities [Mandatory]:

		See Capabilities property.

	:array{byte} Metadata [ISO only]:

		See Metadata property.

	:uint32 Location [ISO only]:

		See Location property.

	:byte Framing [ISO only]:

		See Framing property.

	:byte PHY [ISO only]:

		See PHY property.

	:uint16 MaximumLatency [ISO only]:

		See MaximumLatency property.

	:uint32 MinimumDelay [ISO only]:

		See MinimumDelay property.

	:uint32 MaximumDelay [ISO only]:

		See MaximumDelay property.

	:uint32 PreferredMinimumDelay [ISO only]:

		See PreferredMinimumDelay property.

	:uint32 PreferredMaximumDelay [ISO only]:

		See PreferredMaximumDelay property.

array{byte} SelectConfiguration(array{byte} capabilities)
`````````````````````````````````````````````````````````

	Select preferable configuration from the supported capabilities.

	Returns a configuration which can be used to setup a transport.

	Note: There is no need to cache the selected configuration since on
	success the configuration is send back as parameter of SetConfiguration.

dict SelectProperties(dict properties)
``````````````````````````````````````

	Select preferable properties from the supported properties:

	:object Endpoint [ISO only]:
	:Refer to SetConfiguration for the list of other possible properties.:

	Returns propeties which can be used to setup a transport.

	Note: There is no need to cache the selected properties since on
	success the configuration is send back as parameter of SetConfiguration.

void ClearConfiguration(object transport)
`````````````````````````````````````````

	Clear transport configuration.

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

byte Framing [ISO only]
```````````````````````

	Indicates endpoint support framing.

byte PHY [ISO only]
```````````````````

	Indicates endpoint supported PHY.

	Possible values:

	:bit 0:

		LE 1M

	:bit 1:

		LE 2M

	:bit 2:

		LE Coded

byte Retransmissions [ISO only]
```````````````````````````````

	Indicates endpoint preferred number of retransmissions.

uint16_t MaximumLatency [ISO only]
``````````````````````````````````

	Indicates endpoint maximum latency.

uint32_t MinimumDelay [ISO only]
````````````````````````````````

	Indicates endpoint minimum presentation delay.

uint32_t MaximumDelay [ISO only]
````````````````````````````````

	Indicates endpoint maximum presentation delay.

uint32_t PreferredMinimumDelay [ISO only]
`````````````````````````````````````````

	Indicates endpoint preferred minimum presentation delay.

uint32_t PreferredMaximumDelay [ISO only]
`````````````````````````````````````````

	Indicates endpoint preferred maximum presentation delay.

uint32 Location [ISO only]
``````````````````````````

	Indicates endpoint supported locations.

uint16 SupportedContext [ISO only]
``````````````````````````````````

	Indicates endpoint supported audio context.

uint16 Context [ISO only]
`````````````````````````

	Indicates endpoint available audio context.

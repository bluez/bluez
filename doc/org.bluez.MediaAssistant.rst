========================
org.bluez.MediaAssistant
========================

--------------------------------------------
BlueZ D-Bus MediaAssistant API documentation
--------------------------------------------

:Version: BlueZ
:Date: June 2024
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.MediaAssistant1
:Object path:	/org/bluez/{hci0,hci1,...}/dev_{BDADDR}/src_{BDADDR}/sid#/bis#

Methods
-------

void Push(dict properties)
````````````````````````````````````````````````````````

Send stream information to the remote device.

:dict properties:

Indicate stream properties that will be sent to the peer.

Values:

	:array{byte} Metadata [ISO only]:

		See Metadata property.

	:dict QoS [ISO only]:

		See QoS property.

	:object Device [ISO only, State=local only]:

		Push to a specific device. Device must be connected and with
		an active BASS session.

Properties
----------

string State [readonly]
```````````````````````

Indicates the state of the assistant object. Possible values are:

:"idle": assistant object was created for the stream
:"pending": assistant object was pushed (stream information was sent to the peer)
:"requesting": remote device requires Broadcast_Code
:"active": remote device started receiving stream
:"local": assistant object was created for a local stream

array{byte} Metadata [readwrite, ISO Only, experimental]
````````````````````````````````````````````````````````

Indicates stream Metadata.

dict QoS [readwrite, ISO only, experimental]
````````````````````````````````````````````

Indicates stream QoS capabilities.

Values:

:byte Encryption:

	Indicates whether the stream is encrypted.

:array{byte} BCode

	Indicates Broadcast_Code to decrypt stream.

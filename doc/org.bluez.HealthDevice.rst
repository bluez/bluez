======================
org.bluez.HealthDevice
======================

------------------------------------
BlueZ D-Bus Health API documentation
------------------------------------

:Version: BlueZ
:Date: July 2010
:Author: José Antonio Santos Cadenas <santoscadenas@gmail.com>
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.HealthDevice1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX

Methods
-------

boolean Echo()
``````````````

Sends an echo petition to the remote service. Returns
True if response matches with the buffer sent. If some
error is detected False value is returned.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.OutOfRange:

object CreateChannel(object application, string configuration)
``````````````````````````````````````````````````````````````

Creates a new data channel.  The configuration should
indicate the channel quality of service using one of
this values "reliable", "streaming", "any".

Returns the object path that identifies the data
channel that is already connected.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.HealthError:

void DestroyChannel(object channel)
```````````````````````````````````

Destroys the data channel object. Only the creator of
the channel or the creator of the HealthApplication
that received the data channel will be able to destroy
it.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotFound:
:org.bluez.Error.NotAllowed:

Signals
-------

void ChannelConnected(object channel)
`````````````````````````````````````

This signal is launched when a new data channel is
created or when a known data channel is reconnected.

void ChannelDeleted(object channel)
```````````````````````````````````

This signal is launched when a data channel is deleted.

After this signal the data channel path will not be
valid and its path can be reused for future data
channels.

Properties
----------

object MainChannel [readonly]
`````````````````````````````

The first reliable channel opened. It is needed by
upper applications in order to send specific protocol
data units. The first reliable can change after a
reconnection.


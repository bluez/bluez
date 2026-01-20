=======================
org.bluez.HealthChannel
=======================

----------------------------------
BlueZ D-Bus Health API description
----------------------------------

:Version: BlueZ
:Date: July 2010
:Author: José Antonio Santos Cadenas <santoscadenas@gmail.com>
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.HealthChannel1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX/chanZZZ

Only the process that created the data channel or the creator of the
HealthApplication that received it will be able to call these methods.

Methods
-------

fd Acquire()
````````````

Returns the file descriptor for this data channel. If
the data channel is not connected it will also
reconnect.

Possible Errors:

:org.bluez.Error.NotConnected:
:org.bluez.Error.NotAllowed:

void Release()
``````````````

Releases the fd. Application should also need to
close() it.

Possible Errors:

:org.bluez.Error.NotAcquired:
:org.bluez.Error.NotAllowed:

Properties
----------

string Type [readonly]
``````````````````````

The quality of service of the data channel. ("reliable"
or "streaming")

object Device [readonly]
````````````````````````

Identifies the Remote Device that is connected with.
Maps with a HealthDevice object.

object Application [readonly]
`````````````````````````````

Identifies the HealthApplication to which this channel
is related to (which indirectly defines its role and
data type).


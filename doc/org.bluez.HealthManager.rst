=======================
org.bluez.HealthManager
=======================

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
:Interface:	org.bluez.HealthManager1
:Object path:	/org/bluez/

Methods
-------

object CreateApplication(dict config)
`````````````````````````````````````

Returns the path of the new registered application.
Application will be closed by the call or implicitly
when the programs leaves the bus.

Possible config value:

:uint16 DataType:

        Mandatory

:string Role:

	Mandatory. Possible values: "source", "sink"

:string Description:

	Optional

:ChannelType:

	Optional, just for sources. Possible
	values: "reliable", "streaming"

Possible Errors:

:org.bluez.Error.InvalidArguments:

void DestroyApplication(object application)
```````````````````````````````````````````

Closes the HDP application identified by the object
path. Also application will be closed if the process
that started it leaves the bus. Only the creator of the
application will be able to destroy it.

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotFound:
:org.bluez.Error.NotAllowed:


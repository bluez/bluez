===================
org.bluez.SimAccess
===================

----------------------------------------
BlueZ D-Bus Sim Access API documentation
----------------------------------------

:Version: BlueZ
:Date: February 2011
:Author: Waldemar Rymarkiewicz <waldemar.rymarkiewicz@tieto.com>
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.SimAccess1
:Object path:	[variable prefix]/{hci0,hci1,...}

Methods
-------

void Disconnect()
`````````````````
Disconnects SAP client from the server.

Possible errors:

:org.bluez.Error.Failed:

Properties
----------

boolean Connected [readonly]
````````````````````````````

Indicates if SAP client is connected to the server.


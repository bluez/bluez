===============
org.bluez.Input
===============

-----------------------------------
BlueZ D-Bus Input API documentation
-----------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Input1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}

Properties
----------

string ReconnectMode [readonly]
```````````````````````````````

Indicates the Connectability mode of the HID device as defined by the HID
Profile specification, Section 5.4.2.

This mode is based in the two properties HIDReconnectInitiate (see Section
5.3.4.6) and HIDNormallyConnectable (see Section 5.3.4.14) which define the
following four possible values:

:"none":

	Device and host are not required to automatically restore the
	connection.

:"host":

	Bluetooth HID host restores connection.

:"device":

	Bluetooth HID device restores connection.

:"any":

	Bluetooth HID device shall attempt to restore the lost connection, but
	Bluetooth HID Host may also restore the connection.

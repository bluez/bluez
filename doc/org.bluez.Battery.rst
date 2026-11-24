=================
org.bluez.Battery
=================

-------------------------------------
BlueZ D-Bus Battery API documentation
-------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Battery1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}
		[/battery_{identifier}]

Component battery objects are experimental. Their object paths are
implementation details and shall be treated as opaque. Clients shall use the
``Device`` and ``Identifier`` properties to associate a component with its
parent device and its stable identity.

For diagnostic purposes, ASCII letters and digits in the identifier are kept
in the object path. Every other byte is encoded as an underscore followed by
two lowercase hexadecimal digits.

Properties
----------

byte Percentage [readonly, optional]
````````````````````````````````````

The percentage of battery left as an unsigned 8-bit integer.

The property is absent while the battery level is unknown.

string Source [readonly, optional]
``````````````````````````````````

Describes where the battery information comes from.

This property is informational only and may be useful for debugging purposes.

Providers from **org.bluez.BatteryProvider(5)** may make use of this property to
indicate where the battery report comes from (e.g. "HFP 1.7", "HID", or the
profile UUID).

object Device [readonly, optional, experimental]
````````````````````````````````````````````````````````````

The object path of the device containing this battery.

This property is present on component battery objects below the device object.

string Identifier [readonly, optional, experimental]
````````````````````````````````````````````````````````````

A stable identifier for this battery within the device, such as ``left``,
``right``, or ``case``.

boolean Charging [readonly, optional, experimental]
````````````````````````````````````````````````````````````

Indicates whether this battery is currently charging. The property is absent
while the charging state is unknown.

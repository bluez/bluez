BlueZ D-Bus Battery API description
***********************************


Battery hierarchy
=================

Service		org.bluez
Interface	org.bluez.Battery1
Object path	[variable prefix]/{hci0,hci1,...}/dev_XX_XX_XX_XX_XX_XX

Properties	byte Percentage [readonly]

			The percentage of battery left as an unsigned 8-bit integer.

======================
org.bluez.MediaControl
======================

------------------------------------------
BlueZ D-Bus MediaControl API documentation
------------------------------------------

:Version: BlueZ
:Date: September 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.MediaControl1
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}

Methods
-------

void Play() [Deprecated]
````````````````````````

Resume playback.

void Pause() [Deprecated]
`````````````````````````

Pause playback.

void Stop() [Deprecated]
````````````````````````

Stop playback.

void Next() [Deprecated]
````````````````````````

Next item.

void Previous() [Deprecated]
````````````````````````````

Previous item.

void VolumeUp() [Deprecated]
````````````````````````````

Adjust remote volume one step up

void VolumeDown() [Deprecated]
``````````````````````````````

Adjust remote volume one step down

void FastForward() [Deprecated]
```````````````````````````````

Fast forward playback, this action is only stopped when another method in this
interface is called.

void Rewind() [Deprecated]
``````````````````````````

Rewind playback, this action is only stopped when another method in this
interface is called.

Properties
----------

boolean Connected [readonly]
````````````````````````````

object Player [readonly, optional]
``````````````````````````````````

Addressed Player object path.

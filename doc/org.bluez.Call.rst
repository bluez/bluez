===============
org.bluez.Call1
===============

--------------------------------------------
BlueZ D-Bus Telephony Call API documentation
--------------------------------------------

:Version: BlueZ
:Date: May 2025
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Call1 [experimental]
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/telephony_ag#/call#

Methods
-------

void Answer()
`````````````

Answers an incoming call. Only valid if the state of the call is "incoming".

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

void Hangup()
`````````````

Hangs up the call.

For an incoming call, the call is hung up.
For a waiting call, the remote party is notified. For HFP by using the User
Determined User Busy (UDUB) condition.

NOTE: Releasing active calls does not produce side-effects. That is the state
of held or waiting calls is not affected. As an exception, in the case where a
single active call and a waiting call are present, releasing the active call
will result in the waiting call transitioning to the 'incoming' state.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

Properties
----------

string LineIdentification [readonly]
````````````````````````````````````

Contains the Line Identification information returned by the network, if
present.

string Name [readonly]
``````````````````````

Contains the Name Identification information returned by the network, if
present.

boolean Multiparty [readonly]
`````````````````````````````

Contains the indication if the call is part of a multiparty call or not.

Notifications if a call becomes part or leaves a multiparty call are sent.

string State [readonly]
```````````````````````

Contains the state of the current call.

Possible values:

:"active":

	The call is active

:"held":

	The call is on hold

:"dialing":

	The call is being dialed

:"alerting":

	The remote party is being alerted

:"incoming":

	Incoming call in progress

:"waiting":

	Call is waiting

:"disconnected":

	No further use of this object is allowed, it will be
	destroyed shortly

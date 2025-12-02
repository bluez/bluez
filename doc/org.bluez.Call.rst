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
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/telephony#/call#

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

For an incoming call, the call is hung up using ATH or equivalent. For a
waiting call, the remote party is notified by using the User Determined User
Busy (UDUB) condition. This is generally implemented using CHLD=0.

Please note that the GSM specification does not allow the release of a held
call when a waiting call exists. This is because 27.007 allows CHLD=1X to
operate only on active calls. Hence a held call cannot be hung up without
affecting the state of the incoming call (e.g. using other CHLD alternatives).
Most manufacturers provide vendor extensions that do allow the state of the
held call to be modified using CHLD=1X or equivalent. It should be noted that
Bluetooth HFP specifies the classic 27.007 behavior and does not allow CHLD=1X
to modify the state of held calls.

Based on the discussion above, it should also be noted that releasing a
particular party of a held multiparty call might not be possible on some
implementations. It is recommended for the applications to structure their UI
accordingly.

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
present. For incoming calls this is effectively the CLIP. For outgoing calls
this attribute will hold the dialed number, or the COLP if received by the
audio gateway.

Please note that COLP may be different from the dialed number. A special
"withheld" value means the remote party refused to provide caller ID and the
"override category" option was not provisioned for the current subscriber.

string IncomingLine [readonly, optional]
````````````````````````````````````````

Contains the Called Line Identification information returned by the network.
This is only available for incoming calls and indicates the local subscriber
number which was dialed by the remote party. This is useful for subscribers
which have a multiple line service with their network provider and would like
to know what line the call is coming in on.

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

:"response_and_hold":

	Incoming call has been set on hold

:"disconnected":

	No further use of this object is allowed, it will be
	destroyed shortly

====================
org.bluez.Telephony1
====================

-----------------------------------------------------
BlueZ D-Bus Telephony Audio Gateway API documentation
-----------------------------------------------------

:Version: BlueZ
:Date: May 2025
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.Telephony1 [experimental]
:Object path:	[variable prefix]/{hci0,hci1,...}/dev_{BDADDR}/telephony#

Methods
-------

object Dial(string uri)
``````````````````````````

The uri is comprised of the URI scheme followed by the Caller ID (this could
be a telephone number or username), separated by a colon.

Examples of common URI schemes can be found in Internet Assigned Numbers
Authority (IANA) URI Schemes:
https://iana.org/assignments/uri-schemes/uri-schemes.xhtml

This initiates a new outgoing call. Returns the object path to the newly
created call.

For HFP the URI is "tel:" followed by the telephone number.

The telephone number must be a string containing the following characters:
`[0-9+*#,ABCD]{1,80}` The character set can contain numbers, `+`, `*`, `#`,
`,` and the letters `A` to `D`. Besides this sanity checking no further number
validation is performed. It is assumed that the gateway and/or the network
will perform further validation.

If telephone number is an empty string, it will try to call last dialed number.

NOTE: If an active call (single or multiparty) exists, then it is
automatically put on hold if the dial procedure is successful.

Possible Errors:

:org.bluez.Error.InvalidState:
:org.bluez.Error.InvalidArguments:
:org.bluez.Error.NotSupported:
:org.bluez.Error.Failed:

void SwapCalls()
````````````````

Swaps Active and Held calls. The effect of this is that all calls (0 or more
including calls in a multi-party conversation) that were Active are now Held,
and all calls (0 or more) that were Held are now Active.

GSM specification does not allow calls to be swapped in the case where Held,
Active and Waiting calls exist. Some modems implement this anyway, thus it is
manufacturer specific whether this method will succeed in the case of Held,
Active and Waiting calls.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

void ReleaseAndAnswer()
```````````````````````

Releases currently active call (0 or more) and answers the currently waiting
call. Please note that if the current call is a multiparty call, then all
parties in the multi-party call will be released.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

void ReleaseAndSwap()
`````````````````````

Releases currently active call (0 or more) and activates any currently held
calls. Please note that if the current call is a multiparty call, then all
parties in the multi-party call will be released.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

void HoldAndAnswer()
````````````````````

Puts the current call (including multi-party calls) on hold and answers the
currently waiting call. Calling this function when a user already has a both
Active and Held calls is invalid, since in GSM a user can have only a single
Held call at a time.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

void HangupAll()
````````````````

Releases all calls except waiting calls. This includes multiparty calls.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

void HangupActive()
```````````````````

Releases active calls. This includes multiparty active calls.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

void HangupHeld()
`````````````````

Releases held calls except waiting calls. This includes multiparty held calls.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

array{object} CreateMultiparty()
````````````````````````````````

Joins active and held calls together into a multi-party call. If one of the
calls is already a multi-party call, then the other call is added to the
multiparty conversation. Returns the new list of calls participating in the
multiparty call.

There can only be one subscriber controlled multi-party call according to the
GSM specification.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.Failed

void SendTones(string tones)
````````````````````````````

Sends the DTMF tones to the network. The tones have a fixed duration.
Tones can be one of: '0' - '9', '*', '#', 'A', 'B', 'C', 'D'. The last four
are typically not used in normal circumstances.

Possible Errors:
:org.bluez.Error.InvalidState
:org.bluez.Error.InvalidArgs
:org.bluez.Error.Failed

Properties
----------

string UUID [readonly]
``````````````````````

UUID of the profile which the Telephony Audio Gateway is for.

array{string} SupportedURISchemes [readonly]
````````````````````````````````````````````

Contains the list of supported URI schemes.

string State [readonly]
```````````````````````

Contains the state of the current connection.

Possible values:

:"connecting":

	RFComm connection in progress

:"slc_connecting":

	Service Level Connection in progress

:"connected":

	RFComm and Service Level Connection are connected

:"disconnecting":

	No further use of this object is allowed, it will be destroyed shortly

boolean Service [readonly]
``````````````````````````

Network service availability.

byte Signal [readonly]
``````````````````````

Network level signal from 0 to 5.

boolean Roaming [readonly]
``````````````````````````

Network roaming usage.

byte BattChg [readonly]
```````````````````````

Battery level from 0 to 5.

string OperatorName [readonly, optional]
````````````````````````````````````````

Operator name

boolean InbandRingtone [readonly]
`````````````````````````````````

In-band Ringtone availability.

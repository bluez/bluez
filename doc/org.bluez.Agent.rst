===============
org.bluez.Agent
===============

-----------------------------------
BlueZ D-Bus Agent API documentation
-----------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	unique name
:Interface:	org.bluez.Agent1
:Object path:	freely definable

Methods
-------

void Release()
``````````````

This method gets called when **bluetoothd(8)** unregisters the agent.

An agent can use it to do cleanup tasks. There is no need to unregister the
agent, because when this method gets called it has already been unregistered.

string RequestPinCode(object device)
````````````````````````````````````

This method gets called when **bluetoothd(8)** needs to get the passkey for an
authentication.

The return value should be a string of 1-16 characters length. The string can be
alphanumeric.

Possible errors:

:org.bluez.Error.Rejected:
:org.bluez.Error.Canceled:

void DisplayPinCode(object device, string pincode)
``````````````````````````````````````````````````

This method gets called when **bluetoothd(8)** needs to display a pincode for
an authentication.

An empty reply should be returned. When the pincode needs no longer to be
displayed, the Cancel method of the agent will be called.

This is used during the pairing process of keyboards that don't support
Bluetooth 2.1 Secure Simple Pairing, in contrast to DisplayPasskey which is used
for those that do.

This method will only ever be called once since older keyboards do not support
typing notification.

Note that the PIN will always be a 6-digit number, zero-padded to 6 digits. This
is for harmony with the later specification.

Possible errors:

:org.bluez.Error.Rejected:
:org.bluez.Error.Canceled:

uint32 RequestPasskey(object device)
````````````````````````````````````

This method gets called when **bluetoothd(8)** needs to get the passkey for an
authentication.

The return value should be a numeric value between 0-999999.

Possible errors:

:org.bluez.Error.Rejected:
:org.bluez.Error.Canceled:

void DisplayPasskey(object device, uint32 passkey, uint16 entered)
``````````````````````````````````````````````````````````````````

This method gets called when **bluetoothd(8)** needs to display a passkey for
an authentication.

The entered parameter indicates the number of already typed keys on the remote
side.

An empty reply should be returned. When the passkey needs no longer to be
displayed, the Cancel method of the agent will be called.

During the pairing process this method might be called multiple times to update
the entered value.

Note that the passkey will always be a 6-digit number, so the display should be
zero-padded at the start if the value contains less than 6 digits.

void RequestConfirmation(object device, uint32 passkey)
```````````````````````````````````````````````````````

This method gets called when **bluetoothd(8)** needs to confirm a passkey for
an authentication.

To confirm the value it should return an empty reply or an error in case the
passkey is invalid.

Note that the passkey will always be a 6-digit number, so the display should be
zero-padded at the start if the value contains less than 6 digits.

Possible errors:

:org.bluez.Error.Rejected:
:org.bluez.Error.Canceled:

void RequestAuthorization(object device)
````````````````````````````````````````

This method gets called to request the user to authorize an incoming pairing
attempt which would in other circumstances trigger the just-works model, or when
the user plugged in a device that implements cable pairing. In the latter case,
the device would not be connected to the adapter via Bluetooth yet.

Possible errors:

:org.bluez.Error.Rejected:
:org.bluez.Error.Canceled:

void AuthorizeService(object device, string uuid)
`````````````````````````````````````````````````

This method gets called when **bluetoothd(8)** needs to authorize a
connection/service request.

Possible errors:

:org.bluez.Error.Rejected:
:org.bluez.Error.Canceled:

void Cancel()
`````````````

This method gets called to indicate that the agent request failed before a reply
was returned.

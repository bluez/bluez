======================
org.bluez.obex.Message
======================

------------------------------------------
BlueZ D-Bus OBEX Message API documentation
------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.Message1
:Object path:	[Session object path]/message{#}

Methods
-------

object, dict Get(string targetfile, boolean attachment)
```````````````````````````````````````````````````````

Download message and store it in the target file.

If an empty target file is given, a temporary file will be automatically
generated.

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

Properties
----------

string Folder [readonly]
````````````````````````

Folder which the message belongs to

string Subject [readonly]
`````````````````````````

Message subject

string Timestamp [readonly]
```````````````````````````

Message timestamp

string Sender [readonly]
````````````````````````

Message sender name

string SenderAddress [readonly]
```````````````````````````````

Message sender address

string ReplyTo [readonly]
`````````````````````````

Message Reply-To address

string Recipient [readonly]
```````````````````````````

Message recipient name

string RecipientAddress [readonly]
``````````````````````````````````

Message recipient address

string Type [readonly]
``````````````````````

Message type

Possible values:

:"email":
:"sms-gsm":
:"sms-cdma":
:"mms":

uint64 Size [readonly]
``````````````````````

Message size in bytes

string Status [readonly]
````````````````````````

Message reception status

Possible values:

:"complete":
:"fractioned":
:"notification":

boolean Priority [readonly]
```````````````````````````

Message priority flag

boolean Read [read/write]
`````````````````````````

Message read flag

boolean Deleted [writeonly]
```````````````````````````

Message deleted flag

boolean Sent [readonly]
```````````````````````

Message sent flag

boolean Protected [readonly]
````````````````````````````

Message protected flag

string DeliveryStatus [readonly] [optional]
```````````````````````````````````````````

Message delivery status

Possible values:

:"delivered":
:"sent":
:"unknown":

uint64 ConversationId [readonly] [required]
```````````````````````````````````````````

Message conversation id sent by Server which servers as Unique identification of
the conversation.

string ConversationName [readonly] [optional]
`````````````````````````````````````````````

Human readable name of the conversation

string Direction [readonly] [required]
``````````````````````````````````````

Indicate the direction of the message

Possible values:

:"incoming":
:"outgoing":
:"outgoingdraft":
:"outgoingpending":

string AttachmentMimeTypes [readonly] [optional]
````````````````````````````````````````````````

MIME type of the attachment

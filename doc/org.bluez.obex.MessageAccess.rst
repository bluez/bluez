============================
org.bluez.obex.MessageAccess
============================

------------------------------------------------
BlueZ D-Bus OBEX MessageAccess API documentation
------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.MessageAccess1
:Object path:	[Session object path]

Methods
-------

void SetFolder(string name)
```````````````````````````

Set working directory for current session.

Possible name:

	Directory name or '..[/dir]'.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

array{dict} ListFolders(dict filter)
````````````````````````````````````

Returns a dictionary containing information about the current folder content.

Possible filter:

:uint16 Offset (default 0):

	Offset of the first item.

:uint16 MaxCount (default 1024):

	Maximum number of items.

Possible return:

:string Name:

	Folder name

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

array{string} ListFilterFields()
````````````````````````````````

Return all available fields that can be used in **Fields** filter.

Possible values:

:"subject":
:"timestamp":
:"sender":
:"sender-address":
:"recipient":
:"recipient-address":
:"type":
:"size":
:"status":
:"text":
:"attachment":
:"priority":
:"read":
:"sent":
:"protected":
:"replyto":

Possible errors: None

array{object, dict} ListMessages(string folder, dict filter)
````````````````````````````````````````````````````````````

Returns an array containing the messages objects found in the given subfolder of
the current folder, or in the current folder if folder is empty.

Possible Filters:

:uint16 Offset (default 0):

	Offset of the first item.

uint16 MaxCount (default 1024):

	Maximum number of items.

:byte SubjectLength (default 256):

	Maximum length of the Subject property in the message.

:array{string} Fields:

	Message fields, default is all values.

	See **ListFilterFields()** for possible values.

:array{string} Types:

	Filter messages by type.

	Possible values:

	:"sms":
	:"email":
	:"mms":

:string PeriodBegin:

	Filter messages by starting period.

	Possible values:

		Date in "YYYYMMDDTHHMMSS" format.

:string PeriodEnd:

	Filter messages by ending period.

	Possible values:

		Date in "YYYYMMDDTHHMMSS" format.

:boolean Read:

	Filter messages by read flag.

	Possible values:

		True for read or False for unread

:string Recipient:

	Filter messages by recipient address.

:string Sender:

	Filter messages by sender address.

:boolean Priority:

	Filter messages by priority flag.

	Possible values:

		True for high priority or False for non-high priority.

Each message is represented by an object path, which implements
**org.bluez.obex.Message(5)** interface, followed by a dictionary of its
properties.

void UpdateInbox(void)
``````````````````````

Requests remote to update its inbox.

Possible errors:

:org.bluez.obex.Error.Failed:

object, dict PushMessage(string sourcefile, string folder, dict args)
`````````````````````````````````````````````````````````````````````

Transfers a message (in bMessage format) to the remote device.

The message is transferred either to the given subfolder of the current folder,
or to the current folder if folder is empty.

Possible args: Transparent, Retry, Charset

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

array{string} SupportedTypes [readonly]
```````````````````````````````````````

List of supported message types.

Possible values:

:"EMAIL":

	Email messages.

:"SMS_GSM":

	GSM short messages.

:"SMS_CDMA":

	CDMA short messages.

:"MMS":

	MMS messages.

:"IM":

	Instant messaging.

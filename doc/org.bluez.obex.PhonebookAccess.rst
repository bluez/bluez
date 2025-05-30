==============================
org.bluez.obex.PhonebookAccess
==============================

--------------------------------------------------
BlueZ D-Bus OBEX PhonebookAccess API documentation
--------------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.PhonebookAccess1
:Object path:	[Session object path]

Methods
-------

void Select(string location, string phonebook)
``````````````````````````````````````````````

Selects the phonebook object for other operations.

Should be call before all the other operations.

Possible location values:

:"int", "internal" (default):

	Store in the Internal memory.

:"sim{#}":

	Store in the sim number.

Possible phonebook values:

:"pb":

	Store as contact.

:"ich":

	Store as incoming call.

:"och":

	Store as outgoing call.

:"mch":

	Store as missing call.

:"cch":

	Store as a combination of incoming, outgoing and missing call.

"spd":

	Store as speed dials entry ( only for "internal" )

"fav":

	Store as favorites entry ( only for "internal" )

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

object, dict PullAll(string targetfile, dict filters)
`````````````````````````````````````````````````````

Returns the entire phonebook object from the PSE server in plain string with
vcard format, and store it in a local file.

If an empty target file is given, a name will be automatically generated for the
temporary file.

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible filters:

:string Format:

	Items vcard format.

	Possible values:

	:"vcard21" (default):
	:"vcard30":

:string Order:

	Items order.

	Possible values:

	:"":
	:"indexed":
	:"alphanumeric":
	:"phonetic":

:uint16 Offset (default 0):

	Offset of the first item.

:uint16 MaxCount (default 65535):

	Maximum number of items.

:array{string} Fields (default all fields):

	Item vcard fields.

	See **ListFilterFields()** for possible values.

:array{string} FilterAll:

	Filter items by fields using AND logic, cannot be used together with
	**FilterAny**.

	See **ListFilterFields()** for possible values.

:array{string} FilterAny:

	Filter items by fields using OR logic, cannot be used together with
	**FilterAll**.

	See **ListFilterFields()** for possible values.

:bool ResetNewMissedCalls:

	Reset new the missed calls items, shall only be used for folders mch and
	cch.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Forbidden:

array{string vcard, string name} List(dict filters)
```````````````````````````````````````````````````

Returns array of vcard-listing data where every entry consists of a pair of
strings containing the vcard handle and the contact name.

For example:

:"1.vcf": "John"

Possible filters:

:string Order:

	Contact order.

	Possible values:

	:"":
	:"indexed":
	:"alphanumeric":
	:"phonetic":

:uint16 Offset:

	Start offset.

:uint16 MaxCount:

	Maximum number of contacts.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Forbidden:

object, dict Pull(string vcard, string targetfile, dict filters)
````````````````````````````````````````````````````````````````

Retrieves the vcard in the current phonebook object and store it in a local
file.

If an empty target file is given, a name will be automatically generated for the
temporary file.

The returned path represents the newly created transfer, which should be used to
find out if the content has been successfully transferred or if the operation
fails.

The properties of this transfer are also returned along with the object path, to
avoid a call to GetProperties, see **org.bluez.obex.Transfer(5)** for the
possible list of properties.

Possible filters:

:string Format:

	Contact data format.

	Possible values:

	:"":
	:"vcard21":
	:"vcard30":

:array{string} Fields:

	See **ListFilterFields()** for possible values.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Forbidden:
:org.bluez.obex.Error.Failed:

array{string vcard, string name} Search(string field, string value, dict filters)
`````````````````````````````````````````````````````````````````````````````````

Searches for entries matching the given condition and return an array of
vcard-listing data where every entry consists of a pair of strings containing
the vcard handle and the contact name.

Possible field values:

	:"name" (default):

		Search by name.

	:"number":

		Search by number.

	:"sound":

		Search by sound.

value: the string value to search for

Possible filters:

:string Order:

	Contact order.

	Possible values:

	:"":
	:"indexed":
	:"alphanumeric":
	:"phonetic":

:uint16 Offset:

	Start offset.

:uint16 MaxCount:

	Maximum number of contacts.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Forbidden:
:org.bluez.obex.Error.Failed:

uint16 GetSize()
````````````````

Returns the number of entries in the selected phonebook object that are actually
used (i.e. indexes that correspond to non-NULL entries).

Possible errors:

:org.bluez.obex.Error.Forbidden:
:org.bluez.obex.Error.Failed:

void UpdateVersion()
````````````````````

Attempts to update PrimaryCounter and SecondaryCounter.

Possible errors:

:org.bluez.obex.Error.NotSupported:
:org.bluez.obex.Error.Forbidden:
:org.bluez.obex.Error.Failed:

array{string} ListFilterFields()
````````````````````````````````

Returns all Available fields that can be used in Fields filter.

Possible return:

:"VERSION":
:"FN":
:"N":
:"PHOTO":
:"BDAY":
:"ADR":
:"LABEL":
:"TEL":
:"EMAIL":
:"MAILER":
:"TZ":
:"GEO":
:"TITLE":
:"ROLE":
:"LOGO":
:"AGENT":
:"ORG":
:"NOTE":
:"REV":
:"SOUND":
:"URL":
:"UID":
:"KEY":
:"NICKNAME":
:"CATEGORIES":
:"PROID":
:"CLASS":
:"SORT-STRING":
:"X-IRMC-CALL-DATETIME":
:"X-BT-SPEEDDIALKEY":
:"X-BT-UCI":
:"X-BT-UID":
:"BIT-{#}":

Possible errors: None

Properties
----------

string Folder [readonly]
````````````````````````

Current folder.

string DatabaseIdentifier [readonly, optional]
``````````````````````````````````````````````

128 bits persistent database identifier.

Possible values:

	32-character hexadecimal such as A1A2A3A4B1B2C1C2D1D2E1E2E3E4E5E6

string PrimaryCounter [readonly, optional]
``````````````````````````````````````````

128 bits primary version counter.

Possible values:

	32-character hexadecimal such as A1A2A3A4B1B2C1C2D1D2E1E2E3E4E5E6

string SecondaryCounter [readonly, optional]
````````````````````````````````````````````

128 bits secondary version counter.

Possible values:

	32-character hexadecimal such as A1A2A3A4B1B2C1C2D1D2E1E2E3E4E5E6

bool FixedImageSize [readonly, optional]
````````````````````````````````````````

Indicate support for fixed image size.

Possible values:

	True if image is JPEG 300x300 pixels otherwise False.

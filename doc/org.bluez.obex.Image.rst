====================
org.bluez.obex.Image
====================

--------------------------------------------------
BlueZ D-Bus OBEX Image API documentation
--------------------------------------------------

:Version: BlueZ
:Date: August 2024
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.Image1 [experimental]
:Object path:	[Session object path]

Methods
-------

object, dict Get(string targetfile, string handle, dict description)
````````````````````````````````````````````````````````````````````

Retrieves the image corresponding to the handle and the description, as one of
the descriptions retrieved by GetImageProperties, and store it in a local file.

If the "transform" property description exists it should be set to one of the
value listed by GetImageProperties for this description.

If description is an empty dict, the native image will be retrieved.

	Possible errors:

	:org.bluez.obex.Error.InvalidArguments:
	:org.bluez.obex.Error.Failed:

array{dict} Properties(string handle)
`````````````````````````````````````

Retrieves the image properties corresponding to the handle.

The first dict entry is mandatory and correspond to 'handle' and 'name' of the
image.

The second dict entry is mandatory and correspond to the native description
('type':'native') of the image.

The following dict entries are optional and correspond to variant descriptions
of the image. If the 'transform' entry exists in the description, it lists the
available possible image transformations and should be set to one of them before
using the description as parameter to **GetImage**.

Possible property values:

:string type:

	Type of dict properties. Mandatory for each dict.

	Possible values:

	:"native":
	:"variant":

:string encoding:

	File encoding format.

	Possible values:

	:"BMP":
	:"GIF":
	:"JPEG":
	:"JPEG2000":
	:"PNG":
	:"WBMP":

:string pixel:

	File encoding format size of form "<width>*<height>".

:uint64 size:

	File size.

:uint64 maxsize:

	File maximum size.

:string transformation:

	List of available transformations separated by space.

	Possible values:

	:"crop":
	:"fill":
	:"stretch":

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

object, dict GetThumbnail(string targetfile, string handle)
```````````````````````````````````````````````````````````

Retrieves the image thumbnail corresponding to the handle and store it in a
local file.

Possible errors:

:org.bluez.obex.Error.InvalidArguments:
:org.bluez.obex.Error.Failed:

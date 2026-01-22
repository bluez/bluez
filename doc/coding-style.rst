==================
BlueZ coding style
==================

Every project has its coding style, and BlueZ is not an exception. This
document describes the preferred coding style for BlueZ code, in order to keep
some level of consistency among developers so that code can be easily
understood and maintained.

First of all, BlueZ coding style must follow every rule for Linux kernel
(https://www.kernel.org/doc/Documentation/process/coding-style.rst). There also
exists a tool named checkpatch.pl to help you check the compliance with it.
Just type ``checkpatch.pl --no-tree patch_name`` to check your patch. In theory,
you need to clean up all the warnings and errors except this one: ``ERROR:
Missing Signed-off-by: line(s)``. BlueZ does not used ``Signed-off-by`` lines, so
including them is actually an error. In certain circumstances one can ignore
the 80 character per line limit. This is generally only allowed if the
alternative would make the code even less readable.

Besides the kernel coding style above, BlueZ has special flavors for its own.
Some of them are mandatory (marked as ``M``), while some others are optional
(marked as ``O``), but generally preferred.

M1: Blank line before and after an if/while/do/for statement
------------------------------------------------------------

There should be a blank line before ``if`` statement unless the ``if`` is nested and
not preceded by an expression or variable declaration.

Example:
1)

.. code-block:: C

        a = 1;
        if (b) {  // wrong

2)

.. code-block:: C

        a = 1

        if (b) {
        }
        a = 2;	// wrong

3)

.. code-block:: C

        if (a) {
	        if (b)  // correct

4)

.. code-block:: C

        b = 2;

        if (a) {	// correct

        }

        b = 3;

The only exception to this rule applies when a variable is being checked for
errors as such:

.. code-block:: C

        err = stat(filename, &st);
        if (err || !S_ISDIR(st.st_mode))
	        return;

M2: Multiple line comment
-------------------------

If your comment has more than one line, please start it from the second line.

Example:

.. code-block:: C

        /*
         * first line comment	// correct
         * ...
         * last line comment
         */

M3: Space before and after operator
-----------------------------------

There should be a space before and after each operator.

Example:

.. code-block:: C

        a + b;  // correct


M4: Wrap long lines
-------------------

If your condition in ``if``, ``while``, ``for`` statement or a function declaration is too
long to fit in one line, the new line needs to be indented not aligned with the
body.

Example:
1)

.. code-block:: C

        if ((adapter->supported_settings & MGMT_SETTING_SSP) &&
        	!(adapter->current_settings & MGMT_SETTING_SSP)) // wrong

2)

.. code-block:: C

        if ((adapter->supported_settings & MGMT_SETTING_SSP) &&
	        			!(adapter->current_settings & MGMT_SETTING_SSP))

3)

.. code-block:: C

        void btd_adapter_register_pin_cb(struct btd_adapter *adapter,
	        			 btd_adapter_pin_cb_t cb) // wrong

4)

.. code-block:: C

        void btd_adapter_register_pin_cb(struct btd_adapter *adapter,
	        						btd_adapter_pin_cb_t cb)

The referred style for line wrapping is to indent as far as possible to the
right without hitting the 80 columns limit.

M5: Space when doing type casting
---------------------------------

There should be a space between new type and variable.

Example:
1)

.. code-block:: C

        a = (int *)b;  // wrong

2)

.. code-block:: C

        a = (int *) b;  // correct


M6: Don't initialize variable unnecessarily
-------------------------------------------

When declaring a variable, try not to initialize it unless necessary.

Example:

.. code-block:: C

        int i = 1;  // wrong

        for (i = 0; i < 3; i++) {
        }

M7: Follow the order of include header elements
-----------------------------------------------

When writing an include header the various elements should be in the following
order:

* ``#include``'s
* forward declarations
* ``#define``'s
* ``enum``'s
* ``typedef``'s
* function declarations and inline function definitions

M8: Internal headers must not use include guards
------------------------------------------------

Any time when creating a new header file with non-public API, that header
must not contain include guards.

M9: Naming of enums
-------------------

Enums must have a descriptive name.  The enum type should be small caps and
it should not be ``typedef``'ed.  Enum contents should be in CAPITAL letters and
prefixed by the ``enum`` type name.

Example:

.. code-block:: C

        enum animal_type {
        	ANIMAL_TYPE_FOUR_LEGS,
        	ANIMAL_TYPE_EIGHT_LEGS,
        	ANIMAL_TYPE_TWO_LEGS,
        };

If the enum contents have values (e.g. from specification) the formatting
should be as follows:

.. code-block:: C

        enum animal_type {
        	ANIMAL_TYPE_FOUR_LEGS =		4,
        	ANIMAL_TYPE_EIGHT_LEGS =	8,
        	ANIMAL_TYPE_TWO_LEGS =		2,
        };

M10: Enum as switch variable
----------------------------

If the variable of a ``switch`` is an enum, you must include all values in
switch body even if providing ``default``. This is enforced by compiler option
enabling extra warning in such case. The reason for this is to ensure that if
later on the enum is modified and one forget to change the ``switch`` accordingly, the
compiler will complain the new added type hasn't been handled.

Example:

.. code-block:: C

        enum animal_type {
        	ANIMAL_TYPE_FOUR_LEGS =		4,
        	ANIMAL_TYPE_EIGHT_LEGS =	8,
        	ANIMAL_TYPE_TWO_LEGS =		2,
        };

        enum animal_type t;

        switch (t) { // OK
        case ANIMAL_TYPE_FOUR_LEGS:
        	...
        	break;
        case ANIMAL_TYPE_EIGHT_LEGS:
        	...
        	break;
        case ANIMAL_TYPE_TWO_LEGS:
        	...
        	break;
        default:
        	break;
        }

        switch (t) { // Wrong
        case ANIMAL_TYPE_FOUR_LEGS:
        	...
        	break;
        case ANIMAL_TYPE_TWO_LEGS:
        	...
        	break;
        default:
        	break;
        }

However if the enum comes from an external header file outside BlueZ, such as
Android headers, we cannot make any assumption of how the enum is defined and
this rule might not apply.

M11: Always use parenthesis with sizeof
---------------------------------------

The expression argument to the ``sizeof`` operator should always be in
parenthesis, too.

Example:
1)

.. code-block:: C

        memset(stuff, 0, sizeof(*stuff));

2)

.. code-block:: C

        memset(stuff, 0, sizeof *stuff); // Wrong

M12: Use void if function has no parameters
-------------------------------------------

A function with no parameters must use ``void`` in the parameter list.

Example:
1)

.. code-block:: C

        void foo(void)
        {
        }

2)

.. code-block:: C

        void foo()	// Wrong
        {
        }

O1: Try to avoid complex if body
--------------------------------

It's better not to have a complicated statement for ``if``. You may judge its
contrary condition and ``return``, ``break``, ``continue`` or ``goto`` as soon
as possible.

Example:

1)

.. code-block:: C

        if (device) {  // worse
        	memset(&eir_data, 0, sizeof(eir_data));
        	if (eir_len > 0)
        		eir_parse(&eir_data, ev->eir, eir_len);
        	...
        } else {
        	error("Unable to get device object for %s", addr);
        	return;
        }

2)

.. code-block:: C

        if (!device) {
        	error("Unable to get device object for %s", addr);
        	return;
        }

        memset(&eir_data, 0, sizeof(eir_data));
        if (eir_len > 0)
        	eir_parse(&eir_data, ev->eir, eir_len);
        ...


AI Coding Assistants
++++++++++++++++++++

This document provides guidance for AI tools and developers using AI
assistance when contributing to BlueZ.

AI tools helping with BlueZ development should follow the standard
development process:

* doc/coding-style.rst
* doc/maintainer-guidelines.rst

Licensing and Legal Requirements
================================

All contributed code must be compatible with the license of the
respective file. The daemon is licensed under GPL-2.0, while other
parts of the project may use different licenses such as LGPL.
Use appropriate SPDX license identifiers.

The human submitter is responsible for:

* Reviewing all AI-generated code
* Ensuring compliance with licensing requirements
* Taking full responsibility for the contribution

Attribution
===========

When AI tools contribute to development, proper attribution helps track
the evolving role of AI in the development process. Contributions should
include an Assisted-by tag in the following format::

  Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]

Where:

* ``AGENT_NAME`` is the name of the AI tool or framework
* ``MODEL_VERSION`` is the specific model version used
* ``[TOOL1] [TOOL2]`` are optional specialized analysis tools used
  (e.g., coccinelle, sparse, smatch, clang-tidy)

Basic development tools (git, gcc, make, editors) should not be listed.

Example::

  Assisted-by: Claude:claude-3-opus coccinelle sparse

Commit Messages
===============

Commit messages must follow Rule 2 in doc/maintainer-guidelines.rst.

A commit message records only the changes being made and the rationale
for them. For each sentence in a draft, ask what change it records or
what decision it justifies. If the answer is neither, delete it. In
particular, cut anything that:

* explains something the project's developers already know
* restates general knowledge about the language, toolkits, or codebase
* restates what the diff already shows (e.g. listing touched functions)
* narrates the reasoning behind an earlier, abandoned attempt

Additionally:

* Keep it brief; use bullets only when listing multiple distinct changes.
* Use a subject prefix consistent with the history of the files touched.
* Verify factual claims in the message (file counts, symbol names,
  paths) against the actual diff before committing.

Procedure for finding and fixing bugs
=====================================

When an AI assistant is used to find and fix bugs, it **MUST** follow at
least these steps:

1. Before starting, read the whole process documentation listed above,
   as well as any other document mentioned in the request. Do not rely on
   isolated parts found by keyword search.
2. Note the commit ID and locate the bug as instructed.
3. For any bug that is not trivial, verify that it is real by writing a
   reproducer, preferably a unit test (unit/) or a functional test
   (test/functional/, see doc/functional-testing.rst). Unverified reports
   are often invalid and may be ignored. Stop here if the bug turns out
   not to be real.
4. Write a fix for the bug. Fixes written in the same session that found
   the bug tend to be more accurate, as the reasoning context is still
   present.
5. Build and verify that the fix works, using the reproducer or by
   re-running the analysis; drop any fix that doesn't work and try
   another one. The fix must not add build warnings, must pass
   ``make check`` and the checkpatch.pl checks (see doc/coding-style.rst).
6. Commit the fix with a message describing the problem and the solution,
   following the Commit Messages section above. Add a Fixes tag pointing
   to the commit that introduced the bug and an Assisted-by tag as
   described above.
7. Indicate what could not be done. If the fix could not be built or
   tested, or no reproducer could be produced, say so explicitly.
8. Determine whether the bug is a vulnerability. Vulnerabilities must not
   be reported to the mailing list; follow SECURITY.md instead. Regular
   bugs are sent to linux-bluetooth@vger.kernel.org. Leave the submission
   to the human; the assistant must never send anything itself.

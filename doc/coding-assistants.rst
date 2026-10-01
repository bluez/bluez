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

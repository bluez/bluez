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

======================
org.bluez.AgentManager
======================

------------------------------------------
BlueZ D-Bus AgentManager API documentation
------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez
:Interface:	org.bluez.AgentManager1
:Object path:	/org/bluez

Methods
-------

void RegisterAgent(object agent, string capability)
```````````````````````````````````````````````````

Registers pairing agent.

The object path defines the path of the agent that will be called when user
input is needed and must implement **org.bluez.Agent(5)** interface.

Every application can register its own agent and for all actions triggered by
that application its agent is used.

It is not required by an application to register an agent. If an application
does chooses to not register an agent, the default agent is used. This is on
most cases a good idea. Only application like a pairing wizard should register
their own agent.

An application can only register one agent. Multiple agents per application is
not supported.

Possible capability values:

:"":

	Fallback to "KeyboardDisplay".

:"DisplayOnly":
:"DisplayYesNo":
:"KeyboardOnly":
:"NoInputNoOutput":
:"KeyboardDisplay":

Possible errors:

:org.bluez.Error.InvalidArguments:
:org.bluez.Error.AlreadyExists:

void UnregisterAgent(object agent)
``````````````````````````````````

Unregisters an agent that has been previously registered using
**RegisterAgent**. The object path parameter must match the same value that has
been used on registration.

Possible errors:

:org.bluez.Error.DoesNotExist:

void RequestDefaultAgent(object agent)
``````````````````````````````````````

Requests to make the application agent the default agent. The application is
required to register an agent.

Special permission might be required to become the default agent.

Possible errors:

:org.bluez.Error.DoesNotExist:

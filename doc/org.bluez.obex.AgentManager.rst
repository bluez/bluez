===========================
org.bluez.obex.AgentManager
===========================

-----------------------------------------------
BlueZ D-Bus OBEX AgentManager API documentation
-----------------------------------------------

:Version: BlueZ
:Date: October 2023
:Manual section: 5
:Manual group: Linux System Administration

Interface
=========

:Service:	org.bluez.obex
:Interface:	org.bluez.obex.AgentManager1
:Object path:	/org/bluez/obex

Methods
-------

void RegisterAgent(object agent)
````````````````````````````````

Registers an agent, which must implement **org.bluez.obex.Agent(5)**, to request
authorization of the user to accept/reject objects.

Object push service needs to authorize each received object.

Possible errors:

:org.bluez.obex.Error.AlreadyExists:

void UnregisterAgent(object agent)
``````````````````````````````````

Unregisters the agent that has been previously registered using
**RegisterAgent()**.

The object path parameter must match the same value that has been used on
registration.

Possible errors:

:org.bluez.obex.Error.DoesNotExist:

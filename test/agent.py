#!/usr/bin/python

import sys
import dbus
import dbus.service
import dbus.mainloop.glib

AGENT_IFACE = 'org.bluez.mesh.ProvisionAgent1'
AGENT_PATH = "/mesh/test/agent"

bus = None

class Agent(dbus.service.Object):
	def __init__(self, bus):
		self.path = AGENT_PATH
		self.bus = bus
		dbus.service.Object.__init__(self, bus, self.path)

	def get_properties(self):
		caps = []
		oob = []
		caps.append('out-numeric')
		oob.append('other')
		return {
			AGENT_IFACE: {
				'Capabilities': dbus.Array(caps, 's'),
				'OutOfBandInfo': dbus.Array(oob, 's')
			}
		}

	def get_path(self):
		return dbus.ObjectPath(self.path)

	@dbus.service.method(AGENT_IFACE, in_signature="", out_signature="")
	def Cancel(self):
		print("Cancel")

	@dbus.service.method(AGENT_IFACE, in_signature="su", out_signature="")
	def DisplayNumeric(self, type, value):
		print("DisplayNumeric type=", type, " number=", value)

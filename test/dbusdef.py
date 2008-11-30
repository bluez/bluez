import dbus

bus = dbus.SystemBus()


dummy = dbus.Interface(bus.get_object('org.bluez', '/'), 'org.freedesktop.DBus.Introspectable')

#print dummy.Introspect()


manager = dbus.Interface(bus.get_object('org.bluez', '/'), 'org.bluez.Manager')

try:
	adapter = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.Adapter')
except:
	pass

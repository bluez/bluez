import dbus

bus = dbus.SystemBus()

manager = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.Manager')

adapter = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.Adapter')

test = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.Test')

rfcomm = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.RFCOMM')

sdp = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.SDP')

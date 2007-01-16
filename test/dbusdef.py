import dbus

bus = dbus.SystemBus()


manager = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.Manager')

adapter = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.Adapter')

test = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.Test')

rfcomm = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.RFCOMM')


def create_service(identifier):
	try:
		path = manager.FindService(identifier)
	except:
		path = ""

	if (path != ""):
		return dbus.Interface(bus.get_object('org.bluez', path), 'org.bluez.Service')

transfer = create_service("transfer")

network = create_service("network")

input = create_service("input")

audio = create_service("audio")

headset = create_service("headset")

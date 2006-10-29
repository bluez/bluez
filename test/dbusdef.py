import dbus

bus = dbus.SystemBus()

manager = dbus.Interface(bus.get_object('org.bluez', '/org/bluez'), 'org.bluez.Manager')

adapter = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.Adapter')

test = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.Test')

rfcomm = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.RFCOMM')

sdp = dbus.Interface(bus.get_object('org.bluez', manager.DefaultAdapter()), 'org.bluez.SDP')

echo = dbus.Interface(bus.get_object('org.bluez', '/org/bluez/echo'), 'org.bluez.Service')

network = dbus.Interface(bus.get_object('org.bluez', '/org/bluez/network'), 'org.bluez.Service')

input = dbus.Interface(bus.get_object('org.bluez', '/org/bluez/input'), 'org.bluez.Service')

audio = dbus.Interface(bus.get_object('org.bluez', '/org/bluez/audio'), 'org.bluez.Service')

def connect_echo() :
	return dbus.Interface(bus.get_object(echo.GetConnectionName(), '/org/bluez/echo'), 'org.freedesktop.DBus.Introspectable')

def connect_holtmann() :
	holtmann = dbus.Interface(bus.get_object('org.bluez', '/org/holtmann'), 'org.bluez.Service')
	return dbus.Interface(bus.get_object(holtmann.GetConnectionName(), '/org/holtmann'), 'org.freedesktop.DBus.Introspectable')

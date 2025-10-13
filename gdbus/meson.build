gdbus_sources = [
  'gdbus.h',
  'mainloop.c',
  'watch.c',
  'object.c',
  'client.c',
  'polkit.c'
]

libgdbus_internal = static_library('gdbus_internal',
  sources: gdbus_sources,
  dependencies: [ glib_dep, dbus_dep ],
  install: false
)

libgdbus_internal_dep = declare_dependency(
  dependencies: dbus_dep,
  link_with: libgdbus_internal
)

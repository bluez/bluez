if get_option('datafiles')
  install_data('src/obex.conf',
    install_dir: dbusconfdir / 'dbus-1/system.d'
  )
endif

if get_option('systemd')
  configure_file(
    input: 'src/obex.service.in',
    output: 'obex.service',
    install: true,
    install_dir: systemduserunitdir,
    configuration: service_conf
  )
  configure_file(
    input: 'src/org.bluez.obex.service.in',
    output: 'org.bluez.obex.service',
    install: true,
    install_dir: dbussessionbusdir,
    configuration: service_conf
  )
  install_symlink('dbus-org.bluez.obex.service',
    pointing_to: dbussessionbusdir / 'org.bluez.obex.service',
    install_dir: systemduserunitdir
  )
endif

obexd_builtin_modules = [
  'filesystem',
  'bluetooth',
  'opp',
  'ftp',
  'irmc',
  'pbap',
  'mas',
  'mns'
]

obexd_builtin_sources = [
  'plugins/filesystem.c',
  'plugins/bluetooth.c',
  'plugins/opp.c',
  'plugins/ftp.c',
  'plugins/irmc.c',
  'plugins/pbap.c',
  'plugins/vcard.c',
  'plugins/phonebook-@0@.c'.format(get_option('phonebook')),
  'plugins/mas.c',
  'plugins/messages-dummy.c',
  'client/mns.c',
]

if get_option('experimental')
  obexd_builtin_modules += 'pcsuite'
  obexd_builtin_sources += 'plugins/pcsuite.c'
endif

obex_plugindir = get_option('libdir') / 'obex/plugins'

obexd_genbuiltin = find_program('src/genbuiltin')
obexd_builtin_h = custom_target('obexd-builtin.h',
  output: 'builtin.h',
  capture: true,
  command: [ obexd_genbuiltin, obexd_builtin_modules ]
)

executable('obexd',
  sources: [
    btio_sources,
    gobex_sources,
    obexd_builtin_sources,
    obexd_builtin_h,
    'src/main.c',
    'src/plugin.c',
    'src/log.c',
    'src/logind.c',
    'src/manager.c',
    'src/obex.c',
    'src/mimetype.c',
    'src/service.c',
    'src/transport.c',
    'src/server.c',
    'client/manager.c',
    'client/session.c',
    'client/bluetooth.c',
    'client/sync.c',
    'client/pbap.c',
    'client/ftp.c',
    'client/opp.c',
    'client/map.c',
    'client/bip.c',
    'client/bip-common.c',
    'client/map-event.c',
    'client/transfer.c',
    'client/transport.c',
    'client/driver.c'
  ],
  dependencies: [
    libbluetooth_internal_dep,
    libgdbus_internal_dep,
    libshared_glib_dep,
    ical_dep,
    dbus_dep,
    ebook_dep,
    edataserver_dep,
    glib_dep,
    libsystemd_dep.found() ? libsystemd_dep : dummy_dep
  ],
  c_args: [
    '-DOBEX_PLUGIN_BUILTIN',
    '-DPLUGINDIR="@0@"'.format(obex_plugindir),
    '-D_FILE_OFFSET_BITS=64',
    '-DCONFIGDIR="@0@"'.format(configdir),
    get_option('systemd') ? '-DSYSTEMD' : ''
  ],
  link_args: external_plugins_link_args,
  install: true,
  install_dir: pkglibexecdir,
)



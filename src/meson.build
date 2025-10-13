subdir('shared')

if get_option('datafiles')
  install_data('bluetooth.conf',
    install_dir: dbusconfdir / 'dbus-1/system.d'
  )
  install_data('main.conf',
    install_dir: configdir
  )
endif

if get_option('systemd')
  configure_file(
    input: 'bluetooth.service.in',
    output: 'bluetooth.service',
    install: true,
    install_dir: systemdsystemunitdir,
    configuration: service_conf
  )

  install_data('org.bluez.service',
    install_dir: dbussystembusdir
  )
endif

genbuiltin = find_program('genbuiltin')
builtin_h = custom_target('src-builtin.h',
  output: 'builtin.h',
  capture: true,
  command: [ genbuiltin, builtin_modules ]
)

executable('bluetoothd',
  sources: [ builtin_sources,
    attrib_sources,
    btio_sources,
    builtin_h,
    'main.c',
    'log.c',
    'backtrace.c',
    'rfkill.c',
    'sdpd-server.c',
    'sdpd-request.c',
    'sdpd-service.c',
    'sdpd-database.c',
    'gatt-database.c',
    'sdp-xml.c',
    'sdp-client.c',
    'textfile.c',
    'uuid-helper.c',
    'plugin.c',
    'storage.c',
    'advertising.c',
    'agent.c',
    'bearer.c',
    'error.c',
    'adapter.c',
    'profile.c',
    'service.c',
    'gatt-client.c',
    'device.c',
    'dbus-common.c',
    'eir.c',
    'adv_monitor.c',
    'battery.c',
    'settings.c',
    'set.c' ],
  dependencies: [
    libbluetooth_internal_dep,
    libgdbus_internal_dep,
    libshared_glib_dep,
    backtrace_dep,
    glib_dep,
    dbus_dep,
    udevlib_dep,
    builtin_deps
  ],
  override_options: [ 'b_lundef=false' ],
  c_args: [
    '-DBLUETOOTH_PLUGIN_BUILTIN',
    '-DPLUGINDIR="@0@"'.format(plugindir),
    '-DSTORAGEDIR="@0@"'.format(storagedir),
    '-DCONFIGDIR="@0@"'.format(configdir)
  ],
  link_args: [ '-Wl,--gc-sections', external_plugins_link_args ],
  install: true,
  install_dir: pkglibexecdir
)

if get_option('manpages').enabled()
  bluetoothd_rst = configure_file(
    input: 'bluetoothd.rst.in',
    output: 'bluetoothd.rst',
    configuration: man_conf
  )
  custom_target(
    input: bluetoothd_rst,
    output: 'bluetoothd.8',
    command: rst2man_command,
    install: true,
    install_dir: get_option('mandir') / 'man8'
  )
endif

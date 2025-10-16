executable('bluetoothctl',
  sources: [
    'main.c',
    'print.c',
    'display.c',
    'agent.c',
    'advertising.c',
    'adv_monitor.c',
    'gatt.c',
    'admin.c',
    'player.c',
    'mgmt.c',
    'assistant.c',
    'hci.c',
  ],
  dependencies: [
    libbluetooth_internal_dep,
    libgdbus_internal_dep,
    libshared_glib_dep,
    glib_dep,
    udevlib_dep,
    dbus_dep,
    readline_dep
  ],
  install: true,
)

client_man_pages = [
  'bluetoothctl.1',
  'bluetoothctl-mgmt.1',
  'bluetoothctl-monitor.1',
  'bluetoothctl-admin.1',
  'bluetoothctl-advertise.1',
  'bluetoothctl-endpoint.1',
  'bluetoothctl-gatt.1',
  'bluetoothctl-player.1',
  'bluetoothctl-scan.1',
  'bluetoothctl-transport.1',
  'bluetoothctl-assistant.1',
  'bluetoothctl-hci.1'
]

if rst2man.found()
  foreach man_page: client_man_pages
    man_page_name = man_page.substring(0, -2)
    custom_target(man_page,
      input: man_page_name + '.rst',
      output: man_page,
      command: rst2man_command,
      install: true,
      install_dir: get_option('mandir') / 'man1'
    )
  endforeach
endif

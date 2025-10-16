builtin_modules += [
  'gap',
  'scanparam',
  'deviceinfo',
  'battery'
]

builtin_sources += files(
  'audio/media.c',
  'audio/transport.c',
  'audio/player.c',
  'gap/gas.c',
  'scanparam/scan.c',
  'deviceinfo/deviceinfo.c',
  'battery/battery.c'
)

if get_option('sap').enabled()
  builtin_modules += 'sap'
  builtin_sources += files(
    'sap/main.c',
    'sap/manager.c',
    'sap/server.c',
    'sap/sap-dummy.c'
  )
endif

if get_option('a2dp').enabled()
  builtin_modules += 'a2dp'
  builtin_sources += files(
    'audio/source.c',
    'audio/sink.c',
    'audio/a2dp.c',
    'audio/avdtp.c'
  )
endif

if get_option('avrcp').enabled()
  builtin_modules += 'avrcp'
  builtin_sources += files(
    'audio/control.c',
    'audio/avctp.c',
    'audio/avctp.c',
    'audio/avrcp.c'
  )
endif

if get_option('network').enabled()
  builtin_modules += 'network'
  builtin_sources += files(
    'network/manager.c',
    'network/bnep.c',
    'network/server.c',
    'network/connection.c'
  )
  install_data('network/network.conf',
    install_dir: configdir
  )
endif

if get_option('hid').enabled()
  builtin_modules += 'input'
  builtin_sources += files(
    'input/manager.c',
    'input/server.c',
    'input/device.c'
  )

  install_data('input/input.conf',
    install_dir: configdir
  )
endif

if get_option('hog').enabled()
  builtin_modules += 'hog'
  builtin_sources += files(
    'input/hog.c',
    'input/hog-lib.c',
    'deviceinfo/dis.c',
    'battery/bas.c',
    'scanparam/scpp.c',
    'input/suspend-none.c'
  )
endif

if get_option('health').enabled()
  builtin_modules += 'health'
  builtin_sources += files(
    'health/mcap.c',
    'health/hdp_main.c',
    'health/hdp_manager.c',
    'health/hdp.c',
    'health/hdp_util.c'
  )
endif

if alsa_dep.found()
  builtin_modules += 'midi'
  builtin_sources += files(
    'midi/midi.c',
    'midi/libmidi.c'
  )
  builtin_deps += alsa_dep
endif

if get_option('bap').enabled()
  builtin_modules += 'bap'
  builtin_sources += files('audio/bap.c')
endif

if get_option('bass').enabled()
  builtin_modules += 'bass'
  builtin_sources += files('audio/bass.c')
endif

if get_option('mcp').enabled()
  builtin_modules += 'mcp'
  builtin_sources += files('audio/mcp.c')
endif

if get_option('vcp').enabled()
  builtin_modules += 'vcp'
  builtin_sources += files('audio/vcp.c')
endif

if get_option('micp').enabled()
  builtin_modules += 'micp'
  builtin_sources += files('audio/micp.c')
endif

if get_option('ccp').enabled()
  builtin_modules += 'ccp'
  builtin_sources += files('audio/ccp.c')
endif

if get_option('csip').enabled()
  builtin_modules += 'csip'
  builtin_sources += files('audio/csip.c')
endif

if get_option('asha').enabled()
  builtin_modules += 'asha'
  builtin_sources += files('audio/asha.c')
endif

if get_option('tools').enabled()
  executable('iapd',
    sources: 'iap/main.c',
    dependencies: [ libgdbus_internal_dep, glib_dep, dbus_dep ]
  )
endif

if cups_dep.found()
  executable('bluetooth',
    sources: [
      'cups/main.c',
      'cups/sdp.c',
      'cups/spp.c',
      'cups/hcrp.c'
    ],
    dependencies: [
      libbluetooth_internal_dep,
      libgdbus_internal_dep,
      glib_dep,
      dbus_dep
    ],
    install: true,
    install_dir: cups_serverbin / 'backend'
  )
endif

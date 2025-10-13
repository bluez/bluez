if get_option('tools').enabled() and readline_dep.found()
  executable('mesh-cfgclient',
    sources: [ '../mesh-cfgclient.c',
      'cfgcli.c',
      'keys.c',
      'util.c',
      'remote.c',
      'agent.c',
      'mesh-db.c',
      '../../mesh/util.c',
      '../../mesh/crypto.c',
    ],
    dependencies: [ libbluetooth_internal_dep, libshared_mainloop_dep, ell_dep, dbus_dep, jsonc_dep, readline_dep ],
    install: true
  )
endif

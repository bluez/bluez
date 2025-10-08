emulator_sources = files(
  'hciemu.c',
  'vhci.c',
  'btdev.c',
  'bthost.c',
  'smp.c',
)

if get_option('tests').enabled()
  executable('btvirt',
    sources: [ 'main.c',
      'serial.c',
      'server.c',
      'vhci.c',
      'btdev.c',
      'bthost.c',
      'smp.c',
      'phy.c',
      'le.c' ],
    dependencies: [ libbluetooth_internal_dep, libshared_mainloop_dep, glib_dep ],
    install: true,
    install_dir: pkglibexecdir
  )

  executable('b1ee',
    sources: 'b1ee.c',
    include_directories: '../lib',
    dependencies: libshared_mainloop_dep
  )

  executable('hfp',
    sources: 'hfp.c',
    dependencies: libshared_mainloop_dep
  )
endif


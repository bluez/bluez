shared_sources = [
  'queue.c',
  'util.c',
  'mgmt.c',
  'crypto.c',
  'ecc.c',
  'ringbuf.c',
  'hci.c',
  'hci-crypto.c',
  'hfp.c',
  'uhid.c',
  'pcap.c',
  'btsnoop.c',
  'ad.c',
  'att.c',
  'gatt-helpers.c',
  'gatt-client.c',
  'gatt-server.c',
  'gatt-db.c',
  'gap.c',
  'log.c',
  'bap.c',
  'bap-debug.c',
  'mcp.c',
  'vcp.c',
  'micp.c',
  'csip.c',
  'bass.c',
  'ccp.c',
  'asha.c'
]

if readline_dep.found()
  shared_sources += [ 'shell.c' ]
endif

libshared_glib = static_library('libshared-glib',
  sources: [ shared_sources,
    'io-glib.c',
    'timeout-glib.c',
    'mainloop-glib.c',
    'mainloop-notify.c',
    'tester.c' ],
  include_directories: '../../lib',
  dependencies: glib_dep
)

libshared_glib_dep = declare_dependency(
  link_with: libshared_glib,
  dependencies: glib_dep
)

libshared_mainloop = static_library('libshared-mainloop',
  sources: [ shared_sources,
    'io-mainloop.c',
    'timeout-mainloop.c',
    'mainloop.c',
    'mainloop-notify.c' ],
  include_directories: '../../lib',
  dependencies: glib_dep
)

libshared_mainloop_dep = declare_dependency(
  link_with: libshared_mainloop
)

if ell_dep.found()
  libshared_ell = static_library('libshared-ell',
    sources: [ shared_sources,
      'io-ell.c',
      'timeout-ell.c',
      'mainloop-ell.c' ],
    include_directories: [ '../..', '../../lib' ],
    dependencies: [ glib_dep, ell_dep ]
  )
  libshared_ell_dep = declare_dependency(
    link_with: libshared_ell,
    dependencies: ell_dep
  )
endif

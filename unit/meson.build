
tests1 = [
  [ 'test-tester.c' ],
  [ 'test-uuid.c' ],
  [ 'test-eir.c', '../src/eir.c', '../src/uuid-helper.c' ],
  [ 'test-sdp.c', '../src/sdpd-database.c', '../src/log.c', '../src/sdpd-service.c', '../src/sdpd-request.c' ],
  [ 'test-avrcp.c', '../src/log.c', 'avctp.c', 'avrcp-lib.c' ],
  [ 'test-lib.c' ],
  [ 'test-gatt.c' ],
  [ 'test-bap.c' ],
  [ 'test-micp.c' ],
  [ 'test-bass.c' ],
  [ 'test-vcp.c' ],
  [ 'test-hog.c',
    btio_sources,
    '../profiles/input/hog-lib.c',
    '../profiles/scanparam/scpp.c',
    '../profiles/battery/bas.c',
    '../profiles/deviceinfo/dis.c',
    '../src/log.c',
    '../attrib/att.c',
    '../attrib/gatt.c',
    '../attrib/gattrib.c'
  ],
]

foreach t: tests1
  test_name = t[0].substring(0, -2)
  exe = executable(test_name,
    sources: t,
    dependencies: [ libshared_glib_dep, libbluetooth_internal_dep ],
  )
  test(test_name, exe)
endforeach

tests2 = [
  [ 'test-textfile.c', '../src/textfile.c' ],
  [ 'test-crc.c', '../monitor/crc.c' ],
  [ 'test-crypto.c' ],
  [ 'test-ecc.c' ],
  [ 'test-ringbuf.c' ],
  [ 'test-queue.c' ],
  [ 'test-mgmt.c' ],
  [ 'test-uhid.c' ],
  [ 'test-hfp.c' ],
  [ 'test-avdtp.c', '../src/log.c', 'avdtp.c' ],
  [ 'test-avctp.c', '../src/log.c', 'avctp.c' ],
]

if ical_dep.found()
  tests2 += [
    [ 'test-gobex.c', 'util.c', gobex_sources ],
    [ 'test-gobex-packet.c', 'util.c', gobex_sources ],
    [ 'test-gobex-header.c', 'util.c', gobex_sources ],
    [ 'test-gobex-transfer.c', 'util.c', gobex_sources ],
    [ 'test-gobex-apparam.c', 'util.c', gobex_sources ],
  ]
endif

foreach t: tests2
  test_name = t[0].substring(0, -2)
  exe = executable(test_name,
    sources: t,
    c_args: [ '-DSTORAGEDIR="@0"'.format(storagedir) ],
    include_directories: '../lib',
    dependencies: libshared_glib_dep
  )
  test(test_name, exe)
endforeach

exe = executable('test-gdbus-client',
  sources: 'test-gdbus-client.c',
  dependencies: [ libgdbus_internal_dep, libshared_glib_dep ]
)
dbus_run_session = find_program('dbus-run-session')
if dbus_run_session.found()
  test('test-gdbus-client', dbus_run_session, args: [ '--', exe ])
else
  test('test-gdbus-client', exe)
endif

exe = executable('test-gattrib',
  sources: [ 'test-gattrib.c', '../attrib/gattrib.c', btio_sources, '../src/log.c' ],
  dependencies: [ libshared_glib_dep, libbluetooth_internal_dep ]
)
test('test-gattrib', exe)

if alsa_dep.found()
  exe = executable('test-midi',
    sources: [ 'test-midi.c', '../profiles/midi/libmidi.c' ],
    c_args: [ '-DMIDI_TEST' ],
    dependencies: [ libshared_glib_dep, alsa_dep ]
  )
  test('test-midi', exe)
endif

if get_option('mesh').enabled()
  exe = executable('test-mesh-crypto',
    sources: [ 'test-mesh-crypto.c' ],
    dependencies: [ ell_dep ]
  )
  test('test-mesh-crypto', exe)
endif

add_test_setup(
  'valgrind',
  exe_wrapper: [
    'valgrind', '--quiet', '--leak-check=full', '--trace-children=yes',
    '--suppressions=@0@'.format(meson.current_source_dir() / 'valgrind.supp'),
    '--num-callers=30', '--show-reachable=no', '--error-exitcode=1',
  ],
  # default timeout in meson is 30s
  timeout_multiplier: 4,
)

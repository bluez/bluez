lib_sources = [
  'bluetooth/bluetooth.c',
  'bluetooth/hci.c',
  'bluetooth/sdp.c',
]

lib_extra_sources = [
  'bluetooth/uuid.c'
]

lib_headers = [
  'bluetooth/bluetooth.h',
  'bluetooth/hci.h',
  'bluetooth/hci_lib.h',
  'bluetooth/sco.h',
  'bluetooth/l2cap.h',
  'bluetooth/sdp.h',
  'bluetooth/sdp_lib.h',
  'bluetooth/rfcomm.h',
  'bluetooth/bnep.h',
  'bluetooth/cmtp.h',
  'bluetooth/hidp.h'
  ]

if get_option('library').enabled()
  lib_bluetooth = shared_library('bluetooth',
    sources: lib_headers + lib_sources,
    version: '3.19.15',
    install: true
  )

  install_headers(lib_headers,
    subdir: 'bluetooth'
  )

  pkgconfig = import('pkgconfig')
  pkgconfig.generate(
    name: 'bluez',
    description: 'Bluetooth protocol stack for Linux',
    version: meson.project_version(),
    libraries: lib_bluetooth,
    license: 'GPL-2.0-or-later'
  )
endif

libbluetooth_internal = static_library('bluetooth_internal',
  sources: lib_headers + lib_sources + lib_extra_sources,
  install: false
)

libbluetooth_internal_dep = declare_dependency(
  link_with: libbluetooth_internal,
  include_directories: '.'
)

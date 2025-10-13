# SPDX-License-Identifier: GPL-2.0-or-later
project(
  'bluez', 'c',
  version: '5.84',
  license: 'LGPL-2.1-or-later AND GPL-2.0-or-later',
  meson_version: '>= 1.3.0'
)

datadir = get_option('datadir')
storagedir = '/' / get_option('localstatedir') / 'lib/bluetooth'
configdir = get_option('sysconfdir') / 'bluetooth'
pkglibdir = get_option('libdir') / 'bluetooth'
pkglibexecdir = get_option('libexecdir') / 'bluetooth'
meshstoragedir = storagedir / 'mesh'

service_conf = configuration_data()
service_conf.set('PKGLIBEXECDIR', pkglibexecdir)

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')
config_h = configuration_data()

cc = meson.get_compiler('c')

required_funcs = [
  'explicit_bzero',
  'getrandom',
  'rawmemchr',
  'signalfd',
]

foreach func: required_funcs
  cc.has_function(func, required: true)
endforeach

required_lib_funcs = [
  [ 'clock_gettime', 'rt' ],
  [ 'pthread_create', 'pthread' ],
  [ 'dlopen', 'dl' ]
]

foreach func: required_lib_funcs
  dep = cc.find_library(func[1], required: true)
  cc.has_function(func[0], dependencies: dep, required: true)
endforeach

required_headers = [
  'stdarg.h',
  'stdio.h',
  'string.h',
  'linux/types.h',
  'linux/if_alg.h',
  'linux/uinput.h',
  'linux/uhid.h',
  'sys/random.h'
]

foreach header: required_headers
  cc.has_header(header, required: true)
endforeach

# basename may be only available in libgen.h with the POSIX behavior,
# not desired here
config_h.set10('HAVE_DECL_BASENAME',
  cc.has_function('basename', prefix: '#define _GNU_SOURCE 1\n#include <string.h>'))

# To combine with -Wl,--gc-sections
add_project_arguments([ '-ffunction-sections', '-fdata-sections' ] , language: 'c')

# Maintainer mode
if get_option('buildtype').contains('debug')
  test_cflags = [
    '-Wno-unused-parameter',
    '-Wno-missing-field-initializers',
    '-Wdeclaration-after-statement',
    '-Wmissing-declarations',
    '-Wredundant-decls',
    '-Wcast-align',
    '-Wswitch-enum',
    '-Wformat',
    '-Wformat-security',
    '-Wstringop-overflow',
  ]

  if get_option('buildtype') == 'debugoptimized'
    test_cflags += '-D_FORTIFY_SOURCE=3'
  endif

  common_flags = [
    '-DG_DISABLE_DEPRECATED',
    '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_36',
    '-DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_36'
  ]

  common_flags += cc.get_supported_arguments(test_cflags)

  add_project_arguments(common_flags, language: 'c')

  config_h.set('HAVE_VALGRIND_MEMCHECK_H',
    cc.has_header('valgrind/memcheck.h', required: get_option('valgrind').enabled()))
endif

test_cflags = [
  '-ffunction-sections',
  '-fdata-sections'
]

add_project_arguments(cc.get_supported_arguments(test_cflags), language: 'c')
add_project_arguments('-I' + meson.project_build_root(), language: 'c')
add_project_arguments('-I' + meson.project_source_root(), language: 'c')
add_project_link_arguments('-Wl,--gc-sections', language: 'c')

dummy_dep = dependency('dummy', required: false)
glib_dep = dependency('glib-2.0', version: '>= 2.36')
dbus_dep = dependency('dbus-1', version:'>= 1.10')

cc.check_header('elfutils/libdwfl.h', required: get_option('backtrace'))
backtrace_dep = cc.find_library('dw', required: get_option('backtrace'))
config_h.set('HAVE_BACKTRACE_SUPPORT', backtrace_dep.found())

config_h.set10('HAVE_DECL_SOF_TIMESTAMPING_TX_COMPLETION',
  cc.has_header_symbol('linux/net_tstamp.h', 'SOF_TIMESTAMPING_TX_COMPLETION'))
config_h.set10('HAVE_DECL_SCM_TSTAMP_COMPLETION',
  cc.has_header_symbol('linux/errqueue.h', 'SCM_TSTAMP_COMPLETION', prefix: '#include <time.h>'))

udev_required = get_option('udev').enabled() or get_option('sixaxis').enabled() or
    get_option('hid2hci').enabled()
udev_dep = dependency('udev', version:'>= 196', required: udev_required)
udevlib_dep = dependency('libudev', required: udev_required)

cups_dep = dependency('cups', required: get_option('cups'))
jsonc_dep = dependency('json-c', version: '>= 0.13', required: get_option('mesh'))
alsa_dep = dependency('alsa', required: get_option('midi'))
ical_dep = dependency('libical', required: get_option('obex'))
readline_dep = dependency('readline',
  required: get_option('client').enabled() or
    get_option('mesh').enabled())
systemd_dep = dependency('systemd', required: get_option('systemd'))
libsystemd_dep = dependency('libsystemd', required: get_option('systemd'))
ell_dep = dependency('ell',
  version: '>= 0.39',
  required: get_option('btpclient').enabled() or get_option('mesh').enabled(),
  fallback : ['ell', 'libell_dep'],
  default_options: [
    'default_library=static',
    'tests=false',
    'cert-tests=false'
  ]
)

rst2man = find_program('rst2man', 'rst2man.py', required: get_option('manpages'))
if rst2man.found()
  rst2man_command = [
    rst2man,
    '--strict',
    '--no-raw',
    '--no-generator',
    '--no-datestamp',
    '@INPUT@',
    '@OUTPUT@'
  ]
endif

man_conf = configuration_data()
man_conf.set('CONFIGDIR', get_option('prefix') / configdir)
man_conf.set('MESH_STORAGEDIR', get_option('prefix') / meshstoragedir)

if get_option('phonebook') == 'ebook'
  ebook_dep = dependency('libebook-1.2', '>= 3.3', required: true)
  edataserver_dep = dependency('libedataserver-1.2', '>= 3.3', required: true)
else
  ebook_dep = dummy_dep
  edataserver_dep = dummy_dep
endif

plugindir = get_option('libdir') / 'bluetooth/plugins'

dbusconfdir = get_option('dbusconfdir')
if dbusconfdir == ''
  dbusconfdir = dbus_dep.get_variable('datadir')
endif
dbusdir = dbusconfdir / 'dbus-1/system.d'

dbussystembusdir = get_option('dbussystembusdir')
if dbussystembusdir == ''
  dbussystembusdir = dbus_dep.get_variable('system_bus_services_dir')
endif

dbussessionbusdir = get_option('dbussessionbusdir')
if dbussessionbusdir == ''
  dbussessionbusdir = dbus_dep.get_variable('session_bus_services_dir')
endif

service_in = configuration_data()
service_in.set_quoted('PKGLIBEXECDIR', get_option('prefix') / pkglibexecdir)

if systemd_dep.found()
  systemdsystemunitdir = get_option('systemdsystemunitdir')
  if systemdsystemunitdir == ''
    systemdsystemunitdir = systemd_dep.get_variable('systemdsystemunitdir')
  endif
  systemduserunitdir = get_option('systemduserunitdir')
  if systemduserunitdir == ''
    systemduserunitdir = systemd_dep.get_variable('systemduserunitdir')
  endif
endif

zshcompletiondir = get_option('zsh-completion-dir')
if zshcompletiondir == ''
  zshcompletiondir = datadir / 'zsh/site-functions'
endif

fs = import('fs')
zsh_completions = fs.is_dir(zshcompletiondir)

if udev_dep.found()
  udevdir = get_option('udevdir')
  if udevdir == ''
    udevdir = udev_dep.get_variable('udevdir')
  endif
endif

if cups_dep.found()
  cups_serverbin = get_option('cups_serverbin')
  if cups_serverbin == ''
    cups_serverbin = cups_dep.get_variable('cups_serverbin')
  endif
endif

external_plugins_link_args = ''
if get_option('external-plugins').enabled()
  external_plugins_link_args = [
    '-Wl,--export-dynamic',
    '-Wl,--version-script=' + meson.project_source_root() / 'src/bluetooth.ver'
  ]
endif

config_h.set('HAVE_A2DP', get_option('a2dp').enabled())
config_h.set('HAVE_AVRCP', get_option('avrcp').enabled())
config_h.set('HAVE_ASHA', get_option('asha').enabled())
config_h.set('HAVE_VCP', get_option('vcp').enabled())
config_h.set10('EXTERNAL_PLUGINS', get_option('external-plugins').enabled())
config_h.set_quoted('VERSION', meson.project_version())

configure_file(
  output: 'config.h',
  configuration: config_h
)

subdir('lib')
subdir('gdbus')
subdir('attrib')
subdir('btio')
subdir('plugins')
subdir('profiles')
subdir('src')
if get_option('client').enabled()
  subdir('client')
endif
if get_option('monitor').enabled()
  subdir('monitor')
endif
subdir('emulator')
subdir('gobex')
subdir('tools')
subdir('peripheral')
if get_option('obex').enabled()
  subdir('obexd')
endif
if zsh_completions
  subdir('completion')
endif
if get_option('mesh').enabled()
  subdir('mesh')
endif
if rst2man.found()
  subdir('doc')
endif
if not get_option('tests').disabled()
  subdir('test')
  subdir('unit')
endif

# Fix permissions on install
install = find_program('install')
sh = find_program('sh')
meson.add_install_script(sh, '-c', 'install -dm755 ${DESTDIR}/' + configdir)
meson.add_install_script(sh, '-c', 'install -dm700 ${DESTDIR}/' + storagedir)
if get_option('mesh').enabled()
  meson.add_install_script(sh, '-c', 'install -dm700 ${DESTDIR}/' + meshstoragedir)
endif

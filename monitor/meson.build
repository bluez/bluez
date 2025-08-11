executable('btmon',
  sources: [
    'main.c',
    'display.c',
    'hcidump.c',
    'ellisys.c',
    'control.c',
    'packet.c',
    'vendor.c',
    'lmp.c',
    'crc.c',
    'll.c',
    'l2cap.c',
    'sdp.c',
    'avctp.c',
    'avdtp.c',
    'a2dp.c',
    'rfcomm.c',
    'bnep.c',
    'hwdb.c',
    'keys.c',
    'analyze.c',
    'intel.c',
    'broadcom.c',
    'msft.c',
    'jlink.c',
    'att.c',
    '../src/log.c',
    '../src/textfile.c',
    '../src/settings.c'
  ],
  c_args: [
    '-DSTORAGEDIR="@0"'.format(storagedir)
  ],
  dependencies: [ libbluetooth_internal_dep, libshared_mainloop_dep, udevlib_dep, glib_dep ],
  install: true
)

if get_option('manpages').enabled()
  custom_target(
    input: 'btmon.rst',
    output: 'btmon.1',
    command: rst2man_command,
    install: true,
    install_dir: get_option('mandir') / 'man1'
  )
endif

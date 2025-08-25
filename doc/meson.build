man_pages = [
  'hci.7',
  'iso.7',
  'mgmt.7',
  'l2cap.7',
  'rfcomm.7',
  'sco.7',
  'org.bluez.Adapter.5',
  'org.bluez.Bearer.LE.5',
  'org.bluez.Bearer.BREDR.5',
  'org.bluez.Device.5',
  'org.bluez.DeviceSet.5',
  'org.bluez.AgentManager.5',
  'org.bluez.Agent.5',
  'org.bluez.ProfileManager.5',
  'org.bluez.Profile.5',
  'org.bluez.NetworkServer.5',
  'org.bluez.Network.5',
  'org.bluez.Input.5',
  'org.bluez.BatteryProviderManager.5',
  'org.bluez.BatteryProvider.5',
  'org.bluez.Battery.5',
  'org.bluez.AdminPolicySet.5',
  'org.bluez.AdminPolicyStatus.5',
  'org.bluez.Media.5',
  'org.bluez.MediaControl.5',
  'org.bluez.MediaPlayer.5',
  'org.bluez.MediaFolder.5'
]

foreach man_page: man_pages
  man_page_name = man_page.substring(0, -2)
  man_section = man_page.substring(-1)
  custom_target(man_page,
    input: man_page_name + '.rst',
    output: man_page,
    command: rst2man_command,
    install: true,
    install_dir: get_option('mandir') / 'man@0@'.format(man_section)
  )
endforeach

# BlueZ Release Notes
**Period:** November 21, 2025 - January 8, 2026

This release includes 68 pull requests containing bug fixes, new features, and improvements across various BlueZ components.

## Summary

This release brings significant improvements to:
- **LE Audio Support**: Enhanced BAP (Basic Audio Profile), VCP (Volume Control Profile), and MCP (Media Control Profile) implementations
- **TMAP & GMAP Services**: New support for Telephony and Media Audio Profiles and Gaming Audio Profiles
- **Bearer Management**: Complete implementation of Connect/Disconnect methods for bearer handling
- **Bug Fixes**: Numerous stability and correctness fixes across audio, OBEX, device management, and testing frameworks

---

## Audio Profiles & Features

### BAP (Basic Audio Profile)
- **transport: distinguish BAP mic and playback volumes** ([#1773](https://github.com/bluez/bluez/pull/1773))
  - Cleanup uuid comparisons in device transport volume set/get
  - Use separate functions for set/get AVRCP volume to avoid mixing AVRCP and VCP volumes
  - Fix VCP volume update notifications on all transports

- **transport: distinguish BAP mic and playback volumes** ([#1770](https://github.com/bluez/bluez/pull/1770))
  - Earlier version addressing BAP volume handling

- **bap: remove setup from bcast_snks when freed** ([#1764](https://github.com/bluez/bluez/pull/1764))
  - Fix cleanup of broadcast sink setup data

- **shared/bap: fix invalid BAP server transition releasing -> qos** ([#1716](https://github.com/bluez/bluez/pull/1716))
  - Correct state machine transitions in BAP server

- **transport: fix VCP volume updating and sink volumes** ([#1687](https://github.com/bluez/bluez/pull/1687))
  - Fix Volume Control Profile volume synchronization

### MCP (Media Control Profile)
- **mcp: expose org.bluez.MediaPlayer information via GMCS** ([#1754](https://github.com/bluez/bluez/pull/1754))
  - Integrate MediaPlayer D-Bus interface with Generic Media Control Service

- **mcp: expose org.bluez.MediaPlayer information via GMCS** ([#1747](https://github.com/bluez/bluez/pull/1747))
  - Earlier implementation of GMCS MediaPlayer exposure

- **mcp: support multiple MCP and implement local GMCS** ([#1739](https://github.com/bluez/bluez/pull/1739))
- **mcp: support multiple MCP and implement local GMCS** ([#1737](https://github.com/bluez/bluez/pull/1737))
- **mcp: support multiple MCP and implement local GMCS** ([#1733](https://github.com/bluez/bluez/pull/1733))
- **mcp: support multiple MCP and implement local GMCS** ([#1732](https://github.com/bluez/bluez/pull/1732))
- **mcp: support multiple MCP and implement local GMCS** ([#1724](https://github.com/bluez/bluez/pull/1724))
- **mcp: support multiple MCP and implement local GMCS** ([#1723](https://github.com/bluez/bluez/pull/1723))
- **mcp: support multiple MCP and implement local GMCS** ([#1719](https://github.com/bluez/bluez/pull/1719))
  - Multiple iterations implementing support for multiple Media Control Profiles and Generic Media Control Service

### TMAP & GMAP Services
- **Add local TMAS & GMAS servers** ([#1711](https://github.com/bluez/bluez/pull/1711))
  - Move string versions of UUID to uuid.h
  - Implement local Telephony and Media Audio Servers and Gaming Audio Servers

- **Add TMAP & GMAP information services** ([#1703](https://github.com/bluez/bluez/pull/1703))
- **Add TMAP & GMAP information services** ([#1696](https://github.com/bluez/bluez/pull/1696))
- **Add TMAP & GMAP information services** ([#1679](https://github.com/bluez/bluez/pull/1679))
  - Multiple iterations implementing TMAP and GMAP information services

### BASS (Broadcast Audio Scan Service)
- **bass: Fix attempting to create multiple assistant for the same stream** ([#1707](https://github.com/bluez/bluez/pull/1707))
  - Prevent duplicate assistant creation for broadcast streams

- **bass: Fix attaching to unicast session** ([#1705](https://github.com/bluez/bluez/pull/1705))
  - Correct unicast session attachment logic

### HFP (Hands-Free Profile)
- **audio/hfp-hf: Add Operator name support** ([#1753](https://github.com/bluez/bluez/pull/1753))
- **audio/hfp-hf: Add Operator name support** ([#1748](https://github.com/bluez/bluez/pull/1748))
  - Add support for displaying mobile network operator name

### AVRCP (Audio/Video Remote Control Profile)
- **avrcp: fix AVRCP_STATUS_INVALID_PARAM** ([#1642](https://github.com/bluez/bluez/pull/1642))
  - Fix invalid parameter status handling

### General Audio
- **client/player: Refcount registered endpoints** ([#1742](https://github.com/bluez/bluez/pull/1742))
  - Add reference counting to media endpoints

- **client/player: Fix QoS 32_2_1 in lc3_ucast_presets** ([#1741](https://github.com/bluez/bluez/pull/1741))
  - Correct LC3 unicast preset QoS parameters

- **client/player: Print MediaEndpoint.SupportedFeatures** ([#1700](https://github.com/bluez/bluez/pull/1700))
  - Display supported features for media endpoints

- **client: Fix transport.acquire auto not working as initiator** ([#1702](https://github.com/bluez/bluez/pull/1702))
  - Fix automatic transport acquisition in initiator role

- **transport/audio: fix build with a2dp support disabled** ([#1677](https://github.com/bluez/bluez/pull/1677))
  - Allow building without A2DP support

---

## Bearer Management

- **bearer: Implement Connect/Disconnect methods** ([#1671](https://github.com/bluez/bluez/pull/1671))
- **bearer: Implement Connect/Disconnect methods** ([#1668](https://github.com/bluez/bluez/pull/1668))
  - Add Connect and Disconnect methods for bearer management

- **Add implementation of bearer connect/disconnect** ([#1701](https://github.com/bluez/bluez/pull/1701))
- **Add implementation of bearer connect/disconnect** ([#1699](https://github.com/bluez/bluez/pull/1699))
- **Add implementation of bearer connect/disconnect** ([#1692](https://github.com/bluez/bluez/pull/1692))
- **Add implementation of bearer connect/disconnect** ([#1688](https://github.com/bluez/bluez/pull/1688))
  - Multiple iterations of bearer connection management implementation

- **profiles: Add bearer field to btd_profile** ([#1681](https://github.com/bluez/bluez/pull/1681))
  - Add bearer field to profile structure

- **client: Fix issue of bearer info not printing correctly** ([#1672](https://github.com/bluez/bluez/pull/1672))
  - Fix bearer information display in client tools

---

## Device Management

### Authentication & Security
- **device: Limit the number of retries on auth failures** ([#1709](https://github.com/bluez/bluez/pull/1709))
- **device: Limit the number of retries on auth failures** ([#1654](https://github.com/bluez/bluez/pull/1654))
  - Prevent excessive authentication retry attempts

- **device: Fix the return type of device_irk_cmp()** ([#1666](https://github.com/bluez/bluez/pull/1666))
  - Correct return type for IRK (Identity Resolving Key) comparison function

### Battery
- **shared/battery: improve the display of the charge level** ([#1663](https://github.com/bluez/bluez/pull/1663))
- **battery: improve the display of the charge level** ([#1623](https://github.com/bluez/bluez/pull/1623))
  - Enhanced battery charge level reporting and display

### GATT
- **gatt-client: Implement error handling for DB_OUT_OF_SYNC in GATT caching** ([#1715](https://github.com/bluez/bluez/pull/1715))
  - Add proper handling for database out-of-sync errors in GATT cache

### Input Devices
- **input/device: Fix off by one report descriptor size error** ([#1710](https://github.com/bluez/bluez/pull/1710))
  - Fix buffer size calculation for HID report descriptors

---

## OBEX

- **obex: forward nicer failure messages to dbus** ([#1616](https://github.com/bluez/bluez/pull/1616))
  - Improve error message reporting over D-Bus

- **obexd: Fix transfer status change** ([#1684](https://github.com/bluez/bluez/pull/1684))
  - Correct transfer status state transitions

---

## Bluetooth Core & HCI

### ISO (Isochronous Channels)
- **lib: Rename bt_iso_io_qos phy field to phys** ([#1777](https://github.com/bluez/bluez/pull/1777))
  - Rename field to reflect support for multiple PHYs

- **monitor: show ISO timestamps and fix their handling** ([#1713](https://github.com/bluez/bluez/pull/1713))
  - Add timestamp display and fix timestamp handling for ISO channels

- **monitor: Fix parsing of BT_HCI_CMD_LE_SET_CIG_PARAMS** ([#1755](https://github.com/bluez/bluez/pull/1755))
  - Fix parsing of CIG (Connected Isochronous Group) parameters

### L2CAP & PHY
- **l2cap-test: Add tests for LE 2M and Coded PHYs** ([#1734](https://github.com/bluez/bluez/pull/1734))
- **l2cap-test: Add tests for BT_PHY** ([#1726](https://github.com/bluez/bluez/pull/1726))
  - Add test coverage for different Bluetooth PHY types

### Emulator
- **emulator: Add support for BT_HCI_CMD_CHANGE_CONN_PKT_TYPE** ([#1750](https://github.com/bluez/bluez/pull/1750))
  - Add HCI command support to test emulator

### Monitor
- **monitor: Add unknown options decoding for Configure Response** ([#1708](https://github.com/bluez/bluez/pull/1708))
  - Improve decoding of configuration response options

---

## Testing & Quality

### 6LoWPAN
- **6lowpan-tester: add test for header compression** ([#1769](https://github.com/bluez/bluez/pull/1769))
- **6lowpan-tester: add test for header compression** ([#1629](https://github.com/bluez/bluez/pull/1629))
  - Add tests for IPv6 over Bluetooth Low Energy header compression

### SCO Testing
- **sco-tester: add timeout / close during connection tests** ([#1698](https://github.com/bluez/bluez/pull/1698))
- **sco-tester: add timeout / close during connection tests** ([#1680](https://github.com/bluez/bluez/pull/1680))
  - Add test cases for SCO connection timeouts and closures

### Unit Tests
- **unit: reduce macro expansion volume** ([#1718](https://github.com/bluez/bluez/pull/1718))
  - Optimize macro usage in unit tests

---

## Build System & Configuration

- **build: Allow systemd unit build without libsystemd** ([#1714](https://github.com/bluez/bluez/pull/1714))
  - Enable building systemd units without requiring libsystemd library

- **build: Fix distcheck while installing org.bluez.obex.service with --disable-systemd** ([#1615](https://github.com/bluez/bluez/pull/1615))
  - Fix distribution checks when systemd is disabled

- **Support for config fragments (conf.d style dirs)** ([#1735](https://github.com/bluez/bluez/pull/1735))
  - Add support for configuration file fragments in conf.d directories

---

## Documentation

- **doc: Add new telephony related profiles interfaces** ([#1731](https://github.com/bluez/bluez/pull/1731))
- **doc: Add new telephony related profiles interfaces** ([#1670](https://github.com/bluez/bluez/pull/1670))
  - Document telephony profile D-Bus interfaces

---

## Bug Fixes

### Configuration & Parameters
- **main: Fix wrong option name in LE options array** ([#1695](https://github.com/bluez/bluez/pull/1695))
  - Correct option name in LE configuration

- **main: Validate the AdvMon scan parameters correctly** ([#1693](https://github.com/bluez/bluez/pull/1693))
  - Add proper validation for Advertisement Monitor scan parameters

- **main: fix bool vs. gboolean type in g_option_context_parse()** ([#1706](https://github.com/bluez/bluez/pull/1706))
  - Fix type mismatch in GLib option parsing

### Shell & UI
- **shared/shell: Don't init input for non-interactive shells** ([#1752](https://github.com/bluez/bluez/pull/1752))
  - Skip input initialization when running in non-interactive mode

### mpris-proxy
- **mpris-proxy: Only be started by pipewire.service** ([#1661](https://github.com/bluez/bluez/pull/1661))
  - Adjust service dependencies for MPRIS proxy

---

## Notes

- All pull requests in this release were submitted through the Patchwork system (indicated by PW_SID identifiers)
- This release includes iterative improvements to several major features, particularly in LE Audio support
- Multiple revisions of certain features (MCP, TMAP/GMAP, bearer management) indicate thorough review and refinement

---

**Total Changes:**
- 68 pull requests closed
- Major areas: Audio profiles (30+), Device management (8), Testing (7), Build system (3)
- Contributors: Multiple community contributors via Patchwork

For detailed information about specific changes, please refer to the individual pull requests linked above.

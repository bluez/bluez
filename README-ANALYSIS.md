# Lenovo IdeaPad Duet Keyboard Issue - Analysis Documentation

This directory contains detailed analysis of the Lenovo IdeaPad Duet 3/7 Folio Bluetooth keyboard connectivity issue.

## Quick Summary

**Problem**: Lenovo IdeaPad Duet keyboards pair but don't send input events unless CapsLock is pressed before detaching.

**Root Cause**: The keyboard firmware requires a Feature Report write (value `0x02` to Feature Report ID `0x01`) to enable input notifications. BlueZ currently only writes this when there's an LED state to restore (e.g., CapsLock ON).

**Solution**: Add device-specific initialization in `profiles/input/hog-lib.c` to write the Feature Report after connection.

## Analysis Documents

### 1. SUMMARY.md
**Start here** - Executive summary of the issue, root cause, and recommended fix approach.

Key sections:
- Root cause explanation
- Why CapsLock workaround works
- Three proposed solution options
- Recommendation: Device-specific quirk (Option 2)
- Testing requirements

### 2. ANALYSIS.md
**Detailed technical analysis** - Comprehensive btmon trace analysis comparing working vs non-working scenarios.

Key sections:
- Line-by-line btmon trace comparison
- Connection sequence analysis
- Handle 0x0024 processing differences
- CCC descriptor analysis
- Protocol-level evidence

### 3. Code Analysis (in ANALYSIS.md)
**BlueZ implementation review** - Analysis of current HoG (HID over GATT) code.

Key sections:
- Current report initialization behavior
- Output report handling explanation
- Proposed fix locations
- Sample code for fixes

## Key Files in BlueZ

- `profiles/input/hog-lib.c` - Main HID over GATT implementation (1851 lines)
  - Line 450-453: Input report notification enablement
  - Line 746-778: `forward_report()` - Output report handler
  - Line 989-1022: `uhid_create()` - UHID device creation

## Key Findings

### btmon Evidence
| File | CapsLock | Handle 0x0024 Operation | Input Events |
|------|----------|------------------------|--------------|
| btmon1.log | OFF | READ only (value: 0x00) | ❌ NONE |
| btmon2.log | ON | WRITE 0x02 at 17.018495 | ✅ Continuous |

### The Critical Write
```
btmon2.log line 611:
< ACL Data TX: ATT: Write Request (0x12) len 3
  Handle: 0x0024 Type: Report (0x2a4d)
  Data[1]: 02
```

Immediately followed by:
```
> ACL Data RX: ATT: Handle Value Notification (0x1b)
  Handle: 0x0018 Type: Report (0x2a4d)
  Data[8]: 0000000000000000
```

**This write enables the keyboard!**

## Implementation Guidance

### Recommended Approach
Implement device-specific quirk in `hog-lib.c`:

1. Add quirk detection for Lenovo keyboards (Vendor: 0x17ef, Product: 0x60fa)
2. Add initialization function to write Feature Report ID 0x01 with value 0x02
3. Call after UHID device creation
4. Test with btmon to verify write occurs

### Testing Checklist
- [ ] Works with CapsLock OFF (primary issue)
- [ ] Still works with CapsLock ON
- [ ] Test Duet 3 (Product: 0x60fa)
- [ ] Test Duet 7 (Product: TBD)
- [ ] No regression on other BT keyboards
- [ ] btmon shows Feature Report write at connection

## Device Information

From btmon PnP ID (0x2a50):
- Vendor: `0x17ef` (Lenovo)
- Product: `0x60fa` (Duet 3)
- Device Name: "Lenovo Duet 3 BT Folio"

Handle Information:
- Handle 0x0024: Feature Report (Report ID: 0x01, Type: 0x02)
- Handle 0x0025: Report Reference descriptor for 0x0024
- Handle 0x0036: Input Report (touchpad)
- Handle 0x0018: Input Report (keyboard)

## Questions & Answers

**Q: Why does pressing CapsLock before detaching fix it?**
A: CapsLock LED state triggers a UHID_OUTPUT event on reconnection. This causes BlueZ to write to an output report, which incidentally wakes up the keyboard firmware.

**Q: Is this a BlueZ bug or keyboard firmware issue?**
A: It's a keyboard firmware quirk. The device should send notifications when CCC is enabled, but it requires an additional initialization write. BlueZ needs a workaround.

**Q: Will this fix affect other devices?**
A: Not if implemented as a device-specific quirk (recommended). Only Lenovo keyboards with matching VID/PID will receive the initialization write.

**Q: What is Feature Report ID 0x01?**
A: It appears to be a device-specific control report. Value 0x02 seems to mean "wake up / enable input notifications".

## Related Issues

This pattern may affect other devices with similar firmware behavior:
- Devices that require initialization writes to Feature Reports
- Devices that only wake up when output reports are written
- Other Lenovo HID devices (tablets, keyboards)

## Contact & Contribution

This analysis was performed based on btmon traces and BlueZ source code review. The actual fix implementation should be tested on real hardware before merging.

For questions or additional device information, refer to the original issue report.

# Investigation Summary: Lenovo IdeaPad Duet Keyboard Issue

## Issue Description
Lenovo IdeaPad Duet 3/7 Folio BT keyboards pair successfully but fail to send any input events (keyboard or touchpad) unless CapsLock is pressed before detaching the keyboard from the tablet.

## Investigation Results

### btmon Trace Analysis
Analyzed two btmon traces comparing working vs non-working scenarios:
- **btmon1.log**: CapsLock OFF before detach (NOT WORKING)
- **btmon2.log**: CapsLock ON before detach (WORKING)

### Root Cause Identified

**The Lenovo keyboards require a specific Feature Report write during connection initialization to enable input notifications.**

#### Key Evidence:
1. **btmon2.log (WORKING)**: BlueZ writes value `0x02` to handle `0x0024` (Feature Report ID 0x01)
   - Timestamp: 17.018495
   - Immediately after: Device starts sending Handle Value Notifications with input data

2. **btmon1.log (NOT WORKING)**: BlueZ only reads handle `0x0024`, never writes
   - No write operation to Feature Report
   - Device never sends Handle Value Notifications
   - Keyboard remains silent

### Why CapsLock State Matters

The workaround (pressing CapsLock) works because:
1. CapsLock LED is ON when keyboard detaches
2. On reconnection, kernel sends UHID_OUTPUT event to restore LED state
3. BlueZ's `forward_report()` function writes the output report to the device
4. **This write incidentally wakes up the keyboard firmware**
5. Keyboard starts sending input notifications

When CapsLock is OFF:
- No LED state to restore
- No UHID_OUTPUT events
- No writes to device
- Keyboard firmware stays in idle/low-power state
- No input events generated

### BlueZ Code Analysis

Current behavior in `profiles/input/hog-lib.c`:
- Line 450-453: **Only enables notifications for INPUT reports**
- Does NOT write to OUTPUT or FEATURE reports during initialization
- Only writes OUTPUT reports when UHID events occur (LED changes)
- Never writes to FEATURE reports during connection setup

### Proposed Solutions

#### Option 1: Unconditional Feature Report Initialization
Add a device initialization function after UHID creation that writes to Feature Report ID 0x01:

```c
static void initialize_device(struct bt_hog *hog)
{
    struct report *report;
    uint8_t init_value = 0x02;
    
    report = find_report_by_rtype(hog, HOG_REPORT_TYPE_FEATURE, 0x01);
    
    if (report && (report->properties & GATT_CHR_PROP_WRITE)) {
        write_char(hog, hog->attrib, report->value_handle,
                   &init_value, sizeof(init_value),
                   output_written_cb, hog);
    }
}
```

**Pros**: Simple, fixes the issue
**Cons**: May affect other HID devices that don't expect Feature Report writes

#### Option 2: Device-Specific Quirk
Add a quirk table for devices that need initialization:

```c
static bool needs_feature_init(struct bt_hog *hog)
{
    // Lenovo IdeaPad Duet keyboards
    // Vendor: 0x17ef (Lenovo), Product: 0x60fa (from btmon PnP ID)
    if (hog->vendor == 0x17ef && hog->product == 0x60fa) {
        return true;
    }
    return false;
}
```

**Pros**: Safe, targeted fix for affected devices
**Cons**: Requires maintaining quirk list

#### Option 3: Write All Feature Reports
After report discovery, write default/current values to all writable Feature Reports:

**Pros**: More thorough initialization
**Cons**: More complex, potential for unexpected behavior

## Recommendation

**Implement Option 2 (Device-Specific Quirk)** as it:
1. Fixes the issue for Lenovo keyboards
2. Doesn't risk breaking other devices
3. Follows established patterns in Bluetooth device handling
4. Can be expanded for other devices with similar issues

## Implementation Location

**File**: `profiles/input/hog-lib.c`

**Function to add**: Device initialization after UHID creation
- Add quirk detection function
- Add Feature Report write function
- Call from `uhid_create()` completion or `report_map_read_cb()`

## Testing Requirements

1. Verify fix with CapsLock OFF (primary failing case)
2. Verify fix with CapsLock ON (should still work)
3. Test both Lenovo Duet 3 and Duet 7 models
4. Test that other BT keyboards are not affected
5. Verify with btmon that Feature Report write occurs at connection
6. Verify input events are received immediately after connection

## Additional Notes

- The PnP ID from btmon shows: Vendor=0x17ef (Lenovo), Product=0x60fa
- Handle 0x0024 corresponds to Feature Report ID 0x01, Type 0x02
- The value 0x02 appears to be a device-specific wake/enable command
- This is a firmware quirk in the Lenovo keyboard implementation
- Similar issues may exist in other HID devices from the same manufacturer

## References

- Original issue: Lenovo IdeaPad Duet 3/7 Folio BT keyboard doesn't work
- btmon traces: btmon1.log (not working), btmon2.log (working)
- Workaround: Press CapsLock before detaching keyboard
- Code location: profiles/input/hog-lib.c in BlueZ source
- HID over GATT Profile Specification

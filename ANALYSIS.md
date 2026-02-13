# Analysis of Lenovo IdeaPad Duet 3/7 Folio BT Keyboard Issue

## Issue Summary

The Lenovo IdeaPad Duet 3/7 Folio BT keyboards pair successfully but fail to send any input events (keyboard or touchpad) after connection. However, pressing CapsLock before detaching the keyboard causes it to work correctly. This analysis examines the btmon traces to identify the root cause.

## btmon Trace Analysis

### Test Setup
Two btmon logs were provided:
- **btmon1.log**: CapsLock OFF before detaching keyboard (NOT WORKING)
- **btmon2.log**: CapsLock ON before detaching keyboard (WORKING)

### Connection Establishment (Both Cases)

Both traces show successful LE connection establishment:

```
btmon1.log (lines 1-100):
- LE Extended Advertising Report received (device F9:F6:9A:51:4D:F9)
- LE Extended Create Connection initiated
- LE Enhanced Connection Complete (Handle: 3585)
- Connection interval: 7.50 msec
- Successful encryption (LE Start Encryption with AES-CCM)
```

```
btmon2.log (lines 1-100):
- Same connection sequence
- Notable difference at line 103: LE Read Remote Used Features returns error
  "Connection Failed to be Established (0x3e)" but connection recovers
```

Both cases successfully establish the BLE connection and encryption. The initial connection phase is essentially identical.

### GATT Service Discovery (Both Cases)

Both traces show BlueZ discovering the HID over GATT (HOGP) service:

```
Common sequence:
1. ATT: Exchange MTU (Client: 247, Server: 517)
2. Read Battery Level (0x2a19) = 64
3. Read PnP ID (0x2a50) = 02ef17fa600800
4. Read Device Name (0x2a00) = "Lenovo Duet 3 BT Folio"
5. Read Peripheral Preferred Connection Parameters (0x2a04)
6. Discovery of multiple Report characteristics (0x2a4d)
```

### Critical Difference: Handle 0x0024 Processing

This is where the traces diverge significantly.

#### btmon1.log (NOT WORKING) - Lines 538-572

```
Line 538: < ATT: Read Request Handle: 0x0024 Type: Report (0x2a4d)
Line 556: > ATT: Read Response Value[1]: 00
Line 561: < ATT: Read Request Handle: 0x0025 Type: Report Reference (0x2908)
Line 572: > ATT: Read Response Value[2]: 0102
          Report Reference: Report ID=0x01, Type=0x02 (Feature Report)
```

**BlueZ only READS handle 0x0024, gets value 0x00, then moves on.**

#### btmon2.log (WORKING) - Lines 479-490, 611

```
Line 479: Handle: 0x0037 Type: CCC shows notifications already enabled (0x0100)
Line 490: Handle: 0x0036 Type: Report (CCC enabled)

Line 611: < ACL Data TX: ATT: Write Request (0x12) len 3
          Handle: 0x0024 Type: Report (0x2a4d)
          Data[1]: 02
```

**BlueZ WRITES value 0x02 to handle 0x0024!**

### Immediate Effect After Writing to 0x0024

#### btmon1.log: No Input Events

After reading handle 0x0024, the trace continues with:
- More report descriptor reads
- Report Map read (HID Report Descriptor)
- Multiple Write Requests to various report handles (0x003d, 0x0040, 0x0043)
- **ZERO Handle Value Notifications from input reports**

Even later in the trace (lines 800-1200), there are NO Handle Value Notifications (0x1b) from input report handles like 0x0018, 0x001c, or 0x0036.

#### btmon2.log: Input Events Start Immediately

```
Line 611: < Write Request Handle: 0x0024, Data[1]: 02
Line 619: > Write Response (0x13) - Write acknowledged

Immediately following (line 108, timestamp 17.034350):
> ACL Data RX: ATT: Handle Value Notification (0x1b) len 10
  Handle: 0x0018 Type: Report (0x2a4d)
  Data[8]: 0000000000000000
  
> ACL Data RX: ATT: Handle Value Notification (0x1b) len 5
  Handle: 0x001c Type: Report (0x2a4d)
  Data[3]: 000000
```

**The device starts sending input notifications within milliseconds of the write!**

Later in the trace (lines 360-413), continuous Handle Value Notifications are observed from handle 0x0036 (touchpad reports), showing the device is actively sending input data.

### Client Characteristic Configuration (CCC) Analysis

Both traces show that notifications are **already enabled** on the device for input reports:

```
btmon1.log line 662: Handle: 0x0037 CCC = 0x0100 (Notification enabled)
btmon2.log line 580: Handle: 0x0037 CCC = 0x0100 (Notification enabled)
```

BlueZ reads these CCC descriptors and finds notifications already enabled from a previous connection. BlueZ then writes 0x0100 to confirm/re-enable notifications.

**However, the device does not send notifications until the write to 0x0024 occurs.**

### Understanding Handle 0x0024 and Value 0x02

Based on the Report Reference descriptor read:
```
Report ID: 0x01
Report Type: 0x02 (Feature Report per HID spec)
```

In HID over GATT, Feature Reports can be used for:
1. Device configuration
2. Protocol mode switching
3. Suspend/wake control
4. LED control

The value 0x02 written to this Feature Report likely serves as a **wake-up command** or **enable input** command for the Lenovo keyboard firmware.

### Why CapsLock State Affects Behavior

When CapsLock is ON before detaching:
1. The CapsLock LED is illuminated
2. The keyboard maintains LED state in firmware
3. When reconnecting, BlueZ reads the output reports
4. BlueZ detects a non-zero output report value (LED state)
5. BlueZ's logic triggers a write to Feature Report 0x01 (handle 0x0024)
6. The write value 0x02 wakes up the keyboard
7. Keyboard starts sending input notifications

When CapsLock is OFF:
1. All LEDs are off
2. Keyboard firmware may be in a power-saving/idle state
3. When reconnecting, BlueZ reads output reports (all zeros)
4. BlueZ does NOT write to Feature Report 0x01
5. Keyboard stays in idle state
6. No input notifications are sent

## Root Cause

The Lenovo IdeaPad Duet keyboards require a **Feature Report write** to handle 0x0024 with value 0x02 after connection to enable input reporting. This is likely a firmware-specific initialization requirement.

BlueZ currently has conditional logic that only writes to certain HID reports when specific conditions are met (probably related to LED/output report state restoration). When the keyboard has no active LEDs (CapsLock OFF), this write does not occur, leaving the keyboard in an uninitialized state.

## Required Fix

The fix should be in `profiles/input/hog-lib.c` or `profiles/input/hog.c`:

1. **After HOGP service discovery and CCC descriptor setup**
2. **Unconditionally write to Feature Report with Report ID 0x01** (or identify the device-specific wake command)
3. The write should occur even when no output reports need restoration
4. This ensures the device firmware is properly initialized regardless of prior LED state

Alternatively:
- Detect devices that require this initialization (by VID/PID: Vendor=0x17ef Lenovo, Product=0x60fa)
- Apply the initialization sequence for affected devices

## HID over GATT Protocol Notes

According to the HID over GATT Profile specification:
- Notifications on input reports should be enabled via CCC descriptors (✓ working)
- Protocol Mode characteristic can switch between Boot and Report mode (may be relevant)
- Devices should send input reports automatically when CCC is enabled (✗ not working without 0x02 write)

The Lenovo keyboards appear to have non-standard firmware behavior requiring an explicit Feature Report write to begin sending input data.

## Comparison Summary

| Aspect | btmon1 (CapsLock OFF) | btmon2 (CapsLock ON) |
|--------|----------------------|---------------------|
| Connection | ✓ Success | ✓ Success |
| Encryption | ✓ Success | ✓ Success |
| Service Discovery | ✓ Success | ✓ Success |
| CCC Enable | ✓ Success | ✓ Success |
| Write to 0x0024 | ✗ Only READ | ✓ WRITE 0x02 |
| Input Notifications | ✗ NONE | ✓ Continuous |

## Files to Modify

Based on the codebase structure:
- `profiles/input/hog-lib.c` - Main HID over GATT library implementation
  - Look for output report restoration logic
  - Add unconditional Feature Report initialization
  - Consider device-specific quirks for Lenovo keyboards

## Testing Recommendations

1. Verify fix works with CapsLock OFF (primary use case)
2. Verify fix doesn't break with CapsLock ON (should still work)
3. Test with both Duet 3 and Duet 7 models
4. Test that other HID devices are not affected by the change
5. Monitor btmon output to confirm the write to 0x0024 occurs consistently

## Additional Evidence

The provided workaround script (`duet3-bt-wake.zip`) likely performs a similar write operation via D-Bus or direct GATT commands to wake the keyboard, confirming that a specific write command is needed to initialize the device.

# Pebble K380s reconnect investigation

Target device: Logitech Pebble K380s (`046d:b377`), Bluetooth address
`D2:92:89:C7:3A:ED` during the current pairing.

Symptom: after switching the keyboard to another Easy-Switch host and back,
BlueZ reports `Connected: yes` and exposes a UHID input node, but no key events
arrive. Resetting the USB Bluetooth adapter restores input.

The instrumentation in `profiles/input/hog-lib.c` records:

- HoG attach and rejected duplicate attach attempts;
- HoG detach and whether it is forced;
- CCC notification enablement;
- notification handler registration and removal;
- incoming HID report notifications.

## Capture protocol

1. Start `tools/capture-pebble-trace.sh`.
2. Reset the adapter and type several keys (known-good baseline).
3. Switch to another Easy-Switch channel for at least five seconds.
4. Switch back and type several keys (failing path).
5. Reset the adapter and type again (recovery baseline).
6. Stop capture with Ctrl+C.

## Experimental fix 1

The first capture showed a clean forced HoG detach when the keyboard left its
Linux Easy-Switch channel. No subsequent HoG attach occurred until the USB
adapter reset, at which point CCC subscriptions and input reports were restored.

For `046d:b377`, `device_remove_connection()` now removes and re-adds the device
to the kernel auto-connect list after an LE disconnect. This re-arms controller
background scanning without resetting the adapter or disturbing unrelated
Bluetooth devices.

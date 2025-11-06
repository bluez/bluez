---
name: New issue
about: 'Report a bug or other problem'
title: ''
labels: ''
assignees: ''

---

### Description

<!-- A clear and concise description of what the bug is -->

<!-- A clear and concise description of what you expected to happen -->

<!-- Include any other relevant details -->

### To reproduce
<!-- Steps to reproduce the issue, if possible -->
1.
2.
3.
4.

### Logs
- btmon log: <!-- Bluetooth traffic dump: (usually needed)
                  0. Power off connected device
                  1. Run: btmon -w btmon.log
                  2. Connect device, reproduce the issue
                  3. Ctrl-C btmon
                  4. Attach btmon.log to the issue -->
- bluetoothd log: <!-- Run: journalctl -u bluetooth --boot 0 > bluetoothd.log; if relevant for issue -->

<!-- Any other logs etc. relevant for the issue -->

### Versions
- BlueZ version:  <!-- Run: bluetoothctl --version -->
- Kernel version:  <!-- Run: uname -r -->
- Problematic device: <!-- Device model etc information, if relevant -->

<!-- Any other relevant information on platform / hardware here -->

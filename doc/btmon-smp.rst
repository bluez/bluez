.. This file is included by btmon.rst.

SMP PAIRING FLOW
================

The Security Manager Protocol (SMP) handles pairing, key generation,
and key distribution between Bluetooth devices. SMP traffic appears
inside L2CAP on fixed CID 0x0006 (LE) or CID 0x0007 (BR/EDR). btmon
decodes all SMP operations automatically.

Pairing Phases
--------------

SMP pairing proceeds in three phases. Each phase produces a distinct
pattern in the btmon output.

**Phase 1: Feature Exchange**

Pairing begins when one device sends a Security Request (peripheral)
or the host initiates pairing directly. The initiator sends a Pairing
Request and the responder replies with a Pairing Response::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 11       #497 [hci0] 0.026107
          SMP: Pairing Request (0x01) len 6
            IO capability: NoInputNoOutput (0x03)
            OOB data: Authentication data not present (0x00)
            Authentication requirement: Bonding, MITM, SC, CT2 (0x2d)
            Max encryption key size: 16
            Initiator key distribution: IdKey Sign (0x06)
            Responder key distribution: IdKey Sign (0x06)

    < ACL Data TX: Handle 2048 flags 0x00 dlen 11       #499 [hci0] 0.026894
          SMP: Pairing Response (0x02) len 6
            IO capability: KeyboardDisplay (0x04)
            OOB data: Authentication data not present (0x00)
            Authentication requirement: Bonding, SC, CT2 (0x29)
            Max encryption key size: 16
            Initiator key distribution: IdKey (0x02)
            Responder key distribution: IdKey (0x02)

Key fields to check:

- **Authentication requirement** -- The ``SC`` flag indicates Secure
  Connections. Its absence means Legacy Pairing.
- **IO capability** -- Determines the association model (Just Works,
  Passkey Entry, Numeric Comparison, OOB).
- **Key distribution** -- Which keys each side will send after
  encryption is established. ``IdKey`` = Identity Resolving Key (IRK),
  ``EncKey`` = Long Term Key (legacy only), ``Sign`` = CSRK.

**Phase 2: Authentication (Secure Connections)**

For Secure Connections pairing (``SC`` flag set), both devices exchange
public keys, then perform confirm/random value exchange::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 69       #501 [hci0] 0.098224
          SMP: Pairing Public Key (0x0c) len 64
            X: 1a2b3c4d...
            Y: 5e6f7a8b...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 69       #503 [hci0] 0.148556
          SMP: Pairing Public Key (0x0c) len 64
            X: 9c8d7e6f...
            Y: 0a1b2c3d...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #505 [hci0] 0.149003
          SMP: Pairing Confirm (0x03) len 16
            Confirm value: a1b2c3d4e5f6...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #507 [hci0] 0.212884
          SMP: Pairing Random (0x04) len 16
            Random value: 1122334455...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #509 [hci0] 0.213100
          SMP: Pairing Random (0x04) len 16
            Random value: 6677889900...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #511 [hci0] 0.278003
          SMP: Pairing DHKey Check (0x0d) len 16
            E: aabbccddee...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #513 [hci0] 0.278450
          SMP: Pairing DHKey Check (0x0d) len 16
            E: ffeeddccbb...

After DHKey Check, the initiator starts encryption at the HCI level::

    < HCI Command: LE Start Encryption (0x08|0x0019) plen 28  #515 [hci0] 0.279002
    > HCI Event: Encryption Change (0x08) plen 4              #517 [hci0] 0.342556
          Status: Success (0x00)
          Handle: 2048
          Encryption: Enabled with AES-CCM (0x01)

**Phase 2: Authentication (Legacy Pairing)**

Legacy pairing (no ``SC`` flag) skips the Public Key and DHKey Check
exchanges. Only Confirm and Random values are exchanged::

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #501 [hci0] 0.098224
          SMP: Pairing Confirm (0x03) len 16
            Confirm value: ...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #503 [hci0] 0.162556
          SMP: Pairing Confirm (0x03) len 16
            Confirm value: ...

    < ACL Data TX: Handle 2048 flags 0x00 dlen 21       #505 [hci0] 0.163003
          SMP: Pairing Random (0x04) len 16
            Random value: ...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #507 [hci0] 0.228884
          SMP: Pairing Random (0x04) len 16
            Random value: ...

**Phase 3: Key Distribution**

After encryption is established, each device distributes keys as
negotiated in Phase 1::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #519 [hci0] 0.343002
          SMP: Identity Information (0x08) len 16
            Identity resolving key: 00112233445566778899aabbccddeeff

    > ACL Data RX: Handle 2048 flags 0x02 dlen 12       #521 [hci0] 0.343556
          SMP: Identity Address Information (0x09) len 7
            Address type: Public (0x00)
            Address: 00:11:22:33:44:55

The Identity Address Information reveals the device's true public or
static random address (as opposed to a Resolvable Private Address used
during connection).

For Legacy Pairing, LTK distribution also appears::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 21       #519 [hci0] 0.343002
          SMP: Encryption Information (0x06) len 16
            Long term key: 00112233...

    > ACL Data RX: Handle 2048 flags 0x02 dlen 15       #521 [hci0] 0.343556
          SMP: Central Identification (0x07) len 10
            EDIV: 0x1234
            Rand: 0x0123456789abcdef

Pairing Failure
---------------

When pairing fails, one device sends a Pairing Failed PDU::

    > ACL Data RX: Handle 2048 flags 0x02 dlen 6        #505 [hci0] 0.213002
          SMP: Pairing Failed (0x05) len 1
            Reason: Authentication requirements (0x03)

SMP failure reasons:

.. list-table::
   :header-rows: 1
   :widths: 8 35 57

   * - Code
     - Reason
     - Diagnostic Meaning
   * - 0x01
     - Passkey Entry Failed
     - User cancelled or entered wrong passkey
   * - 0x02
     - OOB Not Available
     - OOB data expected but not provided
   * - 0x03
     - Authentication Requirements
     - Devices cannot agree on security level (e.g.,
       one requires MITM but IO caps only allow Just Works)
   * - 0x04
     - Confirm Value Failed
     - Cryptographic check failed; possible MITM attack
   * - 0x05
     - Pairing Not Supported
     - Remote does not support pairing
   * - 0x06
     - Encryption Key Size
     - Cannot agree on key size
   * - 0x07
     - Command Not Supported
     - Received unrecognized SMP command
   * - 0x08
     - Unspecified Reason
     - Generic failure
   * - 0x09
     - Repeated Attempts
     - Pairing rate-limited; wait before retry
   * - 0x0a
     - Invalid Parameters
     - Invalid fields in SMP command
   * - 0x0b
     - DHKey Check Failed
     - ECDH key agreement failed (SC only)
   * - 0x0c
     - Numeric Comparison Failed
     - User rejected numeric comparison
   * - 0x0d
     - BR/EDR Pairing In Progress
     - Classic pairing already active
   * - 0x0e
     - Cross-Transport Key Derivation Not Allowed
     - CTKD rejected by policy

Automating Pairing Analysis
----------------------------

**Identify all pairing attempts**::

    grep -n "Pairing Request\|Pairing Response\|Pairing Failed\|Pairing Public Key\|DHKey Check" output.txt

**Check pairing method (Secure Connections vs Legacy)**:

- If ``Pairing Public Key`` appears between Request/Response and
  Confirm: Secure Connections.
- If only Confirm/Random follow Request/Response: Legacy Pairing.
- Check the ``Authentication requirement`` line for the ``SC`` flag.

**Detect pairing failures**::

    grep -n "Pairing Failed" output.txt

**Correlate pairing with encryption**:

After successful pairing, expect ``Encryption Change`` with
``Status: Success``. Search for::

    grep -n "Encryption Change\|Encryption:" output.txt

**Identify re-pairing on reconnect**:

Reconnections to a bonded device should show ``Encryption Change``
without SMP traffic (using stored keys). If SMP Pairing Request
appears on reconnection, the bond was lost on one side.

**Full pairing diagnosis pattern**:

1. Find ``Pairing Request`` -- note the handle, IO capabilities,
   auth requirements
2. Find ``Pairing Response`` -- compare IO capabilities to determine
   association model
3. Check for ``Pairing Failed`` -- if present, the reason code
   identifies the failure
4. Check for ``Encryption Change`` with ``Status: Success`` -- confirms
   pairing completed
5. Check for ``Identity Address Information`` -- reveals the device's
   true address

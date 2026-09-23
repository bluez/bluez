==============
functional-hfp
==============

DESCRIPTION
===========

Hands-Free Profile (HFP) functional tests, `test/functional/test_hfp.py`,
using the BlueZ HFP Hands-Free (HF) implementation
(`profiles/audio/hfp-hf.c`) driven through the **telephony** submenu of
**bluetoothctl(1)**, see **bluetoothctl-telephony(1)**. See
**functional-testing(7)** for the conventions used here, and
**test-functional(1)** for how to run the suite.

STATUS
======

Supported today
---------------

HF role (host0)
	The ``hfp`` plugin (`profiles/audio/hfp-hf.c`, experimental,
	enabled with ``Experimental = true``) connects to the AG found in
	the SDP records of the peer and sets up the Service Level
	Connection (SLC) over RFCOMM using `src/shared/hfp.c`:
	``AT+BRSF``, ``AT+CIND=?``, ``AT+CIND?``, ``AT+CMER``, and after
	the SLC ``AT+CHLD=?`` (when the AG supports three-way calling),
	``AT+COPS``, ``AT+CLIP``, ``AT+CCWA``, ``AT+CMEE``, ``AT+NREC`` and
	``AT+CLCC``.

	It exposes an **org.bluez.Telephony1** object per connected AG,
	with the indicators reported by the AG (``Service``, ``Signal``,
	``Roaming``, ``BattChg``), ``OperatorName`` and ``InbandRingtone``,
	and an **org.bluez.Call1** object per call reported by the AG
	(``+CIEV``, ``+CLIP``, ``+CCWA``, ``+CLCC``).

	Of the call control, ``Dial``, ``Call1.Answer`` and
	``Call1.Hangup`` are supported.

bluetoothctl (host0)
	The **telephony** submenu lists and shows the audio gateways and
	calls, and can ``dial``, ``answer`` and ``hangup``.

AG role (host1)
	Not implemented by BlueZ, the test implements a minimal AG with
	**org.bluez.Profile1**. This is enough for the SLC and calls, and
	for the SCO socket once the HF supports audio.

btvirt
	Emulates SCO and eSCO links, with the CVSD and transparent air
	modes, and forwards the SCO data between the controllers, so no
	emulator changes are expected for the audio test cases.

This covers test_hfp_connect and test_hfp_disconnect.

Changes needed
--------------

Codec negotiation, in `src/shared/hfp.c`
	- Set Codec Negotiation (``HFP_HF_FEAT_CODEC_NEGOTIATION``, 0x80)
	  in the HF supported features sent with ``AT+BRSF``, which are
	  currently fixed by ``HFP_HF_FEATURES``.
	- Send ``AT+BAC=<codecs>`` after ``AT+BRSF`` when the AG supports
	  codec negotiation (0x200 in ``+BRSF``), listing CVSD and mSBC.
	- Handle ``+BCS: <codec>`` from the AG, replying ``AT+BCS=<codec>``
	  when the codec is supported, and report the selected codec to the
	  user of `src/shared/hfp.c`.
	- Optionally, request an audio connection with ``AT+BCC``.

Audio connection, in `profiles/audio/hfp-hf.c`
	- Listen for SCO connections from the AG, only accepting them from
	  a connected AG, and with the voice setting of the selected codec:
	  ``BT_VOICE_CVSD_16BIT`` for CVSD, ``BT_VOICE_TRANSPARENT`` for
	  mSBC.
	- Report the audio connection over D-Bus. The test cases assume a
	  **org.bluez.MediaTransport1** object for the telephony object, as
	  done for A2DP, with the ``Codec`` in use and its ``State``, which
	  the user acquires to get the SCO socket. This needs HFP support in
	  `profiles/audio/transport.c`, which only handles A2DP, BAP and
	  ASHA transports.

bluetoothctl
	- The errors of all the telephony commands are reported as
	  ``Failed to answer: <error>`` (`client/telephony.c`), which is
	  misleading for ``dial`` and ``hangup``.
	- Nothing to do for the audio connection when using a transport, as
	  the **transport** submenu already shows and acquires transports.

Other limitations, not needed by the test cases
	- ``HangupAll``, ``SwapCalls``, ``ReleaseAndAnswer``,
	  ``ReleaseAndSwap``, ``HoldAndAnswer``, ``CreateMultiparty`` and
	  ``SendTones`` return ``org.bluez.Error.NotSupported``, so
	  ``telephony.hangup-all`` fails.
	- ``HangupActive`` and ``HangupHeld`` are documented in
	  **org.bluez.Telephony(5)** but not implemented.
	- The HF does not publish an SDP record nor listen for RFCOMM
	  connections, so the SLC can only be connected by the HF.

The audio test cases, test_hfp_sco, are marked as expected to fail
(``xfail``) until these changes are done.

SETUP
=====

Two hosts, connected over BR/EDR:

.. code-block::

	+------------------------+                 +------------------------+
	| host0                  |     BR/EDR      | host1                  |
	| HF                     | --------------> | AG                     |
	| bluetoothd (hfp)       |   RFCOMM (AT)   | bluetoothd             |
	| bluetoothctl           |                 | Python AG (Profile1)   |
	|                        | <=============> |                        |
	+------------------------+       SCO       +------------------------+

	--> connection is initiated by      ==> audio flows towards

host0, the Hands-Free unit
	Runs **bluetoothd(8)** with ``Experimental = true``, as the ``hfp``
	plugin is experimental, and `bluetoothctl` to pair, connect and
	use the **telephony** submenu.

host1, the Audio Gateway
	BlueZ does not implement the AG role, so the test implements it:
	it registers an **org.bluez.Profile1** for the HFP AG UUID
	(``0000111f-0000-1000-8000-00805f9b34fb``) with ``Role = server``,
	which also publishes the SDP record the HF looks for. It answers the
	AT commands of the HF over the RFCOMM socket handed over by
	``NewConnection``, and handles the SCO socket for the audio
	connection. The AG supported features, in ``+BRSF``, are
	configurable, in particular Codec Negotiation (0x200), and the
	codecs it supports.

Both hosts run `bluetoothctl` with an agent answering the pairing
automatically. The AG profile is registered *before* pairing, so its
SDP record is in place when the HF resolves the services.

The HF connects the SLC itself, as the AG does not connect it: the hosts
are paired over BR/EDR, trust each other, and host0 connects.

Codecs
------

``CVSD`` (codec ID 1)
	Narrowband speech, mandatory. Used when codec negotiation is not
	supported by either side, or when the AG selects it. The SCO socket
	uses the default voice setting (``BT_VOICE_CVSD_16BIT``).

``mSBC`` (codec ID 2)
	Wideband speech. Requires codec negotiation on both sides: the HF
	lists it in ``AT+BAC=1,2`` and the AG selects it with ``+BCS: 2``,
	confirmed by the HF with ``AT+BCS=2``. The SCO socket uses the
	transparent voice setting (``BT_VOICE_TRANSPARENT``), i.e. the
	controller does not transcode the audio.

TEST CASES
==========

test_hfp_connect
----------------

:Setup: As above, with the AG not supporting codec negotiation.

:Steps:
	1. host1: register the AG profile.
	2. host0: pair with host1 over BR/EDR, and ``trust`` each other.
	3. host0: ``connect <host1 bdaddr>``.
	4. host0: ``telephony.list``.
	5. host0: ``telephony.show``.

:Expected:
	1. The AG profile is registered.
	2. ``Pairing successful``, ``trust succeeded`` on both hosts.
	3. ``Connection successful``. The AG receives the SLC setup, in
	   order: ``AT+BRSF=<features>``, ``AT+CIND=?``, ``AT+CIND?``,
	   ``AT+CMER=3,0,0,1``, then the commands following the SLC, e.g.
	   ``AT+COPS=3,0``, ``AT+CLIP=1``, ``AT+CCWA=1``, ``AT+CMEE=1``,
	   ``AT+NREC=0`` and ``AT+CLCC``.
	4. ``[NEW] Telephony /org/bluez/hci0/dev_XX/telephony0`` and the
	   audio gateway listed.
	5. ``Audio gateway /org/bluez/hci0/dev_XX/telephony0`` with
	   ``UUID: Handsfree Audio Gateway (0000111f-...)``,
	   ``State: connected``, and the indicators reported by the AG
	   (``Service``, ``Signal``, ``Roaming``, ``BattChg``), and
	   ``OperatorName`` as reported with ``+COPS``.

:Notes: Supported today.

	``connect`` has to be issued by the HF, as the ``hfp`` plugin
	does not listen for incoming connections. Without ``trust``, the
	AG blocks on an **org.bluez.Agent1.AuthorizeService** prompt.

test_hfp_disconnect
-------------------

:Setup: As test_hfp_connect, with the SLC connected.

:Steps: host0: ``disconnect <host1 bdaddr>``.

:Expected:
	1. The AG sees the RFCOMM socket closed.
	2. ``[DEL] Telephony /org/bluez/hci0/dev_XX/telephony0`` on host0.
	3. ``Disconnection successful``.

:Notes: Supported today.

test_hfp_sco[cvsd]
------------------

:Setup: As test_hfp_connect, with the AG not supporting codec
	negotiation.

:Steps:
	1. Connect the SLC as in test_hfp_connect.
	2. host1: connect SCO to host0 with the CVSD voice setting.
	3. host1: send audio data over the SCO socket.
	4. host1: close the SCO socket.

:Expected:
	1. The SLC is connected, the HF does not send ``AT+BAC``.
	2. The HF accepts the audio connection, which is reported on host0
	   as a transport for the telephony object, with ``Codec: 0x01``
	   (CVSD) and ``State: active``.
	3. The audio data is received on host0 over the transport.
	4. The transport is removed on host0.

:Notes: Needs changes: audio connection in the HF, see STATUS.
	Expected to fail until then.

test_hfp_sco[msbc]
------------------

:Setup: As test_hfp_connect, with the AG supporting codec negotiation
	(0x200 in ``+BRSF``) and the CVSD and mSBC codecs.

:Steps:
	1. Connect the SLC as in test_hfp_connect.
	2. host1: send ``+BCS: 2``.
	3. host1: connect SCO to host0 with the transparent voice setting.
	4. host1: send audio data over the SCO socket.
	5. host1: close the SCO socket.

:Expected:
	1. The HF supports codec negotiation, 0x80 in ``AT+BRSF``, and
	   lists its codecs with ``AT+BAC=1,2`` after ``AT+BRSF``.
	2. The HF confirms the codec with ``AT+BCS=2``, and the AG replies
	   ``OK``.
	3. The HF accepts the audio connection, with the transparent air
	   mode, which is reported on host0 as a transport for the
	   telephony object, with ``Codec: 0x02`` (mSBC) and
	   ``State: active``.
	4. The audio data is received on host0 over the transport.
	5. The transport is removed on host0.

:Notes: Needs changes: codec negotiation and audio connection in the
	HF, see STATUS. Expected to fail until then.

	The AG only connects SCO after the codec has been confirmed with
	``AT+BCS``. If the HF replies with another codec, or with
	``ERROR``, the AG shall select the codec again or fall back to
	CVSD.

test_hfp_sco[msbc-to-cvsd]
--------------------------

:Setup: As test_hfp_sco[msbc], except the AG only supports CVSD while
	supporting codec negotiation.

:Steps:
	1. Connect the SLC as in test_hfp_connect.
	2. host1: send ``+BCS: 1``.
	3. host1: connect SCO to host0 with the CVSD voice setting.

:Expected:
	1. The HF lists its codecs with ``AT+BAC=1,2``.
	2. The HF confirms the codec with ``AT+BCS=1``.
	3. The HF accepts the audio connection, reported on host0 as a
	   transport with ``Codec: 0x01`` (CVSD).

:Notes: Needs changes: codec negotiation and audio connection in the
	HF, see STATUS. Expected to fail until then.

	This checks that the HF follows the codec selected by the AG
	rather than always using mSBC when both support codec
	negotiation.

.. This file is included by btmon.rst.

CLASSIC AUDIO PROTOCOL FLOW
=============================

Classic Bluetooth audio uses two main profiles: A2DP for high-quality
stereo streaming and HFP for voice calls. Both run over BR/EDR ACL
connections and use different transport mechanisms for audio data --
A2DP uses L2CAP-based AVDTP media channels while HFP uses SCO/eSCO
synchronous connections.

.. include:: btmon-a2dp.rst

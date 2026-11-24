======================
bluetoothctl-telephony
======================

-----------------
Telephony Submenu
-----------------

:Version: BlueZ
:Copyright: Free use of this software is granted under the terms of the GNU
            Lesser General Public Licenses (LGPL).
:Date: May 2025
:Manual section: 1
:Manual group: Linux System Administration

SYNOPSIS
========

**bluetoothctl** [--options] [telephony.commands]

This submenu manages telephony features using the **org.bluez.Telephony(5)**
and **org.bluez.Call(5)** interfaces.

Telephony Commands
==================

list
----

List available audio gateways.

:Usage: **> list**
:Example Display all available HFP audio gateways:
	| **> list**

show
----

Show audio gateway information.

:Usage: **> show [telephony]**
:Uses: **org.bluez.Telephony(5)** properties
:[telephony]: Audio gateway device path (optional, shows current if omitted)
:Example Show information for currently selected audio gateway:
	| **> show**
:Example Show information for specific audio gateway device:
	| **> show /org/bluez/hci0/dev_00_11_22_33_44_55**
:Example Show information for another audio gateway:
	| **> show /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF**

select
------

Select default audio gateway.

:Usage: **> select <telephony>**
:<telephony>: Audio gateway device path to set as default
:Example Select specific audio gateway as default:
	| **> select /org/bluez/hci0/dev_00_11_22_33_44_55**
:Example Select different audio gateway as default:
	| **> select /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF**

dial
----

Dial number.

:Usage: **> dial <number> [telephony]**
:Uses: **org.bluez.Telephony(5)** method **Dial**
:<number>: Phone number to dial
:[telephony]: Audio gateway device path (optional, uses current if omitted)
:Example Dial number using currently selected audio gateway:
	| **> dial 555-1234**
:Example Dial international number using current audio gateway:
	| **> dial +1-555-123-4567**
:Example Dial emergency number using current audio gateway:
	| **> dial 911**
:Example Dial number using specific audio gateway:
	| **> dial 555-1234 /org/bluez/hci0/dev_00_11_22_33_44_55**
:Example Dial UK number using specific audio gateway:
	| **> dial +44-20-7946-0958 /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF**
:Example Dial with caller ID blocking:
	| **> dial *67-555-1234**
:Example Dial with caller ID hiding (GSM format):
	| **> dial #31#555-1234**

hangup-all
----------

Hangup all calls.

:Usage: **> hangup-all [telephony]**
:Uses: **org.bluez.Telephony(5)** method **HangupAll**
:[telephony]: Audio gateway device path (optional, uses current if omitted)
:Example Terminate all active and waiting calls on current gateway:
	| **> hangup-all**
:Example Terminate all calls on specific audio gateway:
	| **> hangup-all /org/bluez/hci0/dev_00_11_22_33_44_55**

list-calls
----------

List available calls.

:Usage: **> list-calls**
:Example Display all active, waiting, and held calls:
	| **> list-calls**

show-call
---------

Show call information.

:Usage: **> show-call <call>**
:Uses: **org.bluez.Call(5)** properties
:<call>: Call object path to display information for
:Example Show information for specific call:
	| **> show-call /org/bluez/hci0/dev_00_11_22_33_44_55/call1**
:Example Show information for another call:
	| **> show-call /org/bluez/hci0/dev_00_11_22_33_44_55/call2**
:Example Show call information from different device:
	| **> show-call /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/call1**

answer
------

Answer call.

:Usage: **> answer <call>**
:Uses: **org.bluez.Call(5)** method **Answer**
:<call>: Call object path to answer
:Example Answer incoming call:
	| **> answer /org/bluez/hci0/dev_00_11_22_33_44_55/call1**
:Example Answer waiting call:
	| **> answer /org/bluez/hci0/dev_00_11_22_33_44_55/call2**
:Example Answer call from different device:
	| **> answer /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/call1**

hangup
------

Hangup call.

:Usage: **> hangup <call>**
:Uses: **org.bluez.Call(5)** method **Hangup**
:<call>: Call object path to terminate
:Example Terminate specific active call:
	| **> hangup /org/bluez/hci0/dev_00_11_22_33_44_55/call1**
:Example Terminate waiting or held call:
	| **> hangup /org/bluez/hci0/dev_00_11_22_33_44_55/call2**
:Example Terminate call from different device:
	| **> hangup /org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/call1**

RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

linux-bluetooth@vger.kernel.org

.. This file is included by btmon.rst.

HCI INITIALIZATION SEQUENCE
============================

Every btsnoop trace that captures controller startup begins with a
dense block of HCI commands and events. This is the kernel's
Bluetooth subsystem initializing the controller through a multi-stage
sequence defined in ``net/bluetooth/hci_sync.c``. Understanding this
sequence helps distinguish normal initialization traffic from
application-level issues.

Overview
--------

The kernel initializes a Bluetooth controller in four stages after
opening the HCI device. Each stage sends a batch of HCI commands and
waits for their completion before proceeding to the next. The full
call chain is::

    hci_power_on_sync
      └─ hci_dev_open_sync
           └─ hci_dev_init_sync
                ├─ hci_dev_setup_sync     (driver setup + quirks)
                └─ hci_init_sync
                     ├─ Stage 1: Reset + identity
                     ├─ Stage 2: Capabilities + buffer sizes
                     ├─ Stage 3: Event masks + policy
                     └─ Stage 4: Final configuration

After all four stages complete, a post-init phase
(``hci_powered_update_sync``) configures runtime parameters like
SSP, advertising, and scan settings.

For unconfigured devices (e.g. controllers that need firmware or a
BD address programmed), only a minimal **Stage 0** runs to identify
the hardware.

Stage 0: Reset and Basic Identity (Unconfigured Only)
-----------------------------------------------------

This stage runs only for unconfigured controllers that need setup
before full initialization.

**Commands sent:**

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``HCI_Reset``
     - Reset the controller (skipped if ``RESET_ON_CLOSE`` quirk)
   * - ``HCI_Read_Local_Version_Information``
     - Read hardware/firmware version
   * - ``HCI_Read_BD_ADDR``
     - Read the controller's Bluetooth address

Stage 1: Reset and Read Local Features
---------------------------------------

Resets the controller and reads core identity and capability
information.

**Commands sent:**

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``HCI_Reset``
     - Reset the controller
   * - ``HCI_Read_Local_Supported_Features``
     - Read LMP feature bitmask (BR/EDR, LE, SSP, etc.)
   * - ``HCI_Read_Local_Version_Information``
     - Read HCI version, LMP version, manufacturer
   * - ``HCI_Read_BD_ADDR``
     - Read the public Bluetooth address

Stage 2: Read Capabilities and Setup
-------------------------------------

Reads detailed capabilities, enables core features, and reads buffer
sizes. This stage has three phases: common commands, BR/EDR-specific
commands, and LE-specific commands.

Common Commands
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``HCI_Read_Local_Supported_Commands``
     - Read the supported command bitmask (HCI 1.2+)
   * - ``HCI_Write_Simple_Pairing_Mode`` (enable)
     - Enable SSP if supported and configured
   * - ``HCI_Write_Extended_Inquiry_Response`` (clear)
     - Clear EIR data when SSP is disabled
   * - ``HCI_Write_Inquiry_Mode``
     - Set inquiry mode (RSSI or Extended, based on features)
   * - ``HCI_Read_Inquiry_Response_Transmit_Power_Level``
     - Read inquiry TX power if supported
   * - ``HCI_Read_Local_Extended_Features`` (page 1)
     - Read extended feature page 1 (SSP host, LE host, etc.)
   * - ``HCI_Write_Authentication_Enable``
     - Sync authentication state with ``LINK_SECURITY`` flag

BR/EDR Commands (if BR/EDR capable)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``HCI_Read_Buffer_Size``
     - Read ACL/SCO buffer sizes and count
   * - ``HCI_Read_Class_of_Device``
     - Read current device class
   * - ``HCI_Read_Local_Name``
     - Read the stored local name
   * - ``HCI_Read_Voice_Setting``
     - Read SCO voice setting (if supported)
   * - ``HCI_Read_Number_of_Supported_IAC``
     - Read number of supported inquiry access codes
   * - ``HCI_Read_Current_IAC_LAP``
     - Read current IAC LAP values
   * - ``HCI_Set_Event_Filter`` (clear all)
     - Clear any stored event filters
   * - ``HCI_Write_Connection_Accept_Timeout``
     - Set connection accept timeout (~20 seconds)
   * - ``HCI_Write_Synchronous_Flow_Control_Enable``
     - Enable SCO flow control if supported

LE Commands (if LE capable)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``LE_Read_Local_Supported_Features``
     - Read LE feature bitmask
   * - ``LE_Read_All_Local_Supported_Features``
     - Read extended LE features (if supported)
   * - ``LE_Read_Buffer_Size`` [v2] or [v1]
     - Read LE ACL (and ISO) buffer sizes; v2 used when ISO capable
   * - ``LE_Read_Supported_States``
     - Read the LE state combination table

Stage 3: Event Masks, Link Policy, and Features
------------------------------------------------

Configures which events the controller should report, sets link
policy, and reads extended feature pages. This is the longest stage.

Event Masks and Link Policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``HCI_Set_Event_Mask``
     - Configure the main event mask based on controller capabilities
   * - ``HCI_Read_Stored_Link_Key``
     - Read all stored link keys
   * - ``HCI_Write_Default_Link_Policy_Settings``
     - Enable role switch, hold, sniff, park based on LMP features
   * - ``HCI_Read_Page_Scan_Activity``
     - Read page scan interval and window
   * - ``HCI_Read_Default_Erroneous_Data_Reporting``
     - Read error data reporting state (for wideband speech)
   * - ``HCI_Read_Page_Scan_Type``
     - Read page scan type (standard or interlaced)
   * - ``HCI_Read_Local_Extended_Features`` (pages 2..N)
     - Read all remaining extended feature pages

**Event mask details:** For dual-mode controllers the kernel enables
events for inquiry results (RSSI and extended), SSP (IO capability,
user confirmation, passkey), synchronous connections, sniff
subrating, encryption refresh, link supervision, and LE meta-events.
For LE-only controllers a minimal mask covers only command
completion, hardware errors, disconnection, and encryption changes.

LE Event Mask and Capabilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``LE_Set_Event_Mask``
     - Configure which LE sub-events are reported
   * - ``LE_Read_Advertising_Channel_Tx_Power``
     - Read advertising TX power (legacy advertising only)
   * - ``LE_Read_Transmit_Power``
     - Read min/max transmit power range
   * - ``LE_Read_Accept_List_Size``
     - Read filter accept list capacity
   * - ``LE_Clear_Accept_List``
     - Clear the filter accept list
   * - ``LE_Read_Resolving_List_Size``
     - Read resolving list capacity (LL Privacy)
   * - ``LE_Clear_Resolving_List``
     - Clear the resolving list
   * - ``LE_Set_Resolvable_Private_Address_Timeout``
     - Set RPA rotation timeout
   * - ``LE_Read_Maximum_Data_Length``
     - Read max TX/RX octets and time (Data Length Extension)
   * - ``LE_Read_Suggested_Default_Data_Length``
     - Read current default data length
   * - ``LE_Read_Number_of_Supported_Advertising_Sets``
     - Read extended advertising set capacity
   * - ``HCI_Write_LE_Host_Supported``
     - Notify controller of host LE support (dual-mode only)
   * - ``LE_Set_Host_Feature``
     - Enable CIS Central (bit 32) and/or Channel Sounding (bit 47)

**LE event mask details:** The kernel enables LE sub-events based on
features: connection complete (enhanced if available), advertising
reports (extended if available), long term key request, connection
parameter request, data length change, PHY update, channel selection
algorithm, periodic advertising events, CIS established/request (if
CIS capable), BIG create/sync/info (if BIS capable), and channel
sounding events (if CS capable).

Stage 4: Final Configuration
-----------------------------

Performs final setup: deletes stale keys, sets event mask page 2,
reads codec information, enables Secure Connections, and configures
LE data length and PHY defaults.

Keys, Codecs, and Secure Connections
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``HCI_Delete_Stored_Link_Key`` (all)
     - Delete all stored link keys from controller
   * - ``HCI_Set_Event_Mask_Page_2``
     - Enable page 2 events (authenticated payload timeout, etc.)
   * - ``HCI_Read_Local_Supported_Codecs`` [v2] or [v1]
     - Read supported codec IDs; v2 includes transport type info
   * - ``HCI_Read_Local_Pairing_Options``
     - Read default pairing options (max encryption key size)
   * - ``HCI_Get_MWS_Transport_Layer_Configuration``
     - Read MWS coexistence config if supported
   * - ``HCI_Read_Synchronization_Train_Parameters``
     - Read sync train params (Connectionless Peripheral Broadcast)
   * - ``HCI_Write_Secure_Connections_Support`` (enable)
     - Enable Secure Connections if SSP active
   * - ``HCI_Write_Default_Erroneous_Data_Reporting``
     - Enable/disable based on wideband speech setting

LE Data Length and PHY Defaults
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - HCI Command
     - Purpose
   * - ``LE_Write_Suggested_Default_Data_Length``
     - Set default TX octets/time for new connections
   * - ``LE_Set_Default_PHY``
     - Set preferred PHY (1M always; 2M and Coded if supported)

Post-Initialization
-------------------

After the four stages complete, ``hci_powered_update_sync`` runs to
apply runtime configuration:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Action
     - Purpose
   * - ``HCI_Write_Simple_Pairing_Mode``
     - Re-enable SSP + Secure Connections if configured
   * - ``HCI_Write_LE_Host_Supported``
     - Sync LE host support state
   * - LE advertising setup
     - Configure advertising parameters and data
   * - ``HCI_Write_Authentication_Enable``
     - Sync authentication enable state
   * - Scan/class/name/EIR updates
     - Configure page scan, device class, local name, EIR data
   * - ``LE_Set_Random_Address``
     - Set static random address if no public address

Reading the Init Sequence in a Trace
-------------------------------------

When examining a btsnoop trace, the initialization block is the
first thing after the controller is opened. A typical dual-mode
controller trace starts with::

    < HCI Command: Reset
    > HCI Event: Command Complete (Reset)
    < HCI Command: Read Local Supported Features
    > HCI Event: Command Complete (Read Local Supported Features)
    < HCI Command: Read Local Version Information
    > HCI Event: Command Complete (Read Local Version Information)
    < HCI Command: Read BD ADDR
    > HCI Event: Command Complete (Read BD ADDR)
    ... [Stage 2-4 commands follow]

**Key things to look for:**

- **Missing commands**: If expected commands are absent, the
  controller may not support the corresponding feature. For example,
  no ``LE_Read_Buffer_Size`` means the controller is BR/EDR only.

- **Command failures**: A ``Status`` other than ``0x00`` in a Command
  Complete event during init usually indicates a broken controller or
  unsupported feature. The kernel handles most gracefully, but
  persistent errors may prevent the adapter from functioning.

- **Buffer sizes**: The values returned by ``Read_Buffer_Size`` and
  ``LE_Read_Buffer_Size`` determine how many in-flight packets the
  controller can hold. Small buffer counts can cause throughput
  issues.

- **Feature bits**: The ``Read_Local_Supported_Features`` response
  reveals what the controller supports (LE, SSP, eSCO, etc.). Cross
  reference with the commands that follow — the kernel only sends
  commands for features the controller reports supporting.

- **Event mask**: The ``Set_Event_Mask`` command shows exactly which
  events the host wants to receive. If an expected event never
  appears in the trace, check whether it was enabled in the mask.

- **LE-only controllers**: These skip all BR/EDR commands
  (``Read_Buffer_Size``, ``Read_Local_Name``, link policy, etc.) and
  use a minimal event mask. The trace will be noticeably shorter.

- **Vendor commands**: Some controllers (Intel, Broadcom, Qualcomm,
  Realtek, MediaTek) insert vendor-specific HCI commands between
  stages for firmware download, configuration, or patch application.
  These appear as opcode groups ``0x3F`` (vendor) and are
  driver-specific.

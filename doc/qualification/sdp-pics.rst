==========================
Service Discovery Protocol
==========================
(TCRL 2023-1, SDP.ICS.p23)


Roles
=====
**Table 1b: Role Requirements**

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_1b_1    | x        | Server (C.1)                                 |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_1b_2    | x        | Client (C.1)                                 |
+------------------+----------+----------------------------------------------+

- C.1: Mandatory to support at least one of SDP 1b/1 "Server" OR SDP 1b/2
  "Client".

UUID capabilities
=================
**Table 1: Support Different Size Capabilities on UUID**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_1_1     | x        | 128 bit UUID (M)                             |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_1_2     | x        | 32 bit UUID (M)                              |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_1_3     | x        | 16 bit UUID (M)                              |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Service Search Request PDU
==========================
**Table 2: Service Search Request**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_2_1     | x        | Service Search Response (M)                  |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_2_2     |          | Generates continuation state in Service      |
|                  |          | Search Response (O)                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

Service Search Request PDU
==========================
**Table 3: Error Response to Invalid Service Search Request**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_3_1     | x        | Error response to Service Search Request (M) |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Service Attribute Request PDU
=============================
**Table 4: Service Attribute Request**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_4_1     | x        | Service Attribute Response (M)               |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_4_2     |          | Generates continuation state in Service      |
|                  |          | Attribute Response (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_4_3     | x        | Service Attribute Response with              |
|                  |          | AdditionalProtocolDescriptorList attribute   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

Service Attribute Request PDU
=============================
**Table 5: Error Response to Invalid Service Attribute Request**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_5_1     | x        | Error response to Service Attribute Request  |
|                  |          | (M)                                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Service Search Attribute Request PDU
====================================
**Table 6: Service Search Attribute Request**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_6_1     | x        | Service Search Attribute Response (M)        |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_6_2     |          | Generates continuation state in Service      |
|                  |          | Search Attribute Response (O)                |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_6_3     | x        | Service Search Attribute Response with       |
|                  |          | AdditionalProtocolDescriptorList attribute   |
|                  |          | (O)                                          |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional

Service Search Attribute Request PDU
====================================
**Table 7: Invalid Service Search Attribute Request**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_7_1     | x        | Error response to Service Search Attribute   |
|                  |          | Request (M)                                  |
+------------------+----------+----------------------------------------------+

- M: Mandatory

Service Browsing
================
**Table 8: Service Browsing**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_8_1     |          | Browsing, using SDP_ServiceSearchRequest and |
|                  |          | SDP_ServiceAttributeRequest (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_8_2     |          | Browsing, using                              |
|                  |          | SDP_ServiceSearchAttributeRequest (O)        |
+------------------+----------+----------------------------------------------+

- O: Optional

Attributes
==========
**Table 9: Attributes Present in IUT**
Prerequisite: SDP 1b/1 "Server"

+------------------+----------+----------------------------------------------+
| Parameter Name   | Selected | Description                                  |
+==================+==========+==============================================+
| TSPC_SDP_9_1     |          | ServiceID (O)                                |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_2     | x        | ProtocolDescriptorList (O)                   |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_3     |          | ServiceRecordState (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_4     |          | ServiceInfoTimeToLive (O)                    |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_5     |          | BrowseGroupList (O)                          |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_6     |          | LanguageBaseAttributeIdList (O)              |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_7     |          | ServiceAvailability (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_8     |          | IconURL (O)                                  |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_9     | x        | ServiceName (O)                              |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_10    | x        | ServiceDescription (O)                       |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_11    |          | ProviderName (O)                             |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_12    |          | VersionNumberList (O)                        |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_13    |          | ServiceDataBaseState (O)                     |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_14    | x        | BluetoothProfileDescriptorList (O)           |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_15    |          | DocumentationURL (O)                         |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_16    |          | ClientExecutableURL (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_17    |          | AdditionalProtocolDescriptorList (C.1)       |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_18    | x        | ServiceRecordHandle (O)                      |
+------------------+----------+----------------------------------------------+
| TSPC_SDP_9_19    | x        | ServiceClassIDList (O)                       |
+------------------+----------+----------------------------------------------+

- M: Mandatory
- O: Optional
- C.1: Optional IF SDP 9/2 "ProtocolDescriptorList", otherwise Excluded.

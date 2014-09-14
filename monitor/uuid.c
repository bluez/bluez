/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "uuid.h"

static struct {
	uint16_t uuid;
	const char *str;
} uuid16_table[] = {
	{ 0x0001, "SDP"						},
	{ 0x0003, "RFCOMM"					},
	{ 0x0005, "TCS-BIN"					},
	{ 0x0007, "ATT"						},
	{ 0x0008, "OBEX"					},
	{ 0x000f, "BNEP"					},
	{ 0x0010, "UPNP"					},
	{ 0x0011, "HIDP"					},
	{ 0x0012, "Hardcopy Control Channel"			},
	{ 0x0014, "Hardcopy Data Channel"			},
	{ 0x0016, "Hardcopy Notification"			},
	{ 0x0017, "AVCTP"					},
	{ 0x0019, "AVDTP"					},
	{ 0x001b, "CMTP"					},
	{ 0x001e, "MCAP Control Channel"			},
	{ 0x001f, "MCAP Data Channel"				},
	{ 0x0100, "L2CAP"					},
	/* 0x0101 to 0x0fff undefined */
	{ 0x1000, "Service Discovery Server Service Class"	},
	{ 0x1001, "Browse Group Descriptor Service Class"	},
	{ 0x1002, "Public Browse Root"				},
	/* 0x1003 to 0x1100 undefined */
	{ 0x1101, "Serial Port"					},
	{ 0x1102, "LAN Access Using PPP"			},
	{ 0x1103, "Dialup Networking"				},
	{ 0x1104, "IrMC Sync"					},
	{ 0x1105, "OBEX Object Push"				},
	{ 0x1106, "OBEX File Transfer"				},
	{ 0x1107, "IrMC Sync Command"				},
	{ 0x1108, "Headset"					},
	{ 0x1109, "Cordless Telephony"				},
	{ 0x110a, "Audio Source"				},
	{ 0x110b, "Audio Sink"					},
	{ 0x110c, "A/V Remote Control Target"			},
	{ 0x110d, "Advanced Audio Distribution"			},
	{ 0x110e, "A/V Remote Control"				},
	{ 0x110f, "A/V Remote Control Controller"		},
	{ 0x1110, "Intercom"					},
	{ 0x1111, "Fax"						},
	{ 0x1112, "Headset AG"					},
	{ 0x1113, "WAP"						},
	{ 0x1114, "WAP Client"					},
	{ 0x1115, "PANU"					},
	{ 0x1116, "NAP"						},
	{ 0x1117, "GN"						},
	{ 0x1118, "Direct Printing"				},
	{ 0x1119, "Reference Printing"				},
	{ 0x111a, "Basic Imaging Profile"			},
	{ 0x111b, "Imaging Responder"				},
	{ 0x111c, "Imaging Automatic Archive"			},
	{ 0x111d, "Imaging Referenced Objects"			},
	{ 0x111e, "Handsfree"					},
	{ 0x111f, "Handsfree Audio Gateway"			},
	{ 0x1120, "Direct Printing Refrence Objects Service"	},
	{ 0x1121, "Reflected UI"				},
	{ 0x1122, "Basic Printing"				},
	{ 0x1123, "Printing Status"				},
	{ 0x1124, "Human Interface Device Service"		},
	{ 0x1125, "Hardcopy Cable Replacement"			},
	{ 0x1126, "HCR Print"					},
	{ 0x1127, "HCR Scan"					},
	{ 0x1128, "Common ISDN Access"				},
	/* 0x1129 and 0x112a undefined */
	{ 0x112d, "SIM Access"					},
	{ 0x112e, "Phonebook Access Client"			},
	{ 0x112f, "Phonebook Access Server"			},
	{ 0x1130, "Phonebook Access"				},
	{ 0x1131, "Headset HS"					},
	{ 0x1132, "Message Access Server"			},
	{ 0x1133, "Message Notification Server"			},
	{ 0x1134, "Message Access Profile"			},
	{ 0x1135, "GNSS"					},
	{ 0x1136, "GNSS Server"					},
	{ 0x1137, "3D Display"					},
	{ 0x1138, "3D Glasses"					},
	{ 0x1139, "3D Synchronization"				},
	{ 0x113a, "MPS Profile"					},
	{ 0x113b, "MPS Service"					},
	/* 0x113c to 0x11ff undefined */
	{ 0x1200, "PnP Information"				},
	{ 0x1201, "Generic Networking"				},
	{ 0x1202, "Generic File Transfer"			},
	{ 0x1203, "Generic Audio"				},
	{ 0x1204, "Generic Telephony"				},
	{ 0x1205, "UPNP Service"				},
	{ 0x1206, "UPNP IP Service"				},
	{ 0x1300, "UPNP IP PAN"					},
	{ 0x1301, "UPNP IP LAP"					},
	{ 0x1302, "UPNP IP L2CAP"				},
	{ 0x1303, "Video Source"				},
	{ 0x1304, "Video Sink"					},
	{ 0x1305, "Video Distribution"				},
	/* 0x1306 to 0x13ff undefined */
	{ 0x1400, "HDP"						},
	{ 0x1401, "HDP Source"					},
	{ 0x1402, "HDP Sink"					},
	/* 0x1403 to 0x17ff undefined */
	{ 0x1800, "Generic Access Profile"			},
	{ 0x1801, "Generic Attribute Profile"			},
	{ 0x1802, "Immediate Alert"				},
	{ 0x1803, "Link Loss"					},
	{ 0x1804, "Tx Power"					},
	{ 0x1805, "Current Time Service"			},
	{ 0x1806, "Reference Time Update Service"		},
	{ 0x1807, "Next DST Change Service"			},
	{ 0x1808, "Glucose"					},
	{ 0x1809, "Health Thermometer"				},
	{ 0x180a, "Device Information"				},
	/* 0x180b and 0x180c undefined */
	{ 0x180d, "Heart Rate"					},
	{ 0x180e, "Phone Alert Status Service"			},
	{ 0x180f, "Battery Service"				},
	{ 0x1810, "Blood Pressure"				},
	{ 0x1811, "Alert Notification Service"			},
	{ 0x1812, "Human Interface Device"			},
	{ 0x1813, "Scan Parameters"				},
	{ 0x1814, "Running Speed and Cadence"			},
	{ 0x1815, "Automation IO"				},
	{ 0x1816, "Cycling Speed and Cadence"			},
	/* 0x1817 undefined */
	{ 0x1818, "Cycling Power"				},
	{ 0x1819, "Location and Navigation"			},
	{ 0x181a, "Environmental Sensing"			},
	{ 0x181b, "Body Composition"				},
	{ 0x181c, "User Data"					},
	{ 0x181d, "Weight Scale"				},
	/* 0x181e to 0x27ff undefined */
	{ 0x2800, "Primary Service"				},
	{ 0x2801, "Secondary Service"				},
	{ 0x2802, "Include"					},
	{ 0x2803, "Characteristic"				},
	/* 0x2804 to 0x28ff undefined */
	{ 0x2900, "Characteristic Extended Properties"		},
	{ 0x2901, "Characteristic User Description"		},
	{ 0x2902, "Client Characteristic Configuration"		},
	{ 0x2903, "Server Characteristic Configuration"		},
	{ 0x2904, "Characteristic Format"			},
	{ 0x2905, "Characteristic Aggregate Formate"		},
	{ 0x2906, "Valid Range"					},
	{ 0x2907, "External Report Reference"			},
	{ 0x2908, "Report Reference"				},
	{ 0x2909, "Number of Digitals"				},
	{ 0x290a, "Value Trigger Setting"			},
	{ 0x290b, "Environmental Sensing Configuration"		},
	{ 0x290c, "Environmental Sensing Measurement"		},
	{ 0x290d, "Environmental Sensing Trigger Setting"	},
	{ 0x290e, "Time Trigger Setting"			},
	/* 0x290f to 0x29ff undefined */
	{ 0x2a00, "Device Name"					},
	{ 0x2a01, "Appearance"					},
	{ 0x2a02, "Peripheral Privacy Flag"			},
	{ 0x2a03, "Reconnection Address"			},
	{ 0x2a04, "Peripheral Preferred Connection Parameters"	},
	{ 0x2a05, "Service Changed"				},
	{ 0x2a06, "Alert Level"					},
	{ 0x2a07, "Tx Power Level"				},
	{ 0x2a08, "Date Time"					},
	{ 0x2a09, "Day of Week"					},
	{ 0x2a0a, "Day Date Time"				},
	/* 0x2a0b undefined */
	{ 0x2a0c, "Exact Time 256"				},
	{ 0x2a0d, "DST Offset"					},
	{ 0x2a0e, "Time Zone"					},
	{ 0x2a0f, "Local Time Information"			},
	/* 0x2a10 undefined */
	{ 0x2a11, "Time with DST"				},
	{ 0x2a12, "Time Accuracy"				},
	{ 0x2a13, "Time Source"					},
	{ 0x2a14, "Reference Time Information"			},
	/* 0x2a15 undefined */
	{ 0x2a16, "Time Update Control Point"			},
	{ 0x2a17, "Time Update State"				},
	{ 0x2a18, "Glucose Measurement"				},
	{ 0x2a19, "Battery Level"				},
	/* 0x2a1a and 0x2a1b undefined */
	{ 0x2a1c, "Temperature Measurement"			},
	{ 0x2a1d, "Temperature Type"				},
	{ 0x2a1e, "Intermediate Temperature"			},
	/* 0x2a1f and 0x2a20 undefined */
	{ 0x2a21, "Measurement Interval"			},
	{ 0x2a22, "Boot Keyboard Input Report"			},
	{ 0x2a23, "System ID"					},
	{ 0x2a24, "Model Number String"				},
	{ 0x2a25, "Serial Number String"			},
	{ 0x2a26, "Firmware Revision String"			},
	{ 0x2a27, "Hardware Revision String"			},
	{ 0x2a28, "Software Revision String"			},
	{ 0x2a29, "Manufacturer Name String"			},
	{ 0x2a2a, "IEEE 11073-20601 Regulatory Cert. Data List"	},
	{ 0x2a2b, "Current Time"				},
	{ 0x2a2c, "Magnetic Declination"			},
	/* 0x2a2d to 0x2a30 undefined */
	{ 0x2a31, "Scan Refresh"				},
	{ 0x2a32, "Boot Keyboard Output Report"			},
	{ 0x2a33, "Boot Mouse Input Report"			},
	{ 0x2a34, "Glucose Measurement Context"			},
	{ 0x2a35, "Blood Pressure Measurement"			},
	{ 0x2a36, "Intermediate Cuff Pressure"			},
	{ 0x2a37, "Heart Rate Measurement"			},
	{ 0x2a38, "Body Sensor Location"			},
	{ 0x2a39, "Heart Rate Control Point"			},
	/* 0x2a3a to 0x2a3e undefined */
	{ 0x2a3f, "Alert Status"				},
	{ 0x2a40, "Ringer Control Point"			},
	{ 0x2a41, "Ringer Setting"				},
	{ 0x2a42, "Alert Category ID Bit Mask"			},
	{ 0x2a43, "Alert Category ID"				},
	{ 0x2a44, "Alert Notification Control Point"		},
	{ 0x2a45, "Unread Alert Status"				},
	{ 0x2a46, "New Alert"					},
	{ 0x2a47, "Supported New Alert Category"		},
	{ 0x2a48, "Supported Unread Alert Category"		},
	{ 0x2a49, "Blood Pressure Feature"			},
	{ 0x2a4a, "HID Information"				},
	{ 0x2a4b, "Report Map"					},
	{ 0x2a4c, "HID Control Point"				},
	{ 0x2a4d, "Report"					},
	{ 0x2a4e, "Protocol Mode"				},
	{ 0x2a4f, "Scan Interval Window"			},
	{ 0x2a50, "PnP ID"					},
	{ 0x2a51, "Glucose Feature"				},
	{ 0x2a52, "Record Access Control Point"			},
	{ 0x2a53, "RSC Measurement"				},
	{ 0x2a54, "RSC Feature"					},
	{ 0x2a55, "SC Control Point"				},
	{ 0x2a56, "Digital"					},
	/* 0x2a57 undefined */
	{ 0x2a58, "Analog"					},
	/* 0x2a59 undefined */
	{ 0x2a5a, "Aggregate"					},
	{ 0x2a5b, "CSC Measurement"				},
	{ 0x2a5c, "CSC Feature"					},
	{ 0x2a5d, "Sensor Location"				},
	/* 0x2a5e to 0x2a62 undefined */
	{ 0x2a63, "Cycling Power Measurement"			},
	{ 0x2a64, "Cycling Power Vector"			},
	{ 0x2a65, "Cycling Power Feature"			},
	{ 0x2a66, "Cycling Power Control Point"			},
	{ 0x2a67, "Location and Speed"				},
	{ 0x2a68, "Navigation"					},
	{ 0x2a69, "Position Quality"				},
	{ 0x2a6a, "LN Feature"					},
	{ 0x2a6b, "LN Control Point"				},
	{ 0x2a6c, "Elevation"					},
	{ 0x2a6d, "Pressure"					},
	{ 0x2a6e, "Temperature"					},
	{ 0x2a6f, "Humidity"					},
	{ 0x2a70, "True Wind Speed"				},
	{ 0x2a71, "True Wind Direction"				},
	{ 0x2a72, "Apparent Wind Speed"				},
	{ 0x2a73, "Apparent Wind Direction"			},
	{ 0x2a74, "Gust Factor"					},
	{ 0x2a75, "Pollen Concentration"			},
	{ 0x2a76, "UV Index"					},
	{ 0x2a77, "Irradiance"					},
	{ 0x2a78, "Rainfall"					},
	{ 0x2a79, "Wind Chill"					},
	{ 0x2a7a, "Heat Index"					},
	{ 0x2a7b, "Dew Point"					},
	{ 0x2a7c, "Trend"					},
	{ 0x2a7d, "Descriptor Value Changed"			},
	{ 0x2a7e, "Aerobic Heart Rate Lower Limit"		},
	{ 0x2a7f, "Aerobic Threshold"				},
	{ 0x2a80, "Age"						},
	{ 0x2a81, "Anaerobic Heart Rate Lower Limit"		},
	{ 0x2a82, "Anaerobic Heart Rate Upper Limit"		},
	{ 0x2a83, "Anaerobic Threshold"				},
	{ 0x2a84, "Aerobic Heart Rate Upper Limit"		},
	{ 0x2a85, "Date of Birth"				},
	{ 0x2a86, "Date of Threshold Assessment"		},
	{ 0x2a87, "Email Address"				},
	{ 0x2a88, "Fat Burn Heart Rate Lower Limit"		},
	{ 0x2a89, "Fat Burn Heart Rate Upper Limit"		},
	{ 0x2a8a, "First Name"					},
	{ 0x2a8b, "Five Zone Heart Rate Limits"			},
	{ 0x2a8c, "Gender"					},
	{ 0x2a8d, "Heart Rate Max"				},
	{ 0x2a8e, "Height"					},
	{ 0x2a8f, "Hip Circumference"				},
	{ 0x2a90, "Last Name"					},
	{ 0x2a91, "Maximum Recommended Heart Rate"		},
	{ 0x2a92, "Resting Heart Rate"				},
	{ 0x2a93, "Sport Type for Aerobic/Anaerobic Thresholds"	},
	{ 0x2a94, "Three Zone Heart Rate Limits"		},
	{ 0x2a95, "Two Zone Heart Rate Limit"			},
	{ 0x2a96, "VO2 Max"					},
	{ 0x2a97, "Waist Circumference"				},
	{ 0x2a98, "Weight"					},
	{ 0x2a99, "Database Change Increment"			},
	{ 0x2a9a, "User Index"					},
	{ 0x2a9b, "Body Composition Feature"			},
	{ 0x2a9c, "Body Composition Measurement"		},
	{ 0x2a9d, "Weight Measurement"				},
	{ 0x2a9e, "Weight Scale Feature"			},
	{ 0x2a9f, "User Control Point"				},
	{ 0x2aa0, "Magnetic Flux Density - 2D"			},
	{ 0x2aa1, "Magnetic Flux Density - 3D"			},
	{ 0x2aa2, "Language"					},
	{ 0x2aa3, "Barometric Pressure Trend"			},
	{ }
};

const char *uuid16_to_str(uint16_t uuid)
{
	int i;

	for (i = 0; uuid16_table[i].str; i++) {
		if (uuid16_table[i].uuid == uuid)
			return uuid16_table[i].str;
	}

	return "Unknown";
}

const char *uuid32_to_str(uint32_t uuid)
{
	if ((uuid & 0xffff0000) == 0x0000)
		return uuid16_to_str(uuid & 0x0000ffff);

	return "Unknown";
}

const char *uuid128_to_str(const unsigned char *uuid)
{
	return "Unknown";
}

const char *uuidstr_to_str(const char *uuid)
{
	uint32_t val;

	if (!uuid)
		return NULL;

	if (strlen(uuid) != 36)
		return NULL;

	if (strncasecmp(uuid + 8, "-0000-1000-8000-00805f9b34fb", 28))
		return "Vendor specific";

	if (sscanf(uuid, "%08x-0000-1000-8000-00805f9b34fb", &val) != 1)
		return NULL;

	return uuid32_to_str(val);
}

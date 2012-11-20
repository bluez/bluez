/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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
	{ 0x1000, "Service Discovery Server Service Class"	},
	{ 0x1001, "Browse Group Descriptor Service Class"	},
	{ 0x1002, "Public Browse Root"				},
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
	{ 0x1400, "HDP"						},
	{ 0x1401, "HDP Source"					},
	{ 0x1402, "HDP Sink"					},
	{ 0x1800, "Generic Access Profile"			},
	{ 0x1801, "Generic Attribute Profile"			},
	{ 0x180a, "Device Information"				},
	{ 0x2800, "Primary Service"				},
	{ 0x2801, "Secondary Service"				},
	{ 0x2802, "Include"					},
	{ 0x2803, "Characteristic"				},
	{ 0x2900, "Characteristic Extended Properties"		},
	{ 0x2901, "Characteristic User Description"		},
	{ 0x2902, "Client Characteristic Configuration"		},
	{ 0x2903, "Server Characteristic Configuration"		},
	{ 0x2904, "Characteristic Format"			},
	{ 0x2905, "Characteristic Aggregate Formate"		},
	{ 0x2a00, "Device Name"					},
	{ 0x2a01, "Appearance"					},
	{ 0x2a02, "Peripheral Privacy Flag"			},
	{ 0x2a03, "Reconnection Address"			},
	{ 0x2a04, "Peripheral Preferred Connection Parameters"	},
	{ 0x2a05, "Service Changed"				},
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

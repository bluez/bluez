/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2001-2002  Nokia Corporation
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2002-2003  Stephen Crane <steve.crane@rococosoft.com>
 *  Copyright (C) 2002-2003  Jean Tourrilhes <jt@hpl.hp.com>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/in.h>

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#define for_each_opt(opt, long, short) while ((opt=getopt_long(argc, argv, short ? short:"+", long, 0)) != -1)

/*
 * Convert a string to a BDADDR, with a few "enhancements" - Jean II
 */
int estr2ba(char *str, bdaddr_t *ba)
{
	/* Only trap "local", "any" is already dealt with */
	if(!strcmp(str, "local")) {
		bacpy(ba, BDADDR_LOCAL);
		return 0;
	}
	return str2ba(str, ba);
}

/* Pass args to the inquiry/search handler */
struct search_context {
	char 		*svc;		/* Service */
	uuid_t		group;		/* Browse group */
	int		tree;		/* Display full attribute tree */
	uint32_t	handle;		/* Service record handle */
};

typedef int (*handler_t)(bdaddr_t *bdaddr, struct search_context *arg);

static char UUID_str[MAX_LEN_UUID_STR];
static bdaddr_t interface;

/* Definition of attribute members */
struct member_def {
  char *name;
};

/* Definition of an attribute */
struct attrib_def {
  int			num;		/* Numeric ID - 16 bits */
  char *		name;		/* User readable name */
  struct member_def *	members;	/* Definition of attribute args */
  int			member_max;	/* Max of attribute arg definitions */
};

/* Definition of a service or protocol */
struct uuid_def {
  int			num;		/* Numeric ID - 16 bits */
  char *		name;		/* User readable name */
  struct attrib_def *	attribs;	/* Specific attribute definitions */
  int			attrib_max;	/* Max of attribute definitions */
};

/* Context information about current attribute */
struct attrib_context {
  struct uuid_def *	service;	/* Service UUID, if known */
  struct attrib_def *	attrib;		/* Description of the attribute */
  int			member_index;	/* Index of current attribute member */
};

/* Context information about the whole service */
struct service_context {
  struct uuid_def *	service;	/* Service UUID, if known */
};

/* Allow us to do nice formatting of the lists */
static char *indent_spaces = "                                         ";

/* ID of the service attribute.
 * Most attributes after 0x200 are defined based on the service, so
 * we need to find what is the service (which is messy) - Jean II */
#define SERVICE_ATTR	0x1

/* Definition of the optional arguments in protocol list */
static struct member_def protocol_members[] = {
  { "Protocol" },
  { "Channel/Port" },
  { "Version" },
};

/* Definition of the optional arguments in profile list */
static struct member_def profile_members[] = {
  { "Profile" },
  { "Version" },
};

/* Definition of the optional arguments in Language list */
static struct member_def language_members[] = {
  { "Code ISO639" },
  { "Encoding" },
  { "Base Offset" },
};

/* Name of the various common attributes. See BT assigned numbers */
static struct attrib_def attrib_names[] = {
  { 0x0, "ServiceRecordHandle", NULL, 0 },
  { 0x1, "ServiceClassIDList", NULL, 0 },
  { 0x2, "ServiceRecordState", NULL, 0 },
  { 0x3, "ServiceID", NULL, 0 },
  { 0x4, "ProtocolDescriptorList",
    protocol_members, sizeof(protocol_members)/sizeof(struct member_def) },
  { 0x5, "BrowseGroupList", NULL, 0 },
  { 0x6, "LanguageBaseAttributeIDList",
    language_members, sizeof(language_members)/sizeof(struct member_def) },
  { 0x7, "ServiceInfoTimeToLive", NULL, 0 },
  { 0x8, "ServiceAvailability", NULL, 0 },
  { 0x9, "BluetoothProfileDescriptorList",
    profile_members, sizeof(profile_members)/sizeof(struct member_def) },
  { 0xA, "DocumentationURL", NULL, 0 },
  { 0xB, "ClientExecutableURL", NULL, 0 },
  { 0xC, "IconURL", NULL, 0 },
  { 0xD, "AdditionalProtocolDescriptorLists", NULL, 0 },
  /* Definitions after that are tricky (per profile or offset) */
};

const int attrib_max = sizeof(attrib_names)/sizeof(struct attrib_def);

/* Name of the various SPD attributes. See BT assigned numbers */
static struct attrib_def sdp_attrib_names[] = {
  { 0x200, "VersionNumberList", NULL, 0 },
  { 0x201, "ServiceDatabaseState", NULL, 0 },
};

/* Name of the various SPD attributes. See BT assigned numbers */
static struct attrib_def browse_attrib_names[] = {
  { 0x200, "GroupID", NULL, 0 },
};

/* Name of the various PAN attributes. See BT assigned numbers */
/* Note : those need to be double checked - Jean II */
static struct attrib_def pan_attrib_names[] = {
  { 0x200, "IpSubnet", NULL, 0 },		/* Obsolete ??? */
  { 0x30A, "SecurityDescription", NULL, 0 },
  { 0x30B, "NetAccessType", NULL, 0 },
  { 0x30C, "MaxNetAccessrate", NULL, 0 },
  { 0x30D, "IPv4Subnet", NULL, 0 },
  { 0x30E, "IPv6Subnet", NULL, 0 },
};

/* Name of the various Generic-Audio attributes. See BT assigned numbers */
/* Note : totally untested - Jean II */
static struct attrib_def audio_attrib_names[] = {
  { 0x302, "Remote audio volume control", NULL, 0 },
};

/* Same for the UUIDs. See BT assigned numbers */
static struct uuid_def uuid16_names[] = {
  /* -- Protocols -- */
  { 0x1, "SDP (Service Discovery Protocol)", NULL, 0 },
  { 0x2, "UDP", NULL, 0 },
  { 0x3, "RFCOMM", NULL, 0 },
  { 0x4, "TCP", NULL, 0 },
  { 0x5, "TCS-BIN", NULL, 0 },
  { 0x6, "TCS-AT", NULL, 0 },
  { 0x8, "OBEX", NULL, 0 },
  { 0x9, "IP", NULL, 0 },
  { 0xA, "FTP", NULL, 0 },
  { 0xC, "HTTP", NULL, 0 },
  { 0xE, "WSP", NULL, 0 },
  { 0xF, "BNEP (PAN/BNEP)", NULL, 0 },
  { 0x10, "UPnP/ESDP", NULL, 0 },
  { 0x11, "HIDP", NULL, 0 },
  { 0x12, "HardcopyControlChannel", NULL, 0 },
  { 0x14, "HardcopyDataChannel", NULL, 0 },
  { 0x16, "HardcopyNotification", NULL, 0 },
  { 0x17, "AVCTP", NULL, 0 },
  { 0x19, "AVDTP", NULL, 0 },
  { 0x1B, "CMTP", NULL, 0 },
  { 0x1D, "UDI_C-Plane", NULL, 0 },
  { 0x100, "L2CAP", NULL, 0 },
  /* -- Services -- */
  { 0x1000, "ServiceDiscoveryServerServiceClassID (SDP)",
    sdp_attrib_names, sizeof(sdp_attrib_names)/sizeof(struct attrib_def) },
  { 0x1001, "BrowseGroupDescriptorServiceClassID (SDP)",
    browse_attrib_names,
    sizeof(browse_attrib_names)/sizeof(struct attrib_def) },
  { 0x1002, "PublicBrowseGroup (SDP)", NULL, 0 },
  { 0x1101, "SerialPort", NULL, 0 },
  { 0x1102, "LANAccessUsingPPP", NULL, 0 },
  { 0x1103, "DialupNetworking (DUN)", NULL, 0 },
  { 0x1104, "IrMCSync", NULL, 0 },
  { 0x1105, "OBEXObjectPush", NULL, 0 },
  { 0x1106, "OBEXFileTransfer", NULL, 0 },
  { 0x1107, "IrMCSyncCommand", NULL, 0 },
  { 0x1108, "Headset",
    audio_attrib_names, sizeof(audio_attrib_names)/sizeof(struct attrib_def) },
  { 0x1109, "CordlessTelephony", NULL, 0 },
  { 0x110a, "AudioSource", NULL, 0 },
  { 0x110b, "AudioSink", NULL, 0 },
  { 0x110c, "RemoteControlTarget", NULL, 0 },
  { 0x110d, "AdvancedAudio", NULL, 0 },
  { 0x110e, "RemoteControl", NULL, 0 },
  { 0x110f, "VideoConferencing", NULL, 0 },
  { 0x1110, "Intercom", NULL, 0 },
  { 0x1111, "Fax", NULL, 0 },
  { 0x1112, "HeadsetAudioGateway", NULL, 0 },
  { 0x1113, "WAP", NULL, 0 },
  { 0x1114, "WAP_CLIENT", NULL, 0 },
  { 0x1115, "PANU (PAN/BNEP)",
    pan_attrib_names, sizeof(pan_attrib_names)/sizeof(struct attrib_def) },
  { 0x1116, "NAP (PAN/BNEP)",
    pan_attrib_names, sizeof(pan_attrib_names)/sizeof(struct attrib_def) },
  { 0x1117, "GN (PAN/BNEP)",
    pan_attrib_names, sizeof(pan_attrib_names)/sizeof(struct attrib_def) },
  { 0x1118, "DirectPrinting (BPP)", NULL, 0 },
  { 0x1119, "ReferencePrinting (BPP)", NULL, 0 },
  /* ... */
  { 0x111e, "Handsfree", NULL, 0 },
  { 0x111f, "HandsfreeAudioGateway", NULL, 0 },
  { 0x1120, "DirectPrintingReferenceObjectsService (BPP)", NULL, 0 },
  { 0x1121, "ReflectedUI (BPP)", NULL, 0 },
  { 0x1122, "BasicPrinting (BPP)", NULL, 0 },
  { 0x1123, "PrintingStatus (BPP)", NULL, 0 },
  { 0x1124, "HumanInterfaceDeviceService (HID)", NULL, 0 },
  { 0x1125, "HardcopyCableReplacement (HCR)", NULL, 0 },
  { 0x1126, "HCR_Print (HCR)", NULL, 0 },
  { 0x1127, "HCR_Scan (HCR)", NULL, 0 },
  { 0x1128, "Common ISDN Access (CIP)", NULL, 0 },
  { 0x1129, "VideoConferencingGW (VCP)", NULL, 0 },
  { 0x112d, "SIM Access (SAP)", NULL, 0 },
  /* ... */
  { 0x1200, "PnPInformation", NULL, 0 },
  { 0x1201, "GenericNetworking", NULL, 0 },
  { 0x1202, "GenericFileTransfer", NULL, 0 },
  { 0x1203, "GenericAudio",
    audio_attrib_names, sizeof(audio_attrib_names)/sizeof(struct attrib_def) },
  { 0x1204, "GenericTelephony", NULL, 0 },
};

const int uuid16_max = sizeof(uuid16_names)/sizeof(struct uuid_def);

void sdp_data_printf(sdp_data_t *, struct attrib_context *, int);

/*
 * Parse a UUID.
 * The BT assigned numbers only list UUID16, so I'm not sure the
 * other types will ever get used...
 */
void sdp_uuid_printf(uuid_t *uuid, struct attrib_context *context, int indent)
{
	if (uuid) {
		if (uuid->type == SDP_UUID16) {
			uint16_t uuidNum = uuid->value.uuid16;
			struct uuid_def *uuidDef = NULL;
			int i;

			for(i = 0; i < uuid16_max; i++)
				if(uuid16_names[i].num == uuidNum) {
					uuidDef = &uuid16_names[i];
					break;
				}

			/* Check if it's the service attribute */
			if (context->attrib && context->attrib->num == SERVICE_ATTR) {
				/* We got the service ID !!! */
				context->service = uuidDef;
			}

			if(uuidDef)
				printf("%.*sUUID16 : 0x%.4x - %s\n",
				       indent, indent_spaces,
				       uuidNum, uuidDef->name);
			else
				printf("%.*sUUID16 : 0x%.4x\n",
				       indent, indent_spaces, uuidNum);
		} else if (uuid->type == SDP_UUID32) {
			printf("%.*sUUID32 : 0x%.8x\n",
			       indent, indent_spaces, uuid->value.uuid32);
		} else if (uuid->type == SDP_UUID128) {
			unsigned int data0;
			unsigned short data1;
			unsigned short data2;
			unsigned short data3;
			unsigned int data4;
			unsigned short data5;

			memcpy(&data0, &uuid->value.uuid128.data[0], 4);
			memcpy(&data1, &uuid->value.uuid128.data[4], 2);
			memcpy(&data2, &uuid->value.uuid128.data[6], 2);
			memcpy(&data3, &uuid->value.uuid128.data[8], 2);
			memcpy(&data4, &uuid->value.uuid128.data[10], 4);
			memcpy(&data5, &uuid->value.uuid128.data[14], 2);

			printf("%.*sUUID128 : 0x%.8x-%.4x-%.4x-%.4x-%.8x-%.4x\n",
			       indent, indent_spaces,
			       ntohl(data0), ntohs(data1), ntohs(data2),
			       ntohs(data3), ntohl(data4), ntohs(data5));
		} else
			printf("%.*sEnum type of UUID not set\n",
			       indent, indent_spaces);
	} else
		printf("%.*sNull passed to print UUID\n",
		       indent, indent_spaces);
}

/*
 * Parse a sequence of data elements (i.e. a list)
 */
static void printf_dataseq(sdp_data_t * pData,
			       struct attrib_context *context,
			       int indent)
{
	sdp_data_t *sdpdata = NULL;

	sdpdata = pData;
	if (sdpdata) {
		context->member_index = 0;
		do {
			sdp_data_printf(sdpdata, context, indent + 2);
			sdpdata = sdpdata->next;
			context->member_index++;
		} while (sdpdata);
	} else {
		printf("%.*sBroken dataseq link\n", indent, indent_spaces);
	}
}

/*
 * Parse a single data element (either in the attribute or in a data
 * sequence).
 */
void sdp_data_printf(sdp_data_t *sdpdata,
		     struct attrib_context *context,
		     int indent)
{
	char *member_name = NULL;

	/* Find member name. Almost black magic ;-) */
	if (context->attrib && context->attrib->members &&
	   context->member_index < context->attrib->member_max) {
	  member_name = context->attrib->members[context->member_index].name;
	}

	switch (sdpdata->dtd) {
	case SDP_DATA_NIL:
		printf("%.*sNil\n", indent, indent_spaces);
		break;
	case SDP_BOOL:
	case SDP_UINT8:
	case SDP_UINT16:
	case SDP_UINT32:
	case SDP_UINT64:
	case SDP_UINT128:
	case SDP_INT8:
	case SDP_INT16:
	case SDP_INT32:
	case SDP_INT64:
	case SDP_INT128:
		if (member_name) {
			printf("%.*s%s (Integer) : 0x%x\n",
			       indent, indent_spaces,
			       member_name, sdpdata->val.uint32);
		} else {
			printf("%.*sInteger : 0x%x\n", indent, indent_spaces,
			       sdpdata->val.uint32);
		}
		break;

	case SDP_UUID16:
	case SDP_UUID32:
	case SDP_UUID128:
		//printf("%.*sUUID\n", indent, indent_spaces);
		sdp_uuid_printf(&sdpdata->val.uuid, context, indent);
		break;

	case SDP_TEXT_STR8:
	case SDP_TEXT_STR16:
	case SDP_TEXT_STR32:
		if (sdpdata->unitSize > strlen(sdpdata->val.str)) {
			int i;
			printf("%.*sData :", indent, indent_spaces);
			for (i = 0; i < sdpdata->unitSize; i++)
				printf(" %02x", (unsigned char) sdpdata->val.str[i]);
			printf("\n");
		} else
			printf("%.*sText : \"%s\"\n", indent, indent_spaces,
			       sdpdata->val.str);
		break;
	case SDP_URL_STR8:
	case SDP_URL_STR16:
	case SDP_URL_STR32:
		printf("%.*sURL : %s\n", indent, indent_spaces,
		       sdpdata->val.str);
		break;

	case SDP_SEQ8:
	case SDP_SEQ16:
	case SDP_SEQ32:
		printf("%.*sData Sequence\n", indent, indent_spaces);
		printf_dataseq(sdpdata->val.dataseq, context, indent);
		break;

	case SDP_ALT8:
	case SDP_ALT16:
	case SDP_ALT32:
		printf("%.*sData Sequence Alternates\n", indent, indent_spaces);
		printf_dataseq(sdpdata->val.dataseq, context, indent);
		break;
	}
}

/*
 * Parse a single attribute.
 */
void sdp_attr_printf_func(void *value, void *userData)
{
	sdp_data_t *sdpdata = NULL;
	uint16_t attrId;
	struct service_context *service = (struct service_context *) userData;
	struct attrib_context context;
	struct attrib_def *attrDef = NULL;
	int i;

	sdpdata = (sdp_data_t *)value;
	attrId = sdpdata->attrId;
	/* Search amongst the generic attributes */
	for (i = 0; i < attrib_max; i++)
		if (attrib_names[i].num == attrId) {
			attrDef = &attrib_names[i];
			break;
		}
	/* Search amongst the specific attributes of this service */
	if ((attrDef == NULL) &&
	   (service->service != NULL) &&
	   (service->service->attribs != NULL)) {
		struct attrib_def *svc_attribs = service->service->attribs;
		int		svc_attrib_max = service->service->attrib_max;
		for (i = 0; i < svc_attrib_max; i++)
			if (svc_attribs[i].num == attrId) {
				attrDef = &svc_attribs[i];
				break;
			}
	}

	if (attrDef)
		printf("Attribute Identifier : 0x%x - %s\n",
		       attrId, attrDef->name);
	else
		printf("Attribute Identifier : 0x%x\n", attrId);
	/* Build context */
	context.service = service->service;
	context.attrib = attrDef;
	context.member_index = 0;
	/* Parse attribute members */
	if (sdpdata)
		sdp_data_printf(sdpdata, &context, 2);
	else
		printf("  NULL value\n");
	/* Update service */
	service->service = context.service;
}

/*
 * Main entry point of this library. Parse a SDP record.
 * We assume the record has already been read, parsed and cached
 * locally. Jean II
 */
void sdp_printf_service_attr(sdp_record_t *rec)
{
	if (rec && rec->attrlist) {
		struct service_context service = { NULL };
		sdp_list_foreach(rec->attrlist, sdp_attr_printf_func, &service);
	}
}

/*
 * Set attributes with single values in SDP record
 * Jean II
 */
int set_attrib(sdp_session_t *sess, uint32_t handle, uint16_t attrib, char *value) 
{
	sdp_list_t *attrid_list;
	uint32_t range = 0x0000ffff;
	sdp_record_t *rec;
		
	/* Get the old SDP record */
	attrid_list = sdp_list_append(NULL, &range);
	rec = sdp_service_attr_req(sess, handle, SDP_ATTR_REQ_RANGE, attrid_list);

	if (!rec) {
		printf("Service get request failed.\n");
		return -1;
	}

	/* Check the type of attribute */
	if (!strncasecmp(value, "u0x", 3)) {
		/* UUID16 */
		uint16_t value_int = 0;
		uuid_t value_uuid;
		value_int = strtoul(value + 3, NULL, 16);
		sdp_uuid16_create(&value_uuid, value_int);
		printf("Adding attrib 0x%X uuid16 0x%X to record 0x%X\n",
		       attrib, value_int, handle);

		sdp_attr_add_new(rec, attrib, SDP_UUID16, &value_uuid.value.uuid16);
	} else if (!strncasecmp(value, "0x", 2)) {
		/* Int */
		uint32_t value_int;  
		value_int = strtoul(value + 2, NULL, 16);
		printf("Adding attrib 0x%X int 0x%X to record 0x%X\n",
		       attrib, value_int, handle);

		sdp_attr_add_new(rec, attrib, SDP_UINT32, &value_int);
	} else {
		/* String */
		printf("Adding attrib 0x%X string \"%s\" to record 0x%X\n",
		       attrib, value, handle);

		/* Add/Update our attribute to the record */
		sdp_attr_add_new(rec, attrib, SDP_TEXT_STR8, value);
	}

	/* Update on the server */
	if (sdp_record_update(sess, rec)) {
		printf("Service Record update failed (%d).\n", errno);
		return -1;
	}
	return 0;
}

static struct option set_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *set_help = 
	"Usage:\n"
	"\tget record_handle attrib_id attrib_value\n";

/*
 * Add an attribute to an existing SDP record on the local SDP server
 */
int cmd_setattr(int argc, char **argv)
{
	int opt, status;
	uint32_t handle;
	uint16_t attrib;
	sdp_session_t *sess;

	for_each_opt(opt, set_options, NULL) {
		switch(opt) {
		default:
			printf(set_help);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 3) {
		printf(set_help);
		return -1;
	}

	/* Convert command line args */
	handle = strtoul(argv[0], NULL, 16);
	attrib = strtoul(argv[1], NULL, 16);

	/* Do it */
	sess = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
	if (!sess)
		return -1;
	status = set_attrib(sess, handle, attrib, argv[2]);
	sdp_close(sess);
	return status;
}

/*
 * We do only simple data sequences. Sequence of sequences is a pain ;-)
 * Jean II
 */
int set_attribseq(sdp_session_t *session, uint32_t handle, uint16_t attrib, int argc, char **argv)
{
	sdp_list_t *attrid_list;
	uint32_t range = 0x0000ffff;
	sdp_record_t *rec;
	sdp_data_t *pSequenceHolder = NULL;
	void **dtdArray;
	void **valueArray;
	void **allocArray;
	uint8_t uuid16 = SDP_UUID16;
	uint8_t uint32 = SDP_UINT32;
	uint8_t str8 = SDP_TEXT_STR8;
	int i;

	/* Get the old SDP record */
	attrid_list = sdp_list_append(NULL, &range);
	rec = sdp_service_attr_req(session, handle, SDP_ATTR_REQ_RANGE, attrid_list);

	if (!rec) {
		printf("Service get request failed.\n");
		return -1;
	}

	/* Create arrays */
	dtdArray = (void **)malloc(argc * sizeof(void *));
	valueArray = (void **)malloc(argc * sizeof(void *));
	allocArray = (void **)malloc(argc * sizeof(void *));

	/* Loop on all args, add them in arrays */
	for (i = 0; i < argc; i++) {
		/* Check the type of attribute */
		if (!strncasecmp(argv[i], "u0x", 3)) {
			/* UUID16 */
			uint16_t value_int = strtoul((argv[i]) + 3, NULL, 16);
			uuid_t *value_uuid = (uuid_t *)malloc(sizeof(uuid_t));
			allocArray[i] = value_uuid;
			sdp_uuid16_create(value_uuid, value_int);

			printf("Adding uuid16 0x%X to record 0x%X\n",
			       value_int, handle);
			dtdArray[i] = &uuid16;
			valueArray[i] = &value_uuid->value.uuid16;
		} else if (!strncasecmp(argv[i], "0x", 2)) {
			/* Int */
			uint32_t *value_int = (int *)malloc(sizeof(int));
			allocArray[i] = value_int;
			*value_int = strtoul((argv[i]) + 2, NULL, 16);

			printf("Adding int 0x%X to record 0x%X\n",
			       *value_int, handle);
			dtdArray[i] = &uint32;
			valueArray[i] = value_int;
		} else {
			/* String */
			printf("Adding string \"%s\" to record 0x%X\n",
			       argv[i], handle);
			dtdArray[i] = &str8;
			valueArray[i] = argv[i];
		}
	}

	/* Add this sequence to the attrib list */
	pSequenceHolder = sdp_seq_alloc(dtdArray, valueArray, argc);
	if (pSequenceHolder) {
		sdp_attr_replace(rec, attrib, pSequenceHolder);

		/* Update on the server */
		if (sdp_record_update(session, rec)) {
			printf("Service Record update failed (%d).\n", errno);
			return -1;
		}
	} else {
		printf("Failed to create pSequenceHolder\n");
	}

	/* Cleanup */
	for (i = 0; i < argc; i++)
		free(allocArray[i]);
	free(dtdArray);
	free(valueArray);

	return 0;
}

static struct option seq_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *seq_help = 
	"Usage:\n"
	"\tget record_handle attrib_id attrib_values\n";

/*
 * Add an attribute sequence to an existing SDP record
 * on the local SDP server
 */
int cmd_setseq(int argc, char **argv)
{
	int opt, status;
	uint32_t handle;
	uint16_t attrib;
	sdp_session_t *sess;

	for_each_opt(opt, seq_options, NULL) {
		switch(opt) {
		default:
			printf(seq_help);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 3) {
		printf(seq_help);
		return -1;
	}

	/* Convert command line args */
	handle = strtoul(argv[0], NULL, 16);
	attrib = strtoul(argv[1], NULL, 16);

	argc -= 2;
	argv += 2;

	/* Do it */
	sess = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
	if (!sess)
		return -1;
	status = set_attribseq(sess, handle, attrib, argc, argv);
	sdp_close(sess);
	return status;
}

static void print_service_class(void *value, void *userData)
{
	char ServiceClassUUID_str[MAX_LEN_SERVICECLASS_UUID_STR];
	uuid_t *uuid = (uuid_t *)value;

	sdp_uuid2strn(uuid, UUID_str, MAX_LEN_UUID_STR);
	sdp_svclass_uuid2strn(uuid, ServiceClassUUID_str, MAX_LEN_SERVICECLASS_UUID_STR);
	printf("  \"%s\" (0x%s)\n", ServiceClassUUID_str, UUID_str);
}

static void print_service_desc(void *value, void *user)
{
	char str[MAX_LEN_PROTOCOL_UUID_STR];
	sdp_data_t *p = (sdp_data_t *)value, *s;
	int i = 0, proto = 0;
	
	for (; p; p = p->next, i++) {
		switch (p->dtd) {
		case SDP_UUID16:
		case SDP_UUID32:
		case SDP_UUID128:
			sdp_uuid2strn(&p->val.uuid, UUID_str, MAX_LEN_UUID_STR);
			sdp_proto_uuid2strn(&p->val.uuid, str, sizeof(str));
			proto = sdp_uuid_to_proto(&p->val.uuid);
			printf("  \"%s\" (0x%s)\n", str, UUID_str);
			break;
		case SDP_UINT8:
			if (proto == RFCOMM_UUID)
				printf("    Channel: %d\n", p->val.uint8);
			else
				printf("    uint8: 0x%x\n", p->val.uint8);
			break;
		case SDP_UINT16:
			if (proto == L2CAP_UUID) {
				if (i == 1)
					printf("    PSM: %d\n", p->val.uint16);
				else
					printf("    Version: 0x%04x\n", p->val.uint16);
			} else if (proto == BNEP_UUID)
				if (i == 1)
					printf("    Version: 0x%04x\n", p->val.uint16);
				else
					printf("    uint16: 0x%x\n", p->val.uint16);
			else
				printf("    uint16: 0x%x\n", p->val.uint16);
			break;
		case SDP_SEQ16:
			printf("    SEQ16:");
			for (s = p->val.dataseq; s; s = s->next)
				printf(" %x", s->val.uint16);
			printf("\n");
			break;
		case SDP_SEQ8:
			printf("    SEQ8:");
			for (s = p->val.dataseq; s; s = s->next)
				printf(" %x", s->val.uint8);
			printf("\n");
			break;
		default:
			printf("    FIXME: dtd=0%x\n", p->dtd);
			break;
		}
	}
}

void print_lang_attr(void *value, void *user)
{
	sdp_lang_attr_t *lang = (sdp_lang_attr_t *)value;
	printf("  code_ISO639: 0x%02x\n", lang->code_ISO639);
	printf("  encoding:    0x%02x\n", lang->encoding);
	printf("  base_offset: 0x%02x\n", lang->base_offset);
}

void print_access_protos(void *value, void *userData)
{
	sdp_list_t *protDescSeq = (sdp_list_t *)value;
	sdp_list_foreach(protDescSeq, print_service_desc, 0);
}

void print_profile_desc(void *value, void *userData)
{
	sdp_profile_desc_t *desc = (sdp_profile_desc_t *)value;
	char str[MAX_LEN_PROFILEDESCRIPTOR_UUID_STR];

	sdp_uuid2strn(&desc->uuid, UUID_str, MAX_LEN_UUID_STR);
	sdp_profile_uuid2strn(&desc->uuid, str, MAX_LEN_PROFILEDESCRIPTOR_UUID_STR);

	printf("  \"%s\" (0x%s)\n", str, UUID_str);
	if (desc->version)
		printf("    Version: 0x%04x\n", desc->version);
}

/*
 * Parse a SDP record in user friendly form.
 */
void print_service_attr(sdp_record_t *rec)
{
	sdp_list_t *list = 0, *proto = 0;

	sdp_record_print(rec);

	printf("Service RecHandle: 0x%x\n", rec->handle);

	if (sdp_get_service_classes(rec, &list) == 0) {
		printf("Service Class ID List:\n");
		sdp_list_foreach(list, print_service_class, 0);
		sdp_list_free(list, free);
	}
	if (sdp_get_access_protos(rec, &proto) == 0) {
		printf("Protocol Descriptor List:\n");
		sdp_list_foreach(proto, print_access_protos, 0);
		sdp_list_free(proto, (sdp_free_func_t)sdp_data_free);
	}
	if (sdp_get_lang_attr(rec, &list) == 0) {
		printf("Language Base Attr List:\n");
		sdp_list_foreach(list, print_lang_attr, 0);
		sdp_list_free(list, free);
	}
	if (sdp_get_profile_descs(rec, &list) == 0) {
		printf("Profile Descriptor List:\n");
		sdp_list_foreach(list, print_profile_desc, 0);
		sdp_list_free(list, free);
	}
}

/*
 * Support for Service (de)registration
 */
typedef struct {
	char *name;
	char *provider;
	char *desc;
	
	unsigned int class;
	unsigned int profile;
	unsigned int channel;
} svc_info_t;

static int add_sp(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *apseq, *proto[2], *profiles, *root, *aproto;
	uuid_t root_uuid, sp_uuid, l2cap, rfcomm;
	sdp_profile_desc_t profile;
	sdp_record_t record;
	uint8_t u8 = si->channel? si->channel: 1;
	sdp_data_t *channel;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);
	sdp_list_free(root, 0);

	sdp_uuid16_create(&sp_uuid, SERIAL_PORT_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &sp_uuid);
	sdp_set_service_classes(&record, svclass_id);
	sdp_list_free(svclass_id, 0);

	sdp_uuid16_create(&profile.uuid, SERIAL_PORT_PROFILE_ID);
	profile.version = 0x0100;
	profiles = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, profiles);
	sdp_list_free(profiles, 0);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Serial Port", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("Serial Port service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_dun(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root, *aproto;
	uuid_t rootu, dun, gn, l2cap, rfcomm;
	sdp_profile_desc_t profile;
	sdp_list_t *proto[2];
	sdp_record_t record;
	uint8_t u8 = si->channel? si->channel: 1;
	sdp_data_t *channel;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&rootu, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &rootu);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&dun, DIALUP_NET_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &dun);
	sdp_uuid16_create(&gn,  GENERIC_NETWORKING_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &gn);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, DIALUP_NET_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Dial-Up Networking", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("Dial-Up Networking service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_lan(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint8_t u8 = si->channel? si->channel: 2;
	sdp_data_t *channel;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, LAN_ACCESS_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, LAN_ACCESS_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "LAN Access over PPP", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("LAN Access service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}


static int add_headset(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid, l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint8_t u8 = si->channel? si->channel: 5;
	sdp_data_t *channel;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, HEADSET_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HEADSET_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Headset", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("Headset service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_handsfree(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid, l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint8_t u8 = si->channel? si->channel: 3;
	uint16_t u16 = 0x31;
	sdp_data_t *channel, *features;	
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = 0x0101;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	features = sdp_data_alloc(SDP_UINT16, &u16);
	sdp_attr_add(&record, SDP_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Handsfree", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("Handsfree service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_simaccess(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid, l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint8_t u8 = si->channel? si->channel: 3;
	uint16_t u16 = 0x31;
	sdp_data_t *channel, *features;	
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, SAP_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_TELEPHONY_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, SAP_PROFILE_ID);
	profile.version = 0x0101;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	features = sdp_data_alloc(SDP_UINT16, &u16);
	sdp_attr_add(&record, SDP_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "SIM Access", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("Handsfree service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_fax(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, fax_uuid, tel_uuid, l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint8_t u8 = si->channel? si->channel: 3;
	sdp_data_t *channel;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&fax_uuid, FAX_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &fax_uuid);
	sdp_uuid16_create(&tel_uuid, GENERIC_TELEPHONY_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &tel_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, FAX_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq  = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Fax", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("Fax service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_opush(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, opush_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	sdp_record_t record;
	uint8_t chan = si->channel? si->channel: 4;
	sdp_data_t *channel;
	uint8_t formats[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	//uint8_t formats[] = { 0xff };
	void *dtds[sizeof(formats)], *values[sizeof(formats)];
	int i;
	uint8_t dtd = SDP_UINT8;
	sdp_data_t *sflist;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&opush_uuid, OBEX_OBJPUSH_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &opush_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, OBEX_OBJPUSH_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &chan);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(0, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	for (i = 0; i < sizeof(formats); i++) {
		dtds[i] = &dtd;
		values[i] = &formats[i];
	}
	sflist = sdp_seq_alloc(dtds, values, sizeof(formats));
	sdp_attr_add(&record, SDP_ATTR_SUPPORTED_FORMATS_LIST, sflist);

	sdp_set_info_attr(&record, "OBEX Object Push", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("OBEX Object Push service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(proto[2], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_file_trans(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, ftrn_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	sdp_record_t record;
	uint8_t u8 = si->channel? si->channel: 4;
	sdp_data_t *channel;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&ftrn_uuid, OBEX_FILETRANS_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &ftrn_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, OBEX_FILETRANS_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &u8);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(0, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "OBEX File Transfer", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("OBEX File Transfer service registered\n");
end:
	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(proto[2], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_nap(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, ftrn_uuid, l2cap_uuid, bnep_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint16_t lp = 0x000f, ver = 0x0100;
	sdp_data_t *psm, *version;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&ftrn_uuid, NAP_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &ftrn_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, NAP_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&bnep_uuid, BNEP_UUID);
	proto[1] = sdp_list_append(0, &bnep_uuid);
	version  = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);

	{
		uint16_t ptype[4] = { 0x0010, 0x0020, 0x0030, 0x0040 };
		sdp_data_t *head, *pseq;
		int p;

		for (p = 0, head = NULL; p < 4; p++) {
			sdp_data_t *data = sdp_data_alloc(SDP_UINT16, &ptype[p]);
			head = sdp_seq_append(head, data);
		}
		pseq = sdp_data_alloc(SDP_SEQ16, head);
		proto[1] = sdp_list_append(proto[1], pseq);
	}

	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Network Access Point Service", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("NAP service registered\n");
end:
	sdp_data_free(version);
	sdp_data_free(psm);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_gn(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, ftrn_uuid, l2cap_uuid, bnep_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint16_t lp = 0x000f, ver = 0x0100;
	sdp_data_t *psm, *version;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&ftrn_uuid, GN_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &ftrn_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, GN_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&bnep_uuid, BNEP_UUID);
	proto[1] = sdp_list_append(0, &bnep_uuid);
	version = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Group Network Service", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("GN service registered\n");
end:
	sdp_data_free(version);
	sdp_data_free(psm);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_hid(sdp_session_t *sess, svc_info_t *si)
{
	return -1;
}

static int add_cip(sdp_session_t *sess, svc_info_t *si)
{
	return -1;
}

static int add_ctp(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, tcsbin, ctp;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint8_t netid = 0x02; // 0x01-0x07 cf. p120 profile document
	sdp_data_t *network = sdp_data_alloc(SDP_UINT8, &netid);
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&ctp, CORDLESS_TELEPHONY_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &ctp);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, CORDLESS_TELEPHONY_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&tcsbin, TCS_BIN_UUID);
	proto[1] = sdp_list_append(0, &tcsbin);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_attr_add(&record, SDP_EXTERNAL_NETWORK, network);

	sdp_set_info_attr(&record, "Cordless Telephony", 0, 0);

	if (0 > sdp_record_register(session, &record, SDP_RECORD_PERSIST)) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto end;
	}
	printf("CTP service registered\n");
end:
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	sdp_data_free(network);
	return ret;
}

static int add_audio_source(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avdtp, a2src;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	sdp_data_t *psm, *version;
	uint16_t lp = 0x0019, ver = 0x0100;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&a2src, AUDIO_SOURCE_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &a2src);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, ADVANCED_AUDIO_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avdtp, AVDTP_UUID);
	proto[1] = sdp_list_append(0, &avdtp);
	version = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Audio Source", 0, 0);

	if (sdp_record_register(session, &record, SDP_RECORD_PERSIST) < 0) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto done;
	}

	printf("Audio source service registered\n");

done:
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

static int add_audio_sink(sdp_session_t *session, svc_info_t *si)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avdtp, a2snk;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	sdp_data_t *psm, *version;
	uint16_t lp = 0x0019, ver = 0x0100;
	int ret = 0;

	memset((void *)&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&a2snk, AUDIO_SINK_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &a2snk);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, ADVANCED_AUDIO_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avdtp, AVDTP_UUID);
	proto[1] = sdp_list_append(0, &avdtp);
	version = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Audio Sink", 0, 0);

	if (sdp_record_register(session, &record, SDP_RECORD_PERSIST) < 0) {
		printf("Service Record registration failed\n");
		ret = -1;
		goto done;
	}

	printf("Audio sink service registered\n");

done:
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);
	return ret;
}

struct {
	char     *name;
	uint16_t class;
	int      (*add)(sdp_session_t *sess, svc_info_t *si);
} service[] = {
	{ "SP",    SERIAL_PORT_SVCLASS_ID,    add_sp    },
	{ "DUN",   DIALUP_NET_SVCLASS_ID,     add_dun   },
	{ "LAN",   LAN_ACCESS_SVCLASS_ID,     add_lan   },
	{ "FAX",   FAX_SVCLASS_ID,            add_fax   },
	{ "OPUSH", OBEX_OBJPUSH_SVCLASS_ID,   add_opush },
	{ "FTRN",  OBEX_FILETRANS_SVCLASS_ID, add_file_trans },

	{ "HS",    HEADSET_SVCLASS_ID,        add_headset   },
	{ "HF",    HANDSFREE_SVCLASS_ID,      add_handsfree },
	{ "SAP",   SAP_SVCLASS_ID,            add_simaccess },

	{ "NAP",   NAP_SVCLASS_ID,            add_nap   },
	{ "GN",    GN_SVCLASS_ID,             add_gn    },

	{ "HID",   HID_SVCLASS_ID,            add_hid   },
	{ "CIP",   CIP_SVCLASS_ID,            add_cip   },
	{ "CTP",   CORDLESS_TELEPHONY_SVCLASS_ID, add_ctp },

	{ "A2SRC", AUDIO_SOURCE_SVCLASS_ID,   add_audio_source },
	{ "A2SNK", AUDIO_SINK_SVCLASS_ID,     add_audio_sink   },

	{ 0 }
};

/* Add local service */
int add_service(bdaddr_t *bdaddr, svc_info_t *si)
{
	int i;
	sdp_session_t *sess = sdp_connect(&interface, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);

	if (!sess)
		return -1;
	if (si->name)
		for (i=0; service[i].name; i++)
			if (!strcasecmp(service[i].name, si->name)) {
				int ret = service[i].add(sess, si);
				free(si->name);
				sdp_close(sess);
				return ret;
			}
	printf("Unknown service name: %s\n", si->name);
	free(si->name);
	sdp_close(sess);
	return -1;
}

static struct option add_options[] = {
	{"help",    0,0, 'h'},
	{"channel", 1,0, 'c'},
	{0, 0, 0, 0}
};

static char *add_help = 
	"Usage:\n"
	"\tadd [--channel=CHAN] service\n";

int cmd_add(int argc, char **argv)
{
	svc_info_t si;
	int opt;

	memset(&si, 0, sizeof(si));
	for_each_opt(opt, add_options, 0) {
		switch(opt) {
		case 'c':
			si.channel = atoi(optarg);
			break;
		default:
			printf(add_help);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(add_help);
		return -1;
	}

	si.name = strdup(argv[0]);
	return add_service(0, &si);
}

/* Delete local service */
int del_service(bdaddr_t *bdaddr, void *arg) 
{
	uint32_t handle, range = 0x0000ffff;
	sdp_list_t *attr;
	sdp_session_t *sess;
	sdp_record_t *rec;

	if (!arg) { 
		printf("Record handle was not specified.\n");
		return -1;
	}
	sess = sdp_connect(&interface, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
	if (!sess) {
		printf("No local SDP server!\n");
		return -1;
	}
	handle = strtoul((char *)arg, 0, 16);
	attr = sdp_list_append(0, &range);
	rec = sdp_service_attr_req(sess, handle, SDP_ATTR_REQ_RANGE, attr);
	sdp_list_free(attr, 0);
	if (!rec) {
		printf("Service Record not found.\n");
		sdp_close(sess);
		return -1;
	}
	if (sdp_record_unregister(sess, rec)) {
		printf("Failed to unregister service record: %s\n", strerror(errno));
		sdp_close(sess);
		return -1;
	}
	printf("Service Record deleted.\n");
	sdp_close(sess);
	return 0;
}

static struct option del_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *del_help = 
	"Usage:\n"
	"\tdel record_handle\n";

int cmd_del(int argc, char **argv)
{
	int opt;

	for_each_opt(opt, del_options, 0) {
		switch(opt) {
		default:
			printf(del_help);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(del_help);
		return -1;
	}
	return del_service(0, argv[0]);
}

/*
 * Perform an inquiry and search/browse all peer found.
 */
static void inquiry(handler_t handler, void *arg)
{
	inquiry_info ii[20];
	uint8_t count = 0;
	int i;

	printf("Inquiring ...\n");
	if (sdp_general_inquiry(ii, 20, 8, &count) < 0) {
		printf("Inquiry failed\n");
		return;
	}
	for (i=0; i<count; i++)
		handler(&ii[i].bdaddr, arg);
}

/*
 * Search for a specific SDP service
 */
int do_search(bdaddr_t *bdaddr, struct search_context *context)
{
	sdp_list_t *attrid, *search, *seq, *next;
	uint32_t range = 0x0000ffff;
	char str[20];
	sdp_session_t *sess;

	if (!bdaddr) {
		inquiry(do_search, context);
		return 0;
	}
	sess = sdp_connect(&interface, bdaddr, SDP_RETRY_IF_BUSY);
	ba2str(bdaddr, str);
	if (!sess) {
		printf("Failed to connect to SDP server on %s: %s\n", str, strerror(errno));
		return -1;
	}
	if (context->svc)
		printf("Searching for %s on %s ...\n", context->svc, str);
	else
		printf("Browsing %s ...\n", str);

	attrid = sdp_list_append(0, &range);
	search = sdp_list_append(0, &context->group);
	if (sdp_service_search_attr_req(sess, search, SDP_ATTR_REQ_RANGE, attrid, &seq)) {
		printf("Service Search failed: %s\n", strerror(errno));
		sdp_close(sess);
		return -1;
	}
	sdp_list_free(attrid, 0);
	sdp_list_free(search, 0);

	for (; seq; seq = next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		struct search_context sub_context;

		if (context->tree) {
			/* Display full tree */
			sdp_printf_service_attr(rec);
		} else {
			/* Display user friendly form */
			print_service_attr(rec);
		}
		printf("\n");
		
		if (sdp_get_group_id(rec, &sub_context.group) != -1) {
			/* Set the subcontext for browsing the sub tree */
			memcpy(&sub_context, context, sizeof(struct search_context));
			/* Browse the next level down if not done */
			if (sub_context.group.value.uuid16 != context->group.value.uuid16)
				do_search(bdaddr, &sub_context);
		}
		next = seq->next;
		free(seq);
		sdp_record_free(rec);
	}
	sdp_close(sess);
	return 0;
}

static struct option browse_options[] = {
	{"help",    0,0, 'h'},
	{"tree",    0,0, 't'},
	{0, 0, 0, 0}
};

static char *browse_help = 
	"Usage:\n"
	"\tbrowse [--tree] [bdaddr]\n";

/*
 * Browse the full SDP database (i.e. list all services starting from the
 * root/top-level).
 */
int cmd_browse(int argc, char **argv)
{
	struct search_context context;
	int opt;

	/* Initialise context */
	memset(&context, '\0', sizeof(struct search_context));
	/* We want to browse the top-level/root */
	sdp_uuid16_create(&(context.group), PUBLIC_BROWSE_GROUP);

	for_each_opt(opt, browse_options, 0) {
		switch(opt) {
		case 't':
			context.tree = 1;
			break;
		default:
			printf(browse_help);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc >= 1) {
		bdaddr_t bdaddr;
		estr2ba(argv[0], &bdaddr);
		return do_search(&bdaddr, &context);
	}
	return do_search(0, &context);
}

static struct option search_options[] = {
	{"help",    0,0, 'h'},
	{"bdaddr",  1,0, 'b'},
	{"tree",    0,0, 't'},
	{0, 0, 0, 0}
};

static char *search_help = 
	"Usage:\n"
	"\tsearch [--bdaddr bdaddr] [--tree] SERVICE\n"
	"SERVICE is a name (string) or UUID (0x1002)\n";

/*
 * Search for a specific SDP service
 *
 * Note : we should support multiple services on the command line :
 *	sdptool search 0x0100 0x000f 0x1002
 * (this would search a service supporting both L2CAP and BNEP directly in
 * the top level browse group)
 */
int cmd_search(int argc, char **argv)
{
	struct search_context context;
	uint16_t class = 0;
	bdaddr_t bdaddr;
	int has_addr = 0;
	int i;
	int opt;

	/* Initialise context */
	memset(&context, '\0', sizeof(struct search_context));

	for_each_opt(opt, search_options, 0) {
		switch(opt) {
		case 'b':
			estr2ba(optarg, &bdaddr);
			has_addr = 1;
			break;
		case 't':
			context.tree = 1;
			break;
		default:
			printf(search_help);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(search_help);
		return -1;
	}
	/* Note : we need to find a way to support search combining
	 * multiple services - Jean II */
	context.svc = strdup(argv[0]);
	if (!strncasecmp(context.svc, "0x", 2)) {
		int num;
		/* This is a UUID16, just convert to int */
		sscanf(context.svc + 2, "%X", &num);
		class = num;
		printf("Class 0x%X\n", class);
	} else {
		/* Convert class name to an UUID */

		for (i=0; service[i].name; i++)
			if (strcasecmp(context.svc, service[i].name) == 0) {
				class = service[i].class;
				break;
			}
		if (!class) {
			printf("Unknown service %s\n", context.svc);
			return -1;
		}
	}	

	sdp_uuid16_create(&context.group, class);

	if (has_addr)
		return do_search(&bdaddr, &context);
	return do_search(0, &context);
}

/*
 * Show how to get a specific SDP record by its handle.
 * Not really useful to the user, just show how it can be done...
 * Jean II
 */
int get_service(bdaddr_t *bdaddr, struct search_context *context) 
{
	sdp_list_t *attrid;
	uint32_t range = 0x0000ffff;
	sdp_record_t *rec;
	sdp_session_t *session = sdp_connect(&interface, bdaddr, SDP_RETRY_IF_BUSY);

	if (!session) {
		char str[20];
		ba2str(bdaddr, str);
		printf("Failed to connect to SDP server on %s: %s\n", str, strerror(errno));
		return -1;
	}
	attrid = sdp_list_append(0, &range);
	rec = sdp_service_attr_req(session, context->handle, SDP_ATTR_REQ_RANGE, attrid);
	sdp_list_free(attrid, 0);
	sdp_close(session);
	if (!rec) {
		printf("Service get request failed.\n");
		return -1;
	}
	if (context->tree) {
		/* Display full tree */
		sdp_printf_service_attr(rec);
	} else {
		/* Display user friendly form */
		print_service_attr(rec);
	}
	printf("\n");
	sdp_record_free(rec);
	return 0;
}

static struct option get_options[] = {
	{"help",    0,0, 'h'},
	{"bdaddr",  1,0, 'b'},
	{"tree",    0,0, 't'},
	{0, 0, 0, 0}
};

static char *get_help = 
	"Usage:\n"
	"\tget [--tree] [--bdaddr bdaddr] record_handle\n";

/*
 * Get a specific SDP record on the local SDP server
 */
int cmd_get(int argc, char **argv)
{
	struct search_context context;
	bdaddr_t bdaddr;
	int has_addr = 0;
	int opt;

	/* Initialise context */
	memset(&context, '\0', sizeof(struct search_context));

	for_each_opt(opt, get_options, 0) {
		switch(opt) {
		case 'b':
			estr2ba(optarg, &bdaddr);
			has_addr = 1;
			break;
		case 't':
			context.tree = 1;
			break;
		default:
			printf(get_help);
			return -1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(get_help);
		return -1;
	}
	/* Convert command line parameters */
	context.handle = strtoul(argv[0], 0, 16);

	return get_service(has_addr? &bdaddr: BDADDR_LOCAL, &context);
}

struct {
	char *cmd;
	int (*func)(int argc, char **argv);
	char *doc;
} command[] = {
	{ "search",  cmd_search,      "Search for a service"          },
	{ "browse",  cmd_browse,      "Browse all available services" },
	{ "add",     cmd_add,         "Add local service"             },
	{ "del",     cmd_del,         "Delete local service"          },
	{ "get",     cmd_get,         "Get local service"             },
	{ "setattr", cmd_setattr,     "Set/Add attribute to a SDP record" },
	{ "setseq",  cmd_setseq,      "Set/Add attribute sequence to a SDP record" },
	{ 0, 0, 0}
};

static void usage(void)
{
	int i;

	printf("sdptool - SDP Tool v%s\n", VERSION);
	printf("Usage:\n"
		"\tsdptool [options] <command> [command parameters]\n");
	printf("Options:\n"
		"\t--help\t\tDisplay help\n"
		"\t--source\tSpecify source interface\n");

	printf("Commands:\n");
	for (i=0; command[i].cmd; i++)
		printf("\t%-4s\t\t%s\n", command[i].cmd, command[i].doc);

	printf("\nServices:\n\t");
	for (i=0; service[i].name; i++)
		printf("%s ", service[i].name);
	printf("\n");
}

static struct option main_options[] = {
	{"help",   0, 0, 'h'},
	{"source", 1, 0, 'S'},
	{0, 0, 0, 0}
};

int main(int argc, char **argv)
{
	int opt, i;

	bacpy(&interface, BDADDR_ANY);
	while ((opt=getopt_long(argc, argv, "+hS:", main_options, 0)) != -1) {
		switch(opt) {
		case 'S':
			str2ba(optarg, &interface);
			break;
		case 'h':
		default:
			usage();
			return -1;
		}
	}
	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		usage();
		return -1;
	}
	for (i=0; command[i].cmd; i++)
		if (strncmp(command[i].cmd, argv[0], 4) == 0)
			return command[i].func(argc, argv);
	return -1;
}

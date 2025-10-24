/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *
 */

#ifndef TOOLS_PARSER_OPCODES_H
#define TOOLS_PARSER_OPCODES_H

char *opcode2str(uint8_t opcode)
{
	switch (opcode & 0x7f) {
	case 0x00:
		return "Connect";
	case 0x01:
		return "Disconnect";
	case 0x02:
		return "Put";
	case 0x03:
		return "Get";
	case 0x04:
		return "Reserved";
	case 0x05:
		return "SetPath";
	case 0x06:
		return "Action";
	case 0x07:
		return "Session";
	case 0x7f:
		return "Abort";
	case 0x10:
		return "Continue";
	case 0x20:
		return "Success";
	case 0x21:
		return "Created";
	case 0x22:
		return "Accepted";
	case 0x23:
		return "Non-authoritative information";
	case 0x24:
		return "No content";
	case 0x25:
		return "Reset content";
	case 0x26:
		return "Partial content";
	case 0x30:
		return "Multiple choices";
	case 0x31:
		return "Moved permanently";
	case 0x32:
		return "Moved temporarily";
	case 0x33:
		return "See other";
	case 0x34:
		return "Not modified";
	case 0x35:
		return "Use Proxy";
	case 0x40:
		return "Bad request";
	case 0x41:
		return "Unauthorized";
	case 0x42:
		return "Payment required";
	case 0x43:
		return "Forbidden";
	case 0x44:
		return "Not found";
	case 0x45:
		return "Method not allowed";
	case 0x46:
		return "Not acceptable";
	case 0x47:
		return "Proxy authentication required";
	case 0x48:
		return "Request timeout";
	case 0x49:
		return "Conflict";
	case 0x4a:
		return "Gone";
	case 0x4b:
		return "Length required";
	case 0x4c:
		return "Precondition failed";
	case 0x4d:
		return "Requested entity too large";
	case 0x4e:
		return "Requested URL too large";
	case 0x4f:
		return "Unsupported media type";
	case 0x50:
		return "Internal server error";
	case 0x51:
		return "Not implemented";
	case 0x52:
		return "Bad gateway";
	case 0x53:
		return "Service unavailable";
	case 0x54:
		return "Gateway timeout";
	case 0x55:
		return "HTTP version not supported";
	case 0x60:
		return "Database full";
	case 0x61:
		return "Database locked";
	default:
		return "Unknown";
	}
}

#endif /* TOOLS_PARSER_OPCODES_H */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdint.h>

#define AG_FEATURE_THREE_WAY_CALLING             0x0001
#define AG_FEATURE_EC_ANDOR_NR                   0x0002
#define AG_FEATURE_VOICE_RECOGNITION             0x0004
#define AG_FEATURE_INBAND_RINGTONE               0x0008
#define AG_FEATURE_ATTACH_NUMBER_TO_VOICETAG     0x0010
#define AG_FEATURE_REJECT_A_CALL                 0x0020
#define AG_FEATURE_ENHANCES_CALL_STATUS          0x0040
#define AG_FEATURE_ENHANCES_CALL_CONTROL         0x0080
#define AG_FEATURE_EXTENDED_ERROR_RESULT_CODES   0x0100

struct indicator {
	const char *desc;
	const char *range;
	int val;
};

int telephony_features_req(void);
void telephony_features_rsp(uint32_t features);

struct indicator *telephony_indicators_req(void);

int telephony_init(void);
void telephony_exit(void);

/*
 *
 *  CSR BlueCore specific functions
 *
 *  Copyright (C) 2003  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#define CSR_VARID_BUILDID		0x2819
#define CSR_VARID_CHIPVER		0x281a
#define CSR_VARID_CHIPREV		0x281b
#define CSR_VARID_MAX_CRYPT_KEY_LENGTH	0x282c

#define CSR_PSKEY_HOSTIO_MAP_SCO_PCM	0x01ab

char *csr_buildidtostr(uint16_t id);
char *csr_chipvertostr(uint16_t ver, uint16_t rev);

int csr_read_varid_uint16(int dd, uint16_t seqnum, uint16_t varid, uint16_t *value);
int csr_read_pskey_uint16(int dd, uint16_t seqnum, uint16_t pskey, uint16_t *value);

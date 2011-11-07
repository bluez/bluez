/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include "textfile.h"

int read_device_alias(const char *src, const char *dst, char *alias, size_t size);
int write_device_alias(const char *src, const char *dst, const char *alias);
int write_discoverable_timeout(bdaddr_t *bdaddr, int timeout);
int read_discoverable_timeout(const char *src, int *timeout);
int write_pairable_timeout(bdaddr_t *bdaddr, int timeout);
int read_pairable_timeout(const char *src, int *timeout);
int write_device_mode(bdaddr_t *bdaddr, const char *mode);
int read_device_mode(const char *src, char *mode, int length);
int read_on_mode(const char *src, char *mode, int length);
int write_local_name(bdaddr_t *bdaddr, const char *name);
int read_local_name(bdaddr_t *bdaddr, char *name);
int write_local_class(bdaddr_t *bdaddr, uint8_t *class);
int read_local_class(bdaddr_t *bdaddr, uint8_t *class);
int write_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class);
int read_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t *class);
int write_device_name(bdaddr_t *local, bdaddr_t *peer, char *name);
int read_device_name(const char *src, const char *dst, char *name);
int write_remote_eir(bdaddr_t *local, bdaddr_t *peer, uint8_t *data);
int read_remote_eir(bdaddr_t *local, bdaddr_t *peer, uint8_t *data);
int write_version_info(bdaddr_t *local, bdaddr_t *peer, uint16_t manufacturer, uint8_t lmp_ver, uint16_t lmp_subver);
int write_features_info(bdaddr_t *local, bdaddr_t *peer, unsigned char *page1, unsigned char *page2);
int read_remote_features(bdaddr_t *local, bdaddr_t *peer, unsigned char *page1, unsigned char *page2);
int write_lastseen_info(bdaddr_t *local, bdaddr_t *peer, struct tm *tm);
int write_lastused_info(bdaddr_t *local, bdaddr_t *peer, struct tm *tm);
int write_link_key(bdaddr_t *local, bdaddr_t *peer, unsigned char *key, uint8_t type, int length);
int read_link_key(bdaddr_t *local, bdaddr_t *peer, unsigned char *key, uint8_t *type);
ssize_t read_pin_code(bdaddr_t *local, bdaddr_t *peer, char *pin);
gboolean read_trust(const bdaddr_t *local, const char *addr, const char *service);
int write_trust(const char *src, const char *addr, const char *service, gboolean trust);
int write_device_profiles(bdaddr_t *src, bdaddr_t *dst, const char *profiles);
int delete_entry(bdaddr_t *src, const char *storage, const char *key);
int store_record(const gchar *src, const gchar *dst, sdp_record_t *rec);
sdp_record_t *record_from_string(const gchar *str);
sdp_record_t *fetch_record(const gchar *src, const gchar *dst, const uint32_t handle);
int delete_record(const gchar *src, const gchar *dst, const uint32_t handle);
void delete_all_records(const bdaddr_t *src, const bdaddr_t *dst);
sdp_list_t *read_records(const bdaddr_t *src, const bdaddr_t *dst);
sdp_record_t *find_record_in_list(sdp_list_t *recs, const char *uuid);
int store_device_id(const gchar *src, const gchar *dst,
				const uint16_t source, const uint16_t vendor,
				const uint16_t product, const uint16_t version);
int read_device_id(const gchar *src, const gchar *dst,
					uint16_t *source, uint16_t *vendor,
					uint16_t *product, uint16_t *version);
int write_device_pairable(bdaddr_t *local, gboolean mode);
int read_device_pairable(bdaddr_t *local, gboolean *mode);
gboolean read_blocked(const bdaddr_t *local, const bdaddr_t *remote);
int write_blocked(const bdaddr_t *local, const bdaddr_t *remote,
							gboolean blocked);
int write_device_services(const bdaddr_t *sba, const bdaddr_t *dba,
							const char *services);
int delete_device_service(const bdaddr_t *sba, const bdaddr_t *dba);
char *read_device_services(const bdaddr_t *sba, const bdaddr_t *dba);
int write_device_characteristics(const bdaddr_t *sba, const bdaddr_t *dba,
					uint16_t handle, const char *chars);
char *read_device_characteristics(const bdaddr_t *sba, const bdaddr_t *dba,
							uint16_t handle);
int write_device_attribute(const bdaddr_t *sba, const bdaddr_t *dba,
                                        uint16_t handle, const char *chars);
int read_device_attributes(const bdaddr_t *sba, textfile_cb func, void *data);
int read_device_ccc(bdaddr_t *local, bdaddr_t *peer, uint16_t handle,
							uint16_t *value);
int write_device_ccc(bdaddr_t *local, bdaddr_t *peer, uint16_t handle,
							uint16_t value);
void delete_device_ccc(bdaddr_t *local, bdaddr_t *peer);

#define PNP_UUID		"00001200-0000-1000-8000-00805f9b34fb"


/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Instituto Nokia de Tecnologia - INdT
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

struct btd_attribute;

void gatt_init(void);

void gatt_cleanup(void);

/*
 * Callbacks of this type are called once the value from the attribute is
 * ready to be read from the service implementation. Result callback is
 * the asynchronous function that should be used to inform the caller
 * the read value.
 * @err:	error in -errno format.
 * @value:	pointer to value
 * @len:	length of value
 * @user_data:	user_data passed in btd_attr_read_t callback
 */
typedef void (*btd_attr_read_result_t) (int err, uint8_t *value, size_t len,
							void *user_data);
typedef void (*btd_attr_read_t) (struct btd_attribute *attr,
						btd_attr_read_result_t result,
						void *user_data);

/* btd_gatt_add_service - Add a service declaration to local attribute database.
 * @uuid:	Service UUID.
 *
 * Returns a reference to service declaration attribute. In case of error,
 * NULL is returned.
 */
struct btd_attribute *btd_gatt_add_service(const bt_uuid_t *uuid);

/*
 * btd_gatt_add_char - Add a characteristic (declaration and value attributes)
 * to local attribute database.
 * @uuid:	Characteristic UUID (16-bits or 128-bits).
 * @properties:	Characteristic properties. See Core SPEC 4.1 page 2183.
 * @read_cb:	Callback used to provide the characteristic value.
 *
 * Returns a reference to characteristic value attribute. In case of error,
 * NULL is returned.
 */
struct btd_attribute *btd_gatt_add_char(const bt_uuid_t *uuid,
						uint8_t properties,
						btd_attr_read_t read_cb);

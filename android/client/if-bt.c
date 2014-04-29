/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "if-main.h"
#include "terminal.h"
#include "../hal-utils.h"

const bt_interface_t *if_bluetooth;

#define VERIFY_PROP_TYPE_ARG(n, typ) \
	do { \
		if (n < argc) \
			typ = str2btpropertytype(argv[n]); \
		else { \
			haltest_error("No property type specified\n"); \
			return;\
		} \
	} while (0)

static bt_scan_mode_t str2btscanmode(const char *str)
{
	bt_scan_mode_t v = str2bt_scan_mode_t(str);

	if ((int) v != -1)
		return v;

	haltest_warn("WARN: %s cannot convert %s\n", __func__, str);
	return (bt_scan_mode_t) atoi(str);
}

static bt_ssp_variant_t str2btsspvariant(const char *str)
{
	bt_ssp_variant_t v = str2bt_ssp_variant_t(str);

	if ((int) v != -1)
		return v;

	haltest_warn("WARN: %s cannot convert %s\n", __func__, str);
	return (bt_ssp_variant_t) atoi(str);
}

static bt_property_type_t str2btpropertytype(const char *str)
{
	bt_property_type_t v = str2bt_property_type_t(str);

	if ((int) v != -1)
		return v;

	haltest_warn("WARN: %s cannot convert %s\n", __func__, str);
	return (bt_property_type_t) atoi(str);
}

static void dump_properties(int num_properties, bt_property_t *properties)
{
	int i;

	for (i = 0; i < num_properties; i++) {
		/*
		 * properities sometimes come unaligned hence memcp to
		 * aligned buffer
		 */
		bt_property_t prop;
		memcpy(&prop, properties + i, sizeof(prop));

		haltest_info("prop: %s\n", btproperty2str(&prop));
	}
}

/* Cache for remote devices, stored in sorted array */
static bt_bdaddr_t *remote_devices = NULL;
static int remote_devices_cnt = 0;
static int remote_devices_capacity = 0;

/* Adds address to remote device set so it can be used in tab completion */
void add_remote_device(const bt_bdaddr_t *addr)
{
	int i;

	if (remote_devices == NULL) {
		remote_devices = malloc(4 * sizeof(bt_bdaddr_t));
		remote_devices_cnt = 0;
		if (remote_devices == NULL) {
			remote_devices_capacity = 0;
			return;
		}

		remote_devices_capacity = 4;
	}

	/* Array is sorted, search for right place */
	for (i = 0; i < remote_devices_cnt; ++i) {
		int res = memcmp(&remote_devices[i], addr, sizeof(*addr));

		if (res == 0)
			return; /* Already added */
		else if (res > 0)
			break;
	}

	/* Realloc space if needed */
	if (remote_devices_cnt >= remote_devices_capacity) {
		remote_devices_capacity *= 2;
		remote_devices = realloc(remote_devices, sizeof(bt_bdaddr_t) *
						remote_devices_capacity);
		if (remote_devices == NULL) {
			remote_devices_capacity = 0;
			remote_devices_cnt = 0;
			return;
		}
	}

	if (i < remote_devices_cnt)
		memmove(remote_devices + i + 1, remote_devices + i,
				(remote_devices_cnt - i) * sizeof(bt_bdaddr_t));
	remote_devices[i] = *addr;
	remote_devices_cnt++;
}

const char *enum_devices(void *v, int i)
{
	static char buf[MAX_ADDR_STR_LEN];

	if (i >= remote_devices_cnt)
		return NULL;

	bt_bdaddr_t2str(&remote_devices[i], buf);
	return buf;
}

static void add_remote_device_from_props(int num_properties,
						const bt_property_t *properties)
{
	int i;

	for (i = 0; i < num_properties; i++) {
		/*
		 * properities sometimes come unaligned hence memcp to
		 * aligned buffer
		 */
		bt_property_t property;

		memcpy(&property, properties + i, sizeof(property));
		if (property.type == BT_PROPERTY_BDADDR)
			add_remote_device((bt_bdaddr_t *) property.val);
	}
}

static void adapter_state_changed_cb(bt_state_t state)
{
	haltest_info("%s: state=%s\n", __func__, bt_state_t2str(state));
}

static void adapter_properties_cb(bt_status_t status, int num_properties,
						bt_property_t *properties)
{
	haltest_info("%s: status=%s num_properties=%d\n", __func__,
				bt_status_t2str(status), num_properties);

	dump_properties(num_properties, properties);
}

static void remote_device_properties_cb(bt_status_t status,
					bt_bdaddr_t *bd_addr,
					int num_properties,
					bt_property_t *properties)
{
	haltest_info("%s: status=%s bd_addr=%s num_properties=%d\n", __func__,
			bt_status_t2str(status), bdaddr2str(bd_addr),
			num_properties);

	add_remote_device(bd_addr);

	dump_properties(num_properties, properties);
}

static void device_found_cb(int num_properties, bt_property_t *properties)
{
	haltest_info("%s: num_properties=%d\n", __func__, num_properties);

	add_remote_device_from_props(num_properties, properties);

	dump_properties(num_properties, properties);
}

static void discovery_state_changed_cb(bt_discovery_state_t state)
{
	haltest_info("%s: state=%s\n", __func__,
					bt_discovery_state_t2str(state));
}

/*
 * Buffer for remote addres that came from one of bind request.
 * It's stored for command completion.
 */
static char last_remote_addr[MAX_ADDR_STR_LEN];
static bt_ssp_variant_t last_ssp_variant = (bt_ssp_variant_t) -1;

static bt_bdaddr_t pin_request_addr;
static void pin_request_answer(char *reply)
{
	bt_pin_code_t pin;
	int accept = 0;
	int pin_len = strlen(reply);

	if (pin_len > 0) {
		accept = 1;
		if (pin_len > 16)
			pin_len = 16;
		memcpy(&pin.pin, reply, pin_len);
	}

	EXEC(if_bluetooth->pin_reply, &pin_request_addr, accept, pin_len, &pin);
}

static void pin_request_cb(bt_bdaddr_t *remote_bd_addr, bt_bdname_t *bd_name,
								uint32_t cod)
{
	/* Store for command completion */
	bt_bdaddr_t2str(remote_bd_addr, last_remote_addr);
	pin_request_addr = *remote_bd_addr;

	haltest_info("%s: remote_bd_addr=%s bd_name=%s cod=%06x\n", __func__,
					last_remote_addr, bd_name->name, cod);
	terminal_prompt_for("Enter pin: ", pin_request_answer);
}

/* Variables to store information from ssp_request_cb used for ssp_reply */
static bt_bdaddr_t ssp_request_addr;
static bt_ssp_variant_t ssp_request_variant;
static uint32_t ssp_request_pask_key;

/* Called when user hit enter on prompt for confirmation */
static void ssp_request_yes_no_answer(char *reply)
{
	int accept = *reply == 0 || *reply == 'y' || *reply == 'Y';

	if_bluetooth->ssp_reply(&ssp_request_addr, ssp_request_variant, accept,
							ssp_request_pask_key);
}

static void ssp_request_cb(bt_bdaddr_t *remote_bd_addr, bt_bdname_t *bd_name,
				uint32_t cod, bt_ssp_variant_t pairing_variant,
				uint32_t pass_key)
{
	static char prompt[50];

	/* Store for command completion */
	bt_bdaddr_t2str(remote_bd_addr, last_remote_addr);
	last_ssp_variant = pairing_variant;

	haltest_info("%s: remote_bd_addr=%s bd_name=%s cod=%06x pairing_variant=%s pass_key=%d\n",
			__func__, last_remote_addr, bd_name->name, cod,
			bt_ssp_variant_t2str(pairing_variant), pass_key);

	if (pairing_variant == BT_SSP_VARIANT_PASSKEY_CONFIRMATION) {
		sprintf(prompt, "Does other device show %d [Y/n] ?", pass_key);

		ssp_request_addr = *remote_bd_addr;
		ssp_request_variant = pairing_variant;
		ssp_request_pask_key = pass_key;

		terminal_prompt_for(prompt, ssp_request_yes_no_answer);
	}
}

static void bond_state_changed_cb(bt_status_t status,
						bt_bdaddr_t *remote_bd_addr,
						bt_bond_state_t state)
{
	haltest_info("%s: status=%s remote_bd_addr=%s state=%s\n", __func__,
			bt_status_t2str(status), bdaddr2str(remote_bd_addr),
			bt_bond_state_t2str(state));
}

static void acl_state_changed_cb(bt_status_t status,
						bt_bdaddr_t *remote_bd_addr,
						bt_acl_state_t state)
{
	haltest_info("%s: status=%s remote_bd_addr=%s state=%s\n", __func__,
			bt_status_t2str(status), bdaddr2str(remote_bd_addr),
			bt_acl_state_t2str(state));
}

static void thread_evt_cb(bt_cb_thread_evt evt)
{
	haltest_info("%s: evt=%s\n", __func__, bt_cb_thread_evt2str(evt));
}

static void dut_mode_recv_cb(uint16_t opcode, uint8_t *buf, uint8_t len)
{
	haltest_info("%s\n", __func__);
}

static void le_test_mode_cb(bt_status_t status, uint16_t num_packets)
{
	haltest_info("%s %s %d\n", __func__, bt_status_t2str(status),
								num_packets);
}

static bt_callbacks_t bt_callbacks = {
	.size = sizeof(bt_callbacks),
	.adapter_state_changed_cb = adapter_state_changed_cb,
	.adapter_properties_cb = adapter_properties_cb,
	.remote_device_properties_cb = remote_device_properties_cb,
	.device_found_cb = device_found_cb,
	.discovery_state_changed_cb = discovery_state_changed_cb,
	.pin_request_cb = pin_request_cb,
	.ssp_request_cb = ssp_request_cb,
	.bond_state_changed_cb = bond_state_changed_cb,
	.acl_state_changed_cb = acl_state_changed_cb,
	.thread_evt_cb = thread_evt_cb,
	.dut_mode_recv_cb = dut_mode_recv_cb,
	.le_test_mode_cb = le_test_mode_cb
};

static void init_p(int argc, const char **argv)
{
	int err;
	const hw_module_t *module;
	hw_device_t *device;

	err = hw_get_module(BT_HARDWARE_MODULE_ID, &module);
	if (err) {
		haltest_error("he_get_module returned %d\n", err);
		return;
	}

	err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
	if (err) {
		haltest_error("module->methods->open returned %d\n", err);
		return;
	}

	if_bluetooth =
		    ((bluetooth_device_t *) device)->get_bluetooth_interface();
	if (!if_bluetooth) {
		haltest_error("get_bluetooth_interface returned NULL\n");
		return;
	}

	EXEC(if_bluetooth->init, &bt_callbacks);
}

static void cleanup_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_bluetooth);

	EXECV(if_bluetooth->cleanup);

	if_bluetooth = NULL;
}

static void enable_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_bluetooth);

	EXEC(if_bluetooth->enable);
}

static void disable_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_bluetooth);

	EXEC(if_bluetooth->disable);
}

static void get_adapter_properties_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_bluetooth);

	EXEC(if_bluetooth->get_adapter_properties);
}

static void get_adapter_property_c(int argc, const char **argv,
					enum_func *enum_func, void **user)
{
	if (argc == 3) {
		*user = TYPE_ENUM(bt_property_type_t);
		*enum_func = enum_defines;
	}
}

static void get_adapter_property_p(int argc, const char **argv)
{
	int type;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_PROP_TYPE_ARG(2, type);

	EXEC(if_bluetooth->get_adapter_property, type);
}

static const char * const names[] = {
	"BT_PROPERTY_BDNAME",
	"BT_PROPERTY_ADAPTER_SCAN_MODE",
	"BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT",
	NULL
};

static void set_adapter_property_c(int argc, const char **argv,
					enum_func *enum_func, void **user)
{
	if (argc == 3) {
		*user = (void *) names;
		*enum_func = enum_strings;
	} else if (argc == 4) {
		if (0 == strcmp(argv[2], "BT_PROPERTY_ADAPTER_SCAN_MODE")) {
			*user = TYPE_ENUM(bt_scan_mode_t);
			*enum_func = enum_defines;
		}
	}
}

static void set_adapter_property_p(int argc, const char **argv)
{
	bt_property_t property;
	bt_scan_mode_t mode;
	int timeout;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_PROP_TYPE_ARG(2, property.type);

	if (argc <= 3) {
		haltest_error("No property value specified\n");
		return;
	}
	switch (property.type) {
	case BT_PROPERTY_BDNAME:
		property.len = strlen(argv[3]) + 1;
		property.val = (char *) argv[3];
		break;

	case BT_PROPERTY_ADAPTER_SCAN_MODE:
		mode = str2btscanmode(argv[3]);
		property.len = sizeof(bt_scan_mode_t);
		property.val = &mode;
		break;

	case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
		timeout = atoi(argv[3]);
		property.val = &timeout;
		property.len = sizeof(timeout);
		break;

	default:
		haltest_error("Invalid property %s\n", argv[3]);
		return;
	}

	EXEC(if_bluetooth->set_adapter_property, &property);
}

/* This function is to be used for completion methods that need only address */
static void complete_addr_c(int argc, const char **argv, enum_func *enum_func,
								void **user)
{
	if (argc == 3) {
		*user = NULL;
		*enum_func = enum_devices;
	}
}

/* Just addres to complete, use complete_addr_c */
#define get_remote_device_properties_c complete_addr_c

static void get_remote_device_properties_p(int argc, const char **argv)
{
	bt_bdaddr_t addr;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);

	EXEC(if_bluetooth->get_remote_device_properties, &addr);
}

static void get_remote_device_property_c(int argc, const char **argv,
							enum_func *enum_func,
							void **user)
{
	if (argc == 3) {
		*user = NULL;
		*enum_func = enum_devices;
	} else if (argc == 4) {
		*user = TYPE_ENUM(bt_property_type_t);
		*enum_func = enum_defines;
	}
}

static void get_remote_device_property_p(int argc, const char **argv)
{
	bt_property_type_t type;
	bt_bdaddr_t addr;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);
	VERIFY_PROP_TYPE_ARG(3, type);

	EXEC(if_bluetooth->get_remote_device_property, &addr, type);
}

/*
 * Same completion as for get_remote_device_property_c can be used for
 * set_remote_device_property_c. No need to create separate function.
 */
#define set_remote_device_property_c get_remote_device_property_c

static void set_remote_device_property_p(int argc, const char **argv)
{
	bt_property_t property;
	bt_bdaddr_t addr;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);
	VERIFY_PROP_TYPE_ARG(3, property.type);

	switch (property.type) {
	case BT_PROPERTY_REMOTE_FRIENDLY_NAME:
		property.len = strlen(argv[4]);
		property.val = (char *) argv[4];
		break;
	default:
		return;
	}

	EXEC(if_bluetooth->set_remote_device_property, &addr, &property);
}

/* For now uuid is not autocompleted. Use routine for complete_addr_c */
#define get_remote_service_record_c complete_addr_c

static void get_remote_service_record_p(int argc, const char **argv)
{
	bt_bdaddr_t addr;
	bt_uuid_t uuid;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);

	if (argc <= 3) {
		haltest_error("No uuid specified\n");
		return;
	}

	str2bt_uuid_t(argv[3], &uuid);

	EXEC(if_bluetooth->get_remote_service_record, &addr, &uuid);
}

/* Just addres to complete, use complete_addr_c */
#define get_remote_services_c complete_addr_c

static void get_remote_services_p(int argc, const char **argv)
{
	bt_bdaddr_t addr;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);

	EXEC(if_bluetooth->get_remote_services, &addr);
}

static void start_discovery_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_bluetooth);

	EXEC(if_bluetooth->start_discovery);
}

static void cancel_discovery_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_bluetooth);

	EXEC(if_bluetooth->cancel_discovery);
}

/* Just addres to complete, use complete_addr_c */
#define create_bond_c complete_addr_c

static void create_bond_p(int argc, const char **argv)
{
	bt_bdaddr_t addr;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);

	EXEC(if_bluetooth->create_bond, &addr);
}

/* Just addres to complete, use complete_addr_c */
#define remove_bond_c complete_addr_c

static void remove_bond_p(int argc, const char **argv)
{
	bt_bdaddr_t addr;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);

	EXEC(if_bluetooth->remove_bond, &addr);
}

/* Just addres to complete, use complete_addr_c */
#define cancel_bond_c complete_addr_c

static void cancel_bond_p(int argc, const char **argv)
{
	bt_bdaddr_t addr;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);

	EXEC(if_bluetooth->cancel_bond, &addr);
}

static void pin_reply_c(int argc, const char **argv, enum_func *enum_func,
								void **user)
{
	static const char *const completions[] = { last_remote_addr, NULL };

	if (argc == 3) {
		*user = (void *) completions;
		*enum_func = enum_strings;
	}
}

static void pin_reply_p(int argc, const char **argv)
{
	bt_bdaddr_t addr;
	bt_pin_code_t pin;
	int pin_len = 0;
	int accept = 0;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);

	if (argc > 3) {
		accept = 1;
		pin_len = strlen(argv[3]);
		memcpy(pin.pin, argv[3], pin_len);
	}

	EXEC(if_bluetooth->pin_reply, &addr, accept, pin_len, &pin);
}

static void ssp_reply_c(int argc, const char **argv, enum_func *enum_func,
								void **user)
{
	if (argc == 3) {
		*user = last_remote_addr;
		*enum_func = enum_one_string;
	} else if (argc == 5) {
		*user = "1";
		*enum_func = enum_one_string;
	} else if (argc == 4) {
		if (-1 != (int) last_ssp_variant) {
			*user = (void *) bt_ssp_variant_t2str(last_ssp_variant);
			*enum_func = enum_one_string;
		} else {
			*user = TYPE_ENUM(bt_ssp_variant_t);
			*enum_func = enum_defines;
		}
	}
}

static void ssp_reply_p(int argc, const char **argv)
{
	bt_bdaddr_t addr;
	bt_ssp_variant_t var;
	int accept;
	int passkey;

	RETURN_IF_NULL(if_bluetooth);
	VERIFY_ADDR_ARG(2, &addr);

	if (argc < 4) {
		haltest_error("No ssp variant specified\n");
		return;
	}

	var = str2btsspvariant(argv[3]);
	if (argc < 5) {
		haltest_error("No accept value specified\n");
		return;
	}

	accept = atoi(argv[4]);
	passkey = 0;

	if (accept && var == BT_SSP_VARIANT_PASSKEY_ENTRY && argc >= 5)
		passkey = atoi(argv[4]);

	EXEC(if_bluetooth->ssp_reply, &addr, var, accept, passkey);
}

static void get_profile_interface_c(int argc, const char **argv,
					enum_func *enum_func, void **user)
{
	static const char *const profile_ids[] = {
		BT_PROFILE_HANDSFREE_ID,
		BT_PROFILE_ADVANCED_AUDIO_ID,
		BT_PROFILE_HEALTH_ID,
		BT_PROFILE_SOCKETS_ID,
		BT_PROFILE_HIDHOST_ID,
		BT_PROFILE_PAN_ID,
		BT_PROFILE_GATT_ID,
		BT_PROFILE_AV_RC_ID,
		NULL
	};

	if (argc == 3) {
		*user = (void *) profile_ids;
		*enum_func = enum_strings;
	}
}

static void get_profile_interface_p(int argc, const char **argv)
{
	const char *id;
	const void **pif = NULL;

	RETURN_IF_NULL(if_bluetooth);
	if (argc <= 2) {
		haltest_error("No interface specified\n");
		return;
	}

	id = argv[2];

	if (strcmp(BT_PROFILE_HANDSFREE_ID, id) == 0)
		pif = (const void **) &if_hf;
	else if (strcmp(BT_PROFILE_ADVANCED_AUDIO_ID, id) == 0)
		pif = (const void **) &if_av;
	else if (strcmp(BT_PROFILE_HEALTH_ID, id) == 0)
		pif = (const void **) &if_hl;
	else if (strcmp(BT_PROFILE_SOCKETS_ID, id) == 0)
		pif = (const void **) &if_sock;
	else if (strcmp(BT_PROFILE_HIDHOST_ID, id) == 0)
		pif = (const void **) &if_hh;
	else if (strcmp(BT_PROFILE_PAN_ID, id) == 0)
		pif = (const void **) &if_pan;
	else if (strcmp(BT_PROFILE_AV_RC_ID, id) == 0)
		pif = (const void **) &if_rc;
	else if (strcmp(BT_PROFILE_GATT_ID, id) == 0)
		pif = (const void **) &if_gatt;
	else
		haltest_error("%s is not correct for get_profile_interface\n",
									id);

	if (pif != NULL) {
		*pif = if_bluetooth->get_profile_interface(id);
		haltest_info("get_profile_interface(%s) : %p\n", id, *pif);
	}
}

static void dut_mode_configure_p(int argc, const char **argv)
{
	uint8_t mode;

	RETURN_IF_NULL(if_bluetooth);

	if (argc <= 2) {
		haltest_error("No dut mode specified\n");
		return;
	}

	mode = strtol(argv[2], NULL, 0);

	EXEC(if_bluetooth->dut_mode_configure, mode);
}

static void dut_mode_send_p(int argc, const char **argv)
{
	haltest_error("not implemented\n");
}

static void le_test_mode_p(int argc, const char **argv)
{
	haltest_error("not implemented\n");
}

static void config_hci_snoop_log_p(int argc, const char **argv)
{
	uint8_t mode;

	RETURN_IF_NULL(if_bluetooth);

	if (argc <= 2) {
		haltest_error("No mode specified\n");
		return;
	}

	mode = strtol(argv[2], NULL, 0);

	EXEC(if_bluetooth->config_hci_snoop_log, mode);
}

static struct method methods[] = {
	STD_METHOD(init),
	STD_METHOD(cleanup),
	STD_METHOD(enable),
	STD_METHOD(disable),
	STD_METHOD(get_adapter_properties),
	STD_METHODCH(get_adapter_property, "<prop_type>"),
	STD_METHODCH(set_adapter_property, "<prop_type> <prop_value>"),
	STD_METHODCH(get_remote_device_properties, "<addr>"),
	STD_METHODCH(get_remote_device_property, "<addr> <property_type>"),
	STD_METHODCH(set_remote_device_property,
					"<addr> <property_type> <value>"),
	STD_METHODCH(get_remote_service_record, "<addr> <uuid>"),
	STD_METHODCH(get_remote_services, "<addr>"),
	STD_METHOD(start_discovery),
	STD_METHOD(cancel_discovery),
	STD_METHODCH(create_bond, "<addr>"),
	STD_METHODCH(remove_bond, "<addr>"),
	STD_METHODCH(cancel_bond, "<addr>"),
	STD_METHODCH(pin_reply, "<address> [<pin>]"),
	STD_METHODCH(ssp_reply, "<address> <ssp_veriant> 1|0 [<passkey>]"),
	STD_METHODCH(get_profile_interface, "<profile id>"),
	STD_METHODH(dut_mode_configure, "<dut mode>"),
	STD_METHOD(dut_mode_send),
	STD_METHOD(le_test_mode),
	STD_METHODH(config_hci_snoop_log, "<mode>"),
	END_METHOD
};

const struct interface bluetooth_if = {
	.name = "bluetooth",
	.methods = methods
};

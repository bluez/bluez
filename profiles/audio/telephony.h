/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright © 2025 Collabora Ltd.
 *
 *
 */

enum connection_state {
	CONNECTING = 0,
	SESSION_CONNECTING,
	CONNECTED,
	DISCONNECTING
};

enum call_state {
	CALL_STATE_ACTIVE = 0,
	CALL_STATE_HELD,
	CALL_STATE_DIALING,
	CALL_STATE_ALERTING,
	CALL_STATE_INCOMING,
	CALL_STATE_WAITING,
	CALL_STATE_RESPONSE_AND_HOLD,
	CALL_STATE_DISCONNECTED,
};

struct telephony;

struct telephony_callbacks {
	DBusMessage *(*dial)(DBusConnection *conn, DBusMessage *msg,
					void *profile_data);
	DBusMessage *(*swap_calls)(DBusConnection *conn, DBusMessage *msg,
					void *profile_data);
	DBusMessage *(*release_and_answer)(DBusConnection *conn,
					DBusMessage *msg,
					void *profile_data);
	DBusMessage *(*release_and_swap)(DBusConnection *conn,
					DBusMessage *msg,
					void *profile_data);
	DBusMessage *(*hold_and_answer)(DBusConnection *conn,
					DBusMessage *msg,
					void *profile_data);
	DBusMessage *(*hangup_all)(DBusConnection *conn, DBusMessage *msg,
					void *profile_data);
	DBusMessage *(*create_multiparty)(DBusConnection *conn,
					DBusMessage *msg,
					void *profile_data);
	DBusMessage *(*send_tones)(DBusConnection *conn, DBusMessage *msg,
					void *profile_data);

	DBusMessage *(*call_answer)(DBusConnection *conn, DBusMessage *msg,
					void *call_data);
	DBusMessage *(*call_hangup)(DBusConnection *conn, DBusMessage *msg,
					void *call_data);
};

struct call {
	struct telephony	*device;
	char			*path;
	uint8_t			idx;

	char			*line_id;
	char			*incoming_line;
	char			*name;
	bool			multiparty;
	enum call_state		state;

	DBusMessage		*pending_msg;
};

struct telephony *telephony_new(struct btd_service *service,
				void *profile_data,
				struct telephony_callbacks *cbs);
void telephony_free(struct telephony *telephony);
int telephony_register_interface(struct telephony *telephony);
void telephony_unregister_interface(struct telephony *telephony);

struct btd_service *telephony_get_service(struct telephony *telephony);
struct btd_device *telephony_get_device(struct telephony *telephony);
const char *telephony_get_path(struct telephony *telephony);
bdaddr_t telephony_get_src(struct telephony *telephony);
bdaddr_t telephony_get_dst(struct telephony *telephony);
void *telephony_get_profile_data(struct telephony *telephony);
void telephony_add_uri_scheme(struct telephony *telephony, const char *scheme);
void telephony_remove_uri_scheme(struct telephony *telephony,
				const char *scheme);
void telephony_set_state(struct telephony *telephony,
				enum connection_state state);
enum connection_state telephony_get_state(struct telephony *telephony);
void telephony_set_network_service(struct telephony *telephony, bool service);
bool telephony_get_network_service(struct telephony *telephony);
void telephony_set_signal(struct telephony *telephony, uint8_t signal);
uint8_t telephony_get_signal(struct telephony *telephony);
void telephony_set_roaming(struct telephony *telephony, bool roaming);
bool telephony_get_roaming(struct telephony *telephony);
void telephony_set_battchg(struct telephony *telephony, uint8_t battchg);
uint8_t telephony_get_battchg(struct telephony *telephony);
void telephony_set_operator_name(struct telephony *telephony,
				const char *name);
const char *telephony_get_operator_name(struct telephony *telephony);
void telephony_set_inband_ringtone(struct telephony *telephony, bool enabled);
bool telephony_get_inband_ringtone(struct telephony *telephony);

struct call *telephony_new_call(struct telephony *telephony,
	uint8_t idx,
	enum call_state state,
	void *user_data);
void telephony_free_call(struct call *call);
int telephony_call_register_interface(struct call *call);
void telephony_call_unregister_interface(struct call *call);

void telephony_call_set_state(struct call *call, enum call_state state);
void telephony_call_set_line_id(struct call *call, const char *line_id);

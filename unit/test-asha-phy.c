// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <stdarg.h>
#include <sys/socket.h>

int test_setsockopt(int fd, int level, int option, const void *value,
							socklen_t length);

/* Source-level mocks remain effective with link-time optimization. */
#define setsockopt test_setsockopt
#define bt_io_get test_io_get
#define bt_asha_start test_start
#include "profiles/audio/asha.c"
#undef setsockopt
#undef bt_io_get
#undef bt_asha_start
#include "src/shared/tester.h"

static unsigned int preferences, starts;
static bool mtu_ok;
static int preference_error, expected_fd;

/* Sanitizers retain the plugin's globals, including unused daemon callbacks. */
int btd_profile_register(struct btd_profile *profile)
{
	assert(false);
}

void btd_profile_unregister(struct btd_profile *profile)
{
	assert(false);
}

const char *device_get_path(const struct btd_device *device)
{
	assert(false);
}

const bdaddr_t *device_get_address(struct btd_device *device)
{
	assert(false);
}

struct btd_adapter *device_get_adapter(struct btd_device *device)
{
	assert(false);
}

const bdaddr_t *btd_adapter_get_address(struct btd_adapter *adapter)
{
	assert(false);
}

void btd_device_set_conn_param(struct btd_device *device,
				uint16_t min_interval, uint16_t max_interval,
					uint16_t latency, uint16_t timeout)
{
	assert(false);
}

struct gatt_db *btd_device_get_gatt_db(struct btd_device *device)
{
	assert(false);
}

struct bt_gatt_client *btd_device_get_gatt_client(struct btd_device *device)
{
	assert(false);
}

struct btd_device *btd_service_get_device(const struct btd_service *service)
{
	assert(false);
}

void *btd_service_get_user_data(const struct btd_service *service)
{
	assert(false);
}

void btd_service_set_user_data(struct btd_service *service, void *user_data)
{
	assert(false);
}

void btd_service_connecting_complete(struct btd_service *service, int err)
{
	assert(false);
}

void btd_service_disconnecting_complete(struct btd_service *service, int err)
{
	assert(false);
}

DBusConnection *btd_get_dbus_connection(void)
{
	assert(false);
}

gboolean g_dbus_register_interface(DBusConnection *connection,
				const char *path, const char *name,
				const GDBusMethodTable *methods,
				const GDBusSignalTable *signals,
				const GDBusPropertyTable *properties,
				void *user_data, GDBusDestroyFunction destroy)
{
	assert(false);
}

gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name)
{
	assert(false);
}

const struct media_endpoint *media_endpoint_get_asha(void)
{
	assert(false);
}

struct media_transport *media_transport_create(struct btd_device *device,
				const char *remote_endpoint,
				uint8_t *configuration, size_t size,
				void *data, void *stream)
{
	assert(false);
}

void media_transport_destroy(struct media_transport *transport)
{
	assert(false);
}

const char *media_transport_get_path(struct media_transport *transport)
{
	assert(false);
}

GIOChannel *bt_io_connect(BtIOConnect connect, gpointer user_data,
				GDestroyNotify destroy, GError **gerr,
							BtIOOption opt1, ...)
{
	assert(false);
}

void btd_error(uint16_t index, const char *format, ...)
{
}

void btd_debug(uint16_t index, const char *format, ...)
{
}

int test_setsockopt(int fd, int level, int option, const void *value,
							socklen_t length)
{
	const uint32_t *phys = value;

	assert(fd == expected_fd && level == SOL_BLUETOOTH && option == BT_PHY);
	assert(length == sizeof(*phys));
	assert(*phys == (BT_PHY_LE_1M_TX | BT_PHY_LE_1M_RX |
					BT_PHY_LE_2M_TX | BT_PHY_LE_2M_RX));
	assert(starts == 0);
	preferences++;
	errno = preference_error;
	return preference_error ? -1 : 0;
}

gboolean test_io_get(GIOChannel *io, GError **error, BtIOOption first, ...)
{
	va_list args;
	uint16_t *imtu, *omtu;

	if (!mtu_ok) {
		*error = g_error_new(G_IO_CHANNEL_ERROR,
				G_IO_CHANNEL_ERROR_FAILED, "MTU failure");
		return FALSE;
	}

	assert(first == BT_IO_OPT_IMTU);
	va_start(args, first);
	imtu = va_arg(args, uint16_t *);
	assert(va_arg(args, int) == BT_IO_OPT_OMTU);
	omtu = va_arg(args, uint16_t *);
	assert(va_arg(args, int) == BT_IO_OPT_INVALID);
	va_end(args);
	*imtu = 512;
	*omtu = 163;
	return TRUE;
}

unsigned int test_start(struct bt_asha *asha, bt_asha_cb_t callback, void *data)
{
	assert(preferences == 1);
	starts++;
	return 0;
}

static void test_phy(const void *user_data)
{
	const int errors[] = { 0, ENOPROTOOPT, EINVAL };
	unsigned int i;
	int fds[2];
	GIOChannel *io;
	GError *error;
	struct bt_asha asha = { 0 };
	struct bt_asha_device device = { .asha = &asha };
	struct connect_data data = { .asha_dev = &device };

	assert(!pipe(fds));
	io = g_io_channel_unix_new(fds[0]);
	expected_fd = fds[0];

	for (i = 0; i < ARRAY_SIZE(errors); i++) {
		preferences = starts = 0;
		preference_error = errors[i];
		mtu_ok = i != 2;
		connect_cb(io, NULL, &data);
		assert(preferences == 1 && starts == 1 && device.io == io);
		assert(device.imtu == 512 && device.omtu == 163);
	}

	preferences = starts = 0;
	error = g_error_new(G_IO_CHANNEL_ERROR, G_IO_CHANNEL_ERROR_FAILED,
							"mock connection failure");
	connect_cb(io, error, &data);
	assert(preferences == 0 && starts == 0);
	g_error_free(error);
	g_io_channel_unref(io);
	close(fds[0]);
	close(fds[1]);
	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	tester_add("ASHA/PHY/preference", NULL, NULL, test_phy, NULL);
	return tester_run();
}

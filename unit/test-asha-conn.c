// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>

/* Internal calls can be resolved before GNU ld --wrap when LTO is enabled. */
#define bt_gatt_client_get_att test_get_att
#define bt_att_get_fd test_att_fd
#define bt_asha_set_connection_interval test_set_interval
#define bt_asha_start test_start
#define bt_io_get test_io_get
#include "profiles/audio/asha.c"
#undef bt_gatt_client_get_att
#undef bt_att_get_fd
#undef bt_asha_set_connection_interval
#undef bt_asha_start
#undef bt_io_get
#include "bluetooth/hci.h"
#include "src/shared/tester.h"

static int peer_fd[2];
static int observer_fd[2];
static int pending_peer;
static unsigned int writes;
static uint16_t last_interval;
static struct bt_asha *last_asha;
static bool socket_ready = true;
static bool fail_socket;
static int att_fd = 100;
static unsigned int handle_reads;
static socklen_t conninfo_length = sizeof(struct l2cap_conninfo);

int __wrap_socket(int domain, int type, int protocol)
{
	int fds[2];

	assert(domain == PF_BLUETOOTH);
	assert(protocol == BTPROTO_HCI);

	if (fail_socket)
		return -1;

	assert(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, fds));
	pending_peer = fds[1];
	return fds[0];
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t length)
{
	const struct sockaddr_hci *hci = (void *) addr;

	/* Ignore tester's optional logging channel. */
	if (hci->hci_dev == HCI_DEV_NONE) {
		close(pending_peer);
		return -1;
	}

	assert(hci->hci_dev < 2);
	peer_fd[hci->hci_dev] = pending_peer;
	observer_fd[hci->hci_dev] = fd;
	return 0;
}

int __real_setsockopt(int fd, int level, int opt, const void *value,
							socklen_t length);

int __wrap_setsockopt(int fd, int level, int opt, const void *value,
							socklen_t length)
{
	if (level == SOL_HCI)
		return 0;

	return __real_setsockopt(fd, level, opt, value, length);
}

int __wrap_getsockopt(int fd, int level, int opt, void *value,
							socklen_t *length)
{
	struct l2cap_conninfo *info = value;

	assert(level == SOL_L2CAP && opt == L2CAP_CONNINFO);
	handle_reads++;

	if (!socket_ready)
		return -1;

	assert(*length == sizeof(*info));
	info->hci_handle = 16;
	*length = conninfo_length;
	return 0;
}

struct bt_att *test_get_att(struct bt_gatt_client *client)
{
	return (void *) client;
}

int test_att_fd(struct bt_att *att)
{
	return att_fd;
}

struct btd_adapter *device_get_adapter(struct btd_device *device)
{
	return (void *) device;
}

uint16_t btd_adapter_get_index(struct btd_adapter *adapter)
{
	return PTR_TO_UINT(adapter) - 1;
}

void btd_debug(uint16_t index, const char *format, ...)
{
}

void btd_error(uint16_t index, const char *format, ...)
{
}

bool test_set_interval(struct bt_asha *asha,
							uint16_t interval)
{
	writes++;
	last_asha = asha;
	last_interval = interval;
	return true;
}

unsigned int test_start(struct bt_asha *asha, bt_asha_cb_t cb,
							void *user_data)
{
	assert(writes == 1 && last_asha == asha && last_interval == 24);
	asha->state = ASHA_STARTING;
	return 0;
}

gboolean test_io_get(GIOChannel *io, GError **err, BtIOOption opt1, ...)
{
	return TRUE;
}

static void event(unsigned int adapter, uint8_t subevent, const void *value,
							uint8_t length)
{
	uint8_t packet[260] = { BT_H4_EVT_PKT, BT_HCI_EVT_LE_META_EVENT,
						length + 1, subevent };

	memcpy(packet + 4, value, length);
	assert(write(peer_fd[adapter], packet, length + 4) == length + 4);

	while (g_main_context_iteration(NULL, FALSE))
		;
}

static void test_connection(const void *user_data)
{
	struct bt_asha asha = { .client = (void *) 1, .acp_handle = 0x79 };
	struct bt_asha other = { .client = (void *) 2, .acp_handle = 0x79 };
	struct bt_asha_device dev = { .asha = &asha, .device = (void *) 1 };
	struct bt_asha_device dev2 = { .asha = &other, .device = (void *) 2 };
	struct connect_data conn = { .asha_dev = &dev };
	GIOChannel *io;
	int io_fds[2];
	struct asha_adapter *adapter;
	unsigned int before;
	struct bt_hci_evt_le_conn_complete complete = {
		.handle = cpu_to_le16(16), .interval = cpu_to_le16(24),
	};
	struct bt_hci_evt_le_enhanced_conn_complete enhanced = {
		.handle = cpu_to_le16(16), .interval = cpu_to_le16(32),
	};
	struct bt_hci_evt_le_conn_update_complete update = {
		.handle = cpu_to_le16(16), .interval = cpu_to_le16(40),
	};
	struct bt_hci_evt_disconnect_complete disconnect = {
		.handle = cpu_to_le16(16),
	};
	uint8_t packet[7] = { BT_H4_EVT_PKT, BT_HCI_EVT_DISCONNECT_COMPLETE,
							sizeof(disconnect) };

	assert(!pipe(io_fds));
	io = g_io_channel_unix_new(io_fds[0]);
	assert(!asha_adapter_probe(NULL, (void *) 1));
	assert(!asha_adapter_probe(NULL, (void *) 2));
	asha_streams = queue_new();
	queue_push_tail(asha_streams, &dev);
	queue_push_tail(asha_streams, &dev2);
	writes = 0;
	asha_send_interval(&dev);
	assert(writes == 0);

	/* Cache the initial event before GATT discovery/CoC. */
	event(0, BT_HCI_EVT_LE_CONN_COMPLETE, &complete, sizeof(complete));
	assert(writes == 0);
	connect_cb(io, NULL, &conn);
	assert(writes == 1 && last_interval == 24);

	/* Identical handles on different controllers are separate links. */
	event(1, BT_HCI_EVT_LE_ENHANCED_CONN_COMPLETE, &enhanced,
							sizeof(enhanced));
	before = handle_reads;
	event(0, BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE, &update, sizeof(update));
	assert(handle_reads == before + 1);
	assert(writes == 2 && last_asha == &asha && last_interval == 40);
	other.state = ASHA_STOPPED;
	event(1, BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE, &update, sizeof(update));
	assert(writes == 3 && last_asha == &other);

	/* Failed/malformed updates leave the last successful value intact. */
	update.status = 1;
	event(0, BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE, &update, sizeof(update));
	update.status = 0;
	event(0, BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE, &update,
							sizeof(update) - 1);
	update.handle = cpu_to_le16(ASHA_NUM_HANDLES);
	event(0, BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE, &update, sizeof(update));
	assert(writes == 3);
	asha_send_interval(&dev);
	assert(writes == 4 && last_interval == 40);

	/* Closed ATT sockets cannot be associated with a cached handle. */
	socket_ready = false;
	asha_send_interval(&dev);
	assert(writes == 4);
	socket_ready = true;

	memcpy(packet + 3, &disconnect, sizeof(disconnect));
	assert(write(peer_fd[0], packet, sizeof(packet)) == sizeof(packet));

	while (g_main_context_iteration(NULL, FALSE))
		;

	asha_send_interval(&dev);
	assert(writes == 4);
	asha_send_interval(&dev2);
	assert(writes == 5 && last_interval == 40);

	/* Reused handle gets the new connection's value, never the old one. */
	complete.interval = cpu_to_le16(16);
	event(0, BT_HCI_EVT_LE_CONN_COMPLETE, &complete, sizeof(complete));
	asha_send_interval(&dev);
	assert(writes == 6 && last_interval == 16);

	adapter = queue_find(asha_adapters, match_adapter, (void *) 1);
	assert(adapter->intervals[16] == 16);
	queue_remove(asha_streams, &dev);
	update.handle = cpu_to_le16(16);
	event(0, BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE, &update, sizeof(update));
	assert(writes == 6);
	asha_adapter_remove(NULL, (void *) 1);
	asha_adapter_remove(NULL, (void *) 2);
	assert(!asha_adapters);
	queue_destroy(asha_streams, NULL);
	asha_streams = NULL;
	close(peer_fd[0]);
	close(peer_fd[1]);
	g_io_channel_unref(io);
	close(io_fds[0]);
	close(io_fds[1]);
	dev.io = NULL;

	fail_socket = true;
	assert(asha_adapter_probe(NULL, (void *) 1) == -EIO);
	assert(!asha_adapters);
	fail_socket = false;
	tester_test_passed();
}

static void test_observer_lifecycle(const void *user_data)
{
	struct bt_asha asha = { .client = (void *) 1, .acp_handle = 0x79 };
	struct bt_asha_device dev = { .asha = &asha, .device = (void *) 1 };
	struct bt_hci_evt_le_conn_complete complete = {
		.handle = cpu_to_le16(16), .interval = cpu_to_le16(24),
	};
	struct bt_hci_evt_le_conn_update_complete update = {
		.handle = cpu_to_le16(16), .interval = cpu_to_le16(32),
	};
	uint8_t pending[] = { BT_H4_EVT_PKT, BT_HCI_EVT_LE_META_EVENT,
				sizeof(update) + 1,
				BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE };
	uint8_t packet[sizeof(pending) + sizeof(update)];
	uint8_t byte;

	writes = 0;
	assert(!asha_adapter_probe(NULL, (void *) 1));
	asha_streams = queue_new();
	queue_push_tail(asha_streams, &dev);
	event(0, BT_HCI_EVT_LE_CONN_COMPLETE, &complete, sizeof(complete));
	asha_send_interval(&dev);
	assert(writes == 1 && last_interval == 24);

	/* Failed/truncated events cannot replace a successful interval. */
	complete.status = 1;
	complete.interval = cpu_to_le16(40);
	event(0, BT_HCI_EVT_LE_CONN_COMPLETE, &complete, sizeof(complete));
	complete.status = 0;
	event(0, BT_HCI_EVT_LE_CONN_COMPLETE, &complete, sizeof(complete) - 1);
	asha_send_interval(&dev);
	assert(writes == 2 && last_interval == 24);

	conninfo_length--;
	asha_send_interval(&dev);
	conninfo_length += 2;
	asha_send_interval(&dev);
	conninfo_length--;
	att_fd = -1;
	asha_send_interval(&dev);
	att_fd = 100;
	assert(writes == 2);

	/* The passive observer must never transmit controller commands. */
	assert(read(peer_fd[0], &byte, 1) == -1);
	assert(errno == EAGAIN);
	asha_adapter_remove(NULL, (void *) 1);
	assert(fcntl(observer_fd[0], F_GETFD) == -1 && errno == EBADF);
	close(peer_fd[0]);
	assert(!asha_adapter_probe(NULL, (void *) 1));

	/* After restart, existing links stay unknown until a new update. */
	asha_send_interval(&dev);
	assert(writes == 2);
	event(0, BT_HCI_EVT_LE_CONN_UPDATE_COMPLETE, &update, sizeof(update));
	assert(writes == 3 && last_interval == 32);

	/* Drop queued callbacks when their adapter and device are removed. */
	memcpy(packet, pending, sizeof(pending));
	memcpy(packet + sizeof(pending), &update, sizeof(update));
	assert(write(peer_fd[0], packet, sizeof(packet)) == sizeof(packet));
	queue_remove(asha_streams, &dev);
	asha_adapter_remove(NULL, (void *) 1);

	while (g_main_context_iteration(NULL, FALSE))
		;

	assert(writes == 3 && !asha_adapters);
	assert(fcntl(observer_fd[0], F_GETFD) == -1 && errno == EBADF);
	close(peer_fd[0]);
	queue_destroy(asha_streams, NULL);
	asha_streams = NULL;
	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	tester_add("ASHA/interval/HCI", NULL, NULL, test_connection, NULL);
	tester_add("ASHA/interval/observer-lifecycle", NULL, NULL,
						test_observer_lifecycle, NULL);
	return tester_run();
}

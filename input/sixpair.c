/* To compile
 * gcc -g -Wall -I../src -I../lib/ -I../include -DSTORAGEDIR=\"/var/lib/bluetooth\" -o sixpair sixpair.c ../src/storage.c ../common/libhelper.a -I../common `pkg-config --libs --cflags glib-2.0 libusb-1.0` -lbluetooth
 */

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>

#include <sdp.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp_lib.h>
#include <glib.h>
#include <libusb.h>

#include "storage.h"

/* Vendor and product ID for the Sixaxis PS3 controller */
#define VENDOR 0x054c
#define PRODUCT 0x0268

#define PS3_PNP_RECORD "3601920900000A000100000900013503191124090004350D35061901000900113503190011090006350909656E09006A0901000900093508350619112409010009000D350F350D350619010009001335031900110901002513576972656C65737320436F6E74726F6C6C65720901012513576972656C65737320436F6E74726F6C6C6572090102251B536F6E7920436F6D707574657220456E7465727461696E6D656E740902000901000902010901000902020800090203082109020428010902052801090206359A35980822259405010904A101A102850175089501150026FF00810375019513150025013500450105091901291381027501950D0600FF8103150026FF0005010901A10075089504350046FF0009300931093209358102C0050175089527090181027508953009019102750895300901B102C0A1028502750895300901B102C0A10285EE750895300901B102C0A10285EF750895300901B102C0C0090207350835060904090901000902082800090209280109020A280109020B09010009020C093E8009020D280009020E2800"

gboolean option_get_master = TRUE;
char *option_master= NULL;
gboolean option_store_info = TRUE;
const char *option_device = NULL;
gboolean option_quiet = FALSE;

const GOptionEntry options[] = {
	{ "get-master", '\0', 0, G_OPTION_ARG_NONE, &option_get_master, "Get currently set master address", NULL },
	{ "set-master", '\0', 0, G_OPTION_ARG_STRING, &option_master, "Set master address (\"auto\" for automatic)", NULL },
	{ "store-info", '\0', 0, G_OPTION_ARG_NONE, &option_store_info, "Store the HID info into the input database", NULL },
	{ "device", '\0', 0, G_OPTION_ARG_STRING, &option_device, "Only handle one device (default, all supported", NULL },
	{ "quiet", 'q', 0, G_OPTION_ARG_NONE, &option_quiet, "Quieten the output", NULL },
	{ NULL }
};

static gboolean
show_master (libusb_device_handle *devh, int itfnum)
{
	unsigned char msg[8];
	int res;

	res = libusb_control_transfer (devh,
				       LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE,
				       0x01, 0x03f5, itfnum,
				       (void*) msg, sizeof(msg),
				       5000);

	if (res < 0) {
		g_warning ("Getting the master Bluetooth address failed");
		return FALSE;
	}
	g_print ("Current Bluetooth master: %02X:%02X:%02X:%02X:%02X:%02X\n",
		 msg[2], msg[3], msg[4], msg[5], msg[6], msg[7]);

	return TRUE;
}

static char *
get_bdaddr (libusb_device_handle *devh, int itfnum)
{
	unsigned char msg[17];
	char *address;
	int res;

	res = libusb_control_transfer (devh,
				       LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE,
				       0x01, 0x03f2, itfnum,
				       (void*) msg, sizeof(msg),
				       5000);

	if (res < 0) {
		g_warning ("Getting the device Bluetooth address failed");
		return NULL;
	}

	address = g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X",
				   msg[4], msg[5], msg[6], msg[7], msg[8], msg[9]);

	if (option_quiet == FALSE) {
		g_print ("Device Bluetooth address: %s\n", address);
	}

	return address;
}

static gboolean
set_master_bdaddr (libusb_device_handle *devh, int itfnum, char *host)
{
	unsigned char msg[8];
	int mac[6];
	int res;

	if (sscanf(host, "%X:%X:%X:%X:%X:%X",
		   &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
		return FALSE;
	}

	msg[0] = 0x01;
	msg[1] = 0x00;
	msg[2] = mac[0];
	msg[3] = mac[1];
	msg[4] = mac[2];
	msg[5] = mac[3];
	msg[6] = mac[4];
	msg[7] = mac[5];

	res = libusb_control_transfer (devh,
				       LIBUSB_ENDPOINT_OUT | LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE,
				       0x09, 0x03f5, itfnum,
				       (void*) msg, sizeof(msg),
				       5000);

	if (res < 0) {
		g_warning ("Setting the master Bluetooth address failed");
		return FALSE;
	}

	return TRUE;
}

static char *
get_host_bdaddr (void)
{
	FILE *f;
	int mac[6];

	//FIXME use dbus to get the default adapter

	f = popen("hcitool dev", "r");

	if (f == NULL) {
		//FIXME
		return NULL;
	}
	if (fscanf(f, "%*s\n%*s %X:%X:%X:%X:%X:%X",
		   &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
		//FIXME
		return NULL;
	}

	return g_strdup_printf ("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int
handle_device (libusb_device *dev, struct libusb_config_descriptor *cfg, int itfnum, const struct libusb_interface_descriptor *alt)
{
	libusb_device_handle *devh;
	int res, retval;

	retval = -1;

	if (libusb_open (dev, &devh) < 0) {
		g_warning ("Can't open device");
		goto bail;
	}
	libusb_detach_kernel_driver (devh, itfnum);

	res = libusb_claim_interface (devh, itfnum);
	if (res < 0) {
		g_warning ("Can't claim interface %d", itfnum);
		goto bail;
	}

	if (option_get_master != FALSE) {
		if (show_master (devh, itfnum) == FALSE)
			goto bail;
		retval = 0;
	}

	if (option_master != NULL) {
		if (strcmp (option_master, "auto") == 0) {
			g_free (option_master);
			option_master = get_host_bdaddr ();
			if (option_master == NULL) {
				g_warning ("Can't get bdaddr from default device");
				retval = -1;
				goto bail;
			}
		}
	} else {
		option_master = get_host_bdaddr ();
		if (option_master == NULL) {
			g_warning ("Can't get bdaddr from default device");
			retval = -1;
			goto bail;
		}
	}

	if (option_store_info != FALSE) {
		sdp_record_t *rec;
		char *device;
		bdaddr_t dst, src;

		device = get_bdaddr (devh, itfnum);
		if (device == NULL) {
			retval = -1;
			goto bail;
		}

		rec = record_from_string (PS3_PNP_RECORD);
		store_record(option_master, device, rec);
		write_trust(option_master, device, "[all]", TRUE);
		store_device_id(option_master, device, 0xffff, 0x054c, 0x0268, 0);
		str2ba(option_master, &src);
		str2ba(device, &dst);
		write_device_profiles(&src, &dst, "");
		write_device_name(&src, &dst, "PLAYSTATION(R)3 Controller");
		sdp_record_free(rec);

		if (set_master_bdaddr (devh, itfnum, option_master) == FALSE) {
			retval = -1;
			goto bail;
		}
	}

bail:
	libusb_release_interface (devh, itfnum);
	res = libusb_attach_kernel_driver(devh, itfnum);
	if (res < 0) {
		//FIXME sometimes the kernel tells us ENOENT, but succeeds anyway...
		g_warning ("Reattaching the driver failed: %d", res);
	}
	if (devh != NULL)
		libusb_close (devh);

	return retval;
}

int main (int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	libusb_device **list;
	ssize_t num_devices, i;

	context = g_option_context_new ("- Manage Sixaxis PS3 controllers");
	g_option_context_add_main_entries (context, options, NULL);
	if (g_option_context_parse (context, &argc, &argv, &error) == FALSE) {
		g_warning ("Couldn't parse command-line options: %s", error->message);
		return 1;
	}

	/* Check that the passed bdaddr is correct */
	if (option_master != NULL && strcmp (option_master, "auto") != 0) {
		//FIXME check bdaddr
	}

	libusb_init (NULL);

	/* Find device(s) */
	num_devices = libusb_get_device_list (NULL, &list);
	if (num_devices < 0) {
		g_warning ("libusb_get_device_list failed");
		return 1;
	}

	for (i = 0; i < num_devices; i++) {
		struct libusb_config_descriptor *cfg;
		libusb_device *dev = list[i];
		struct libusb_device_descriptor desc;
		guint8 j;

		if (libusb_get_device_descriptor (dev, &desc) < 0) {
			g_warning ("libusb_get_device_descriptor failed");
			continue;
		}

		/* Here we check for the supported devices */
		if (desc.idVendor != VENDOR || desc.idProduct != PRODUCT)
			continue;

		/* Look for the interface number that interests us */
		for (j = 0; j < desc.bNumConfigurations; j++) {
			struct libusb_config_descriptor *config;
			guint8 k;

			libusb_get_config_descriptor (dev, j, &config);

			for (k = 0; k < config->bNumInterfaces; k++) {
				const struct libusb_interface *itf = &config->interface[k];
				int l;

				for (l = 0; l < itf->num_altsetting ; l++) {
					struct libusb_interface_descriptor alt;

					alt = itf->altsetting[l];
					if (alt.bInterfaceClass == 3) {
						handle_device (dev, cfg, l, &alt);
					}
				}
			}
		}
	}

	return 0;
}


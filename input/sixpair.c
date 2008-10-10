/* To compile
 * gcc -g -Wall -I../src -I../lib/ -I../include -DSTORAGEDIR=\"/var/lib/bluetooth\" -o sixpair sixpair.c ../src/storage.c ../common/libhelper.a -I../common `pkg-config --libs --cflags glib-2.0 libusb` -lbluetooth
 */

#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>

#include <sdp.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hidp.h>
#include <glib.h>
#include <usb.h>

#include "storage.h"

/* Vendor and product ID for the Sixaxis PS3 controller */
#define VENDOR 0x054c
#define PRODUCT 0x0268

#define USB_DIR_IN 0x80
#define USB_DIR_OUT 0

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
show_master (usb_dev_handle *devh, int itfnum)
{
	unsigned char msg[8];
	int res;

	res = usb_control_msg (devh,
			       USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
			       0x01, 0x03f5, itfnum,
			       (void*) msg, sizeof(msg),
			       5000);

	if (res < 0) {
		g_warning ("Getting the master Bluetooth address failed");
		return FALSE;
	}
	g_print ("Current Bluetooth master: %02x:%02x:%02x:%02x:%02x:%02x\n",
		 msg[2], msg[3], msg[4], msg[5], msg[6], msg[7]);

	return TRUE;
}

static char *
get_bdaddr (usb_dev_handle *devh, int itfnum)
{
	unsigned char msg[17];
	char *address;
	int res;

	res = usb_control_msg (devh,
			       USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
			       0x01, 0x03f2, itfnum,
			       (void*) msg, sizeof(msg),
			       5000);

	if (res < 0) {
		g_warning ("Getting the device Bluetooth address failed");
		return NULL;
	}

	address = g_strdup_printf ("%02x:%02x:%02x:%02x:%02x:%02x",
				   msg[4], msg[5], msg[6], msg[7], msg[8], msg[9]);

	if (option_quiet == FALSE) {
		g_print ("Device Bluetooth address: %s\n", address);
	}

	return address;
}

static gboolean
set_master_bdaddr (usb_dev_handle *devh, int itfnum, char *host)
{
	unsigned char msg[8];
	int mac[6];
	int res;

	if (sscanf(host, "%x:%x:%x:%x:%x:%x",
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

	res = usb_control_msg (devh,
			       USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE,
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
	if (fscanf(f, "%*s\n%*s %x:%x:%x:%x:%x:%x",
		   &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
		//FIXME
		return NULL;
	}

	return g_strdup_printf ("%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int
get_record_info (struct usb_interface_descriptor *alt, unsigned int *_len, unsigned int *_country, uint16_t *_version)
{
	unsigned char *buf;
	unsigned int size, len, country;
	uint16_t version;
	int l;

	len = 0;
	country = 0;
	version = 0;

	if (!alt->extralen)
		return 0;

	size = alt->extralen;
	buf = alt->extra;
	while (size >= 2 * sizeof(u_int8_t)) {
		if (buf[0] < 2 || buf[1] != USB_DT_HID)
			continue;

		//FIXME that should be "21"
		//g_message ("country: %u", buf[4]);
		//country = buf[4];
		//country = 0x21;
		country = 0;
		version = (buf[3] << 8) + buf[2];

		for (l = 0; l < buf[5]; l++) {
			/* we are just interested in report descriptors*/
			if (buf[6+3*l] != USB_DT_REPORT)
				continue;
			len = buf[7+3*l] | (buf[8+3*l] << 8);
		}
		size -= buf[0];
		buf += buf[0];
	}

	if (len == 0)
		return -1;
	*_len = len;
	*_country = country;
	*_version = version;

	return 0;
}

static void
fill_req_from_usb (struct usb_device *dev, struct hidp_connadd_req *req, void *data, unsigned int len, unsigned int country, uint16_t version)
{
	req->vendor = dev->descriptor.idVendor;
	req->product = dev->descriptor.idProduct;
	req->version = version;
	/* req->subclass already set */
	req->country = country;
	/* Default value */
	req->parser = 0x0100;
	/* What are we expecting here? No idea, but we don't seem to need it */
	req->flags = 0;

	req->rd_size = len;
	req->rd_data = data;
}

static void
store_info (const char *host, const char *device, struct hidp_connadd_req *req)
{
	bdaddr_t dest, src;

	if (str2ba (host, &src) < 0) {
		//FIXME
		return;
	}
	if (str2ba (device, &dest) < 0) {
		//FIXME
		return;
	}

#if 0
	if (store_device_info (&src, &dest, req) < 0)
#endif
		g_message ("store_device_info failed");
}

static int
handle_device (struct usb_device *dev, struct usb_config_descriptor *cfg, int itfnum, struct usb_interface_descriptor *alt)
{
	usb_dev_handle *devh;
	int res, retval;

	retval = -1;

	devh = usb_open (dev);
	if (devh == NULL) {
		g_warning ("Can't open device");
		goto bail;
	}
	usb_detach_kernel_driver_np (devh, itfnum);

	res = usb_claim_interface (devh, itfnum);
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
		unsigned char data[8192];
		struct hidp_connadd_req req;
		unsigned int len, country;
		int n;
		uint16_t version;
		char *device;

		device = get_bdaddr (devh, itfnum);
		if (device == NULL) {
			retval = -1;
			goto bail;
		}

		if (get_record_info (alt, &len, &country, &version) < 0) {
			g_warning ("Can't get record info");
			retval = -1;
			goto bail;
		}

		if ((n = usb_control_msg(devh,
				    USB_ENDPOINT_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE,
				    USB_REQ_GET_DESCRIPTOR,
				    (USB_DT_REPORT << 8),
				    itfnum, (void *) &data, len, 5000)) < 0) {
			g_warning ("Can't get report descriptor (length: %d, interface: %d)", len, itfnum);
			retval = -1;
			goto bail;
		}

		req.subclass = alt->bInterfaceSubClass;
		fill_req_from_usb (dev, &req, data, len, country, version);

		store_info (option_master, device, &req);

		if (set_master_bdaddr (devh, itfnum, option_master) == FALSE) {
			retval = -1;
			goto bail;
		}

		//FIXME finally, set device as trusted
	}

bail:
	if (devh != NULL)
		usb_close (devh);

	return retval;
}

int main (int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	struct usb_bus *busses, *bus;

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

	/* Find device(s) */
	usb_init ();
	if (usb_find_busses () < 0) {
		g_warning ("usb_find_busses failed");
		return 1;
	}
	if (usb_find_devices () < 0) {
		g_warning ("usb_find_devices failed");
		return 1;
	}

	busses = usb_get_busses();
	if (busses == NULL) {
		g_warning ("usb_get_busses failed");
		return 1;
	}

	for (bus = busses; bus; bus = bus->next) {
		struct usb_device *dev;

		for (dev = bus->devices; dev; dev = dev->next) {
			struct usb_config_descriptor *cfg;

			/* Here we check for the supported devices */
			if (dev->descriptor.idVendor != VENDOR || dev->descriptor.idProduct != PRODUCT)
				continue;

			/* Look for the interface number that interests us */
			for (cfg = dev->config; cfg < dev->config + dev->descriptor.bNumConfigurations; ++cfg) {
				int itfnum;

				for (itfnum = 0; itfnum < cfg->bNumInterfaces; ++itfnum) {
					struct usb_interface *itf = &cfg->interface[itfnum];
					struct usb_interface_descriptor *alt;

					for (alt = itf->altsetting; alt < itf->altsetting + itf->num_altsetting; ++alt) {
						if (alt->bInterfaceClass == 3) {
							handle_device (dev, cfg, itfnum, alt);
						}
					}
				}
			}
		}
	}

	return 0;
}


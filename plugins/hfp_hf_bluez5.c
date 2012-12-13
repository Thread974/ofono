/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2013 Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <gdbus.h>
#include <gatchat.h>
#include <gattty.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/modem.h>
#include <ofono/dbus.h>
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/devinfo.h>
#include <ofono/netreg.h>
#include <ofono/voicecall.h>
#include <ofono/call-volume.h>
#include <ofono/handsfree.h>

#include <drivers/hfpmodem/slc.h>

#include "bluez5.h"
#include "media.h"

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

#define HFP_EXT_PROFILE_PATH   "/bluetooth/profile/hfp_hf"

struct hfp {
	char *device_address;
	char *device_path;
	struct hfp_slc_info info;
	DBusMessage *msg;
	GIOChannel *slcio;
	GSList *endpoints;
};

static GHashTable *modem_hash = NULL;

static void hfp_free(gpointer user_data)
{
	struct hfp *hfp = user_data;

	if (hfp->msg)
		dbus_message_unref(hfp->msg);

	if (hfp->slcio)
		g_io_channel_unref(hfp->slcio);

	g_slist_free(hfp->endpoints);
	g_free(hfp->device_address);
	g_free(hfp->device_path);
	g_free(hfp);
}

static void modem_data_free(gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct hfp *hfp = ofono_modem_get_data(modem);

	hfp_free(hfp);
}

static void hfp_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	ofono_info("%s%s", prefix, str);
}

static void slc_established(gpointer userdata)
{
	struct ofono_modem *modem = userdata;
	struct hfp *hfp = ofono_modem_get_data(modem);
	DBusMessage *msg;

	ofono_modem_set_powered(modem, TRUE);

	msg = dbus_message_new_method_return(hfp->msg);
	g_dbus_send_message(ofono_dbus_get_connection(), msg);
	dbus_message_unref(hfp->msg);
	hfp->msg = NULL;

	ofono_info("Service level connection established");
}

static void slc_failed(gpointer userdata)
{
	struct ofono_modem *modem = userdata;
	struct hfp *hfp = ofono_modem_get_data(modem);
	DBusMessage *msg;

	msg = g_dbus_create_error(hfp->msg, BLUEZ_ERROR_INTERFACE
						".Failed",
						"HFP Handshake failed");

	g_dbus_send_message(ofono_dbus_get_connection(), msg);
	dbus_message_unref(hfp->msg);
	hfp->msg = NULL;

	ofono_error("Service level connection failed");
	ofono_modem_set_powered(modem, FALSE);

	hfp_slc_info_free(&hfp->info);
}

static void hfp_disconnected_cb(gpointer user_data)
{
	struct ofono_modem *modem = user_data;
	struct hfp *hfp = ofono_modem_get_data(modem);

	DBG("HFP disconnected");

	hfp_slc_info_free(&hfp->info);

	ofono_modem_set_powered(modem, FALSE);
	g_hash_table_remove(modem_hash, hfp->device_path);
	ofono_modem_remove(modem);
}

static GIOChannel *service_level_connection(struct ofono_modem *modem, int fd, int *err)
{
	struct hfp *hfp = ofono_modem_get_data(modem);
	GIOChannel *io;
	GAtSyntax *syntax;
	GAtChat *chat;

	io = g_io_channel_unix_new(fd);
	if (io == NULL) {
		ofono_error("Service level connection failed: %s (%d)",
			strerror(errno), errno);
		*err = -EIO;
		return NULL;
	}

	syntax = g_at_syntax_new_gsm_permissive();
	chat = g_at_chat_new(io, syntax);
	g_at_syntax_unref(syntax);
	g_io_channel_set_close_on_unref(io, TRUE);

	if (chat == NULL) {
		*err = -ENOMEM;
		goto fail;
	}

	g_at_chat_set_disconnect_function(chat, hfp_disconnected_cb, modem);

	if (getenv("OFONO_AT_DEBUG"))
		g_at_chat_set_debug(chat, hfp_debug, "");

	hfp->info.chat = chat;
	hfp_slc_establish(&hfp->info, slc_established, slc_failed, modem);

	*err = -EINPROGRESS;

	return io;

fail:
	g_io_channel_unref(io);
	return NULL;
}

static int modem_register(struct hfp *hfp, const char *alias, int fd,
							guint16 version)
{
	struct ofono_modem *modem;
	guint8 codecs[1];
	char *path;
	int err;

	path = g_strconcat("hfp", hfp->device_path, NULL);

	modem = ofono_modem_create(path, "hfp");

	g_free(path);

	if (modem == NULL)
		return -ENOMEM;

	ofono_modem_set_data(modem, hfp);
	ofono_modem_set_name(modem, alias);
	ofono_modem_register(modem);

	g_hash_table_insert(modem_hash, g_strdup(hfp->device_path), modem);

	memset(codecs, 0, sizeof(codecs));
	codecs[0] = HFP_CODEC_CVSD;

	hfp_slc_info_init(&hfp->info, version, codecs, 1);

	hfp->slcio = service_level_connection(modem, fd, &err);

	return err;
}

static void parse_guint16(DBusMessageIter *iter, gpointer user_data)
{
	guint16 *value = user_data;

	if (dbus_message_iter_get_arg_type(iter) !=  DBUS_TYPE_UINT16)
		return;

	dbus_message_iter_get_basic(iter, value);
}

static void parse_string(DBusMessageIter *iter, gpointer user_data)
{
	char **str = user_data;
	int arg_type = dbus_message_iter_get_arg_type(iter);

	if (arg_type != DBUS_TYPE_OBJECT_PATH && arg_type != DBUS_TYPE_STRING)
		return;

	dbus_message_iter_get_basic(iter, str);
}

static void parse_byte(DBusMessageIter *iter, gpointer user_data)
{
	guint8 *value = user_data;

	if (dbus_message_iter_get_arg_type(iter) !=  DBUS_TYPE_BYTE)
		return;

	dbus_message_iter_get_basic(iter, value);
}

static void parse_byte_array(DBusMessageIter *iter, gpointer user_data)
{
	DBusMessageIter array;
	GArray **garray = user_data;
	guint8 *data = NULL;
	int n = 0;

	if (dbus_message_iter_get_arg_type(iter) !=  DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &data, &n);
	if (n == 0)
		return;

	*garray = g_array_sized_new(TRUE, TRUE, sizeof(guint8), n);
	*garray = g_array_append_vals(*garray, (gconstpointer) data, n);
}

static void parse_media_endpoints(DBusMessageIter *array, gpointer user_data)
{
	const char *path, *owner;
	GSList **endpoints = user_data;
	GArray *capabilities = NULL;
	struct media_endpoint *endpoint;
	guint8 codec;
	DBusMessageIter dict, variant, entry;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		path = NULL;
		codec = 0x00;
		capabilities = NULL;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return;

		dbus_message_iter_get_basic(&entry, &owner);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return;

		dbus_message_iter_recurse(&entry, &variant);

		bluetooth_iter_parse_properties(&variant,
				"Path", parse_string, &path,
				"Codec", parse_byte, &codec,
				"Capabilities", parse_byte_array, &capabilities,
				NULL);

		dbus_message_iter_next(&dict);

		endpoint = media_endpoint_new(owner, path, codec, capabilities);
		if (capabilities)
			g_array_unref(capabilities);

		*endpoints = g_slist_append(*endpoints, endpoint);

		DBG("Media Endpoint %s %s codec:0x%02X Capabilities:%p",
					owner, path, codec, capabilities);
	}
}

static int hfp_probe(struct ofono_modem *modem)
{
	DBG("modem: %p", modem);

	return 0;
}

static void hfp_remove(struct ofono_modem *modem)
{
	DBG("modem: %p", modem);
}

/* power up hardware */
static int hfp_enable(struct ofono_modem *modem)
{
	DBG("%p", modem);

	if (ofono_modem_get_powered(modem))
		return 0;

	ofono_modem_set_powered(modem, TRUE);

	return 0;
}

static int hfp_disable(struct ofono_modem *modem)
{
	DBG("%p", modem);

	ofono_modem_set_powered(modem, FALSE);

	return 0;
}

static void hfp_pre_sim(struct ofono_modem *modem)
{
	struct hfp *hfp = ofono_modem_get_data(modem);

	DBG("%p", modem);

	ofono_devinfo_create(modem, 0, "hfpmodem", hfp->device_address);
	ofono_voicecall_create(modem, 0, "hfpmodem", &hfp->info);
	ofono_netreg_create(modem, 0, "hfpmodem", &hfp->info);
	ofono_call_volume_create(modem, 0, "hfpmodem", &hfp->info);
	ofono_handsfree_create(modem, 0, "hfpmodem", &hfp->info);
}

static void hfp_post_sim(struct ofono_modem *modem)
{
	DBG("%p", modem);
}

static struct ofono_modem_driver hfp_driver = {
	.name		= "hfp",
	.modem_type	= OFONO_MODEM_TYPE_HFP,
	.probe		= hfp_probe,
	.remove		= hfp_remove,
	.enable		= hfp_enable,
	.disable	= hfp_disable,
	.pre_sim	= hfp_pre_sim,
	.post_sim	= hfp_post_sim,
};

static DBusMessage *profile_new_connection(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct hfp *hfp;
	DBusMessageIter entry;
	const char *device;
	GSList *endpoints = NULL;
	guint16 version, features;
	int fd, err;

	DBG("Profile handler NewConnection");

	if (dbus_message_iter_init(msg, &entry) == FALSE)
		goto error;

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_OBJECT_PATH)
		goto error;

	dbus_message_iter_get_basic(&entry, &device);
	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_UNIX_FD)
		goto error;

	dbus_message_iter_get_basic(&entry, &fd);
	if (fd < 0)
		goto error;

	dbus_message_iter_next(&entry);

	bluetooth_iter_parse_properties(&entry,
			"Version", parse_guint16, &version,
			"Features", parse_guint16, &features,
			"MediaEndpoints", parse_media_endpoints, &endpoints,
			NULL);

	DBG("%s version: 0x%04x feature: 0x%04x", device, version, features);

	if (endpoints == NULL) {
		ofono_error("Media Endpoint missing");
		goto error;
	}

	hfp = g_new0(struct hfp, 1);
	hfp->device_address = g_strdup("unknown");
	hfp->device_path = g_strdup(device);
	hfp->endpoints = endpoints;
	hfp->msg = dbus_message_ref(msg);

	err = modem_register(hfp, "unknown", fd, version);
	if (err < 0 && err != -EINPROGRESS) {
		hfp_free(hfp);
		return g_dbus_create_error(msg,
				BLUEZ_ERROR_INTERFACE ".Rejected",
				"%s", strerror(-err));
	}

	return NULL;

error:
	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE ".Rejected",
					"Invalid arguments in method call");
}

static DBusMessage *profile_release(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBG("Profile handler Release");

	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
						".NotImplemented",
						"Implementation not provided");
}

static DBusMessage *profile_cancel(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBG("Profile handler Cancel");

	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static DBusMessage *profile_disconnection(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBG("Profile handler RequestDisconnection");

	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static const GDBusMethodTable profile_methods[] = {
	{ GDBUS_ASYNC_METHOD("NewConnection",
				GDBUS_ARGS({ "device", "o"}, { "fd", "h"},
						{ "fd_properties", "a{sv}" }),
				NULL, profile_new_connection) },
	{ GDBUS_METHOD("Release", NULL, NULL, profile_release) },
	{ GDBUS_METHOD("Cancel", NULL, NULL, profile_cancel) },
	{ GDBUS_METHOD("RequestDisconnection",
				GDBUS_ARGS({"device", "o"}), NULL,
				profile_disconnection) },
	{ }
};

static int hfp_init(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	int err;

	if (DBUS_TYPE_UNIX_FD < 0)
		return -EBADF;

	/* Registers External Profile handler */
	if (!g_dbus_register_interface(conn, HFP_EXT_PROFILE_PATH,
					BLUEZ_PROFILE_INTERFACE,
					profile_methods, NULL,
					NULL, NULL, NULL)) {
		ofono_error("Register Profile interface failed: %s",
						HFP_EXT_PROFILE_PATH);
		return -EIO;
	}

	err = ofono_modem_driver_register(&hfp_driver);
	if (err < 0) {
		g_dbus_unregister_interface(conn, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);
		return err;
	}

	err = bluetooth_register_profile(conn, HFP_HS_UUID, "hfp_hf",
						HFP_EXT_PROFILE_PATH);
	if (err < 0) {
		g_dbus_unregister_interface(conn, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);
		ofono_modem_driver_unregister(&hfp_driver);
		return err;
	}

	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
								modem_data_free);

	return 0;
}

static void hfp_exit(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();

	bluetooth_unregister_profile(conn, HFP_EXT_PROFILE_PATH);
	g_dbus_unregister_interface(conn, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);
	ofono_modem_driver_unregister(&hfp_driver);

	g_hash_table_destroy(modem_hash);
}

OFONO_PLUGIN_DEFINE(hfp_bluez5, "External Hands-Free Profile Plugin", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT, hfp_init, hfp_exit)

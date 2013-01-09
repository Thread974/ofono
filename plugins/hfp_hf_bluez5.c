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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

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

/* HFP 1.6 SPEC page 95: “SupportedFeatures” table */
enum sdp_supported_features {
	HF_SDP_FEATURE_ECNR = 0x01,
	HF_SDP_FEATURE_3WAY = 0x02,
	HF_SDP_FEATURE_CLIP = 0x04,
	HF_SDP_FEATURE_VOICE_RECOGNITION = 0x08,
	HF_SDP_FEATURE_REMOTE_VOLUME_CONTROL = 0x10,
	HF_SDP_FEATURE_WBS = 0x20,
};

struct hfp {
	char *device_address;
	char *device_path;
	char *adapter_address;
	struct hfp_slc_info info;
	guint8 current_codec;
	DBusMessage *msg;
	GIOChannel *slcio;
	GIOChannel *scoio;
	guint sco_watch;
	GSList *endpoints;
	GSList *transports;
};

struct bt_peer {
	char src[18];
	char dst[18];
};

static GHashTable *modem_hash = NULL;
static GHashTable *devices_proxies = NULL;
static GIOChannel *sco_io = NULL;
static guint sco_watch = 0;
static GDBusClient *bluez = NULL;

static void hfp_free(gpointer user_data)
{
	struct hfp *hfp = user_data;

	if (hfp->msg)
		dbus_message_unref(hfp->msg);

	if (hfp->slcio)
		g_io_channel_unref(hfp->slcio);

	if (hfp->sco_watch)
		g_source_remove(hfp->sco_watch);

	if (hfp->scoio)
		g_io_channel_unref(hfp->scoio);

	g_slist_free_full(hfp->endpoints, (GDestroyNotify) media_endpoint_unref);
	g_slist_free_full(hfp->transports, (GDestroyNotify) media_transport_unref);
	g_free(hfp->device_address);
	g_free(hfp->adapter_address);
	g_free(hfp->device_path);
	g_free(hfp);
}

static void hfp_reset(struct hfp *hfp, GSList *endpoints, DBusMessage *msg,
			const char *adapter_address, const char *device_address)
{
	hfp->endpoints = endpoints;
	hfp->current_codec = HFP_CODEC_CVSD;

	if (hfp->msg)
		dbus_message_unref(hfp->msg);
	hfp->msg = dbus_message_ref(msg);

	g_free(hfp->adapter_address);
	hfp->adapter_address = g_strdup(adapter_address);

	g_free(hfp->device_address);
	hfp->device_address = g_strdup(device_address);
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

static void bt_bacpy(bdaddr_t *dst, const bdaddr_t *src)
{
	memcpy(dst, src, sizeof(bdaddr_t));
}

static int bt_ba2str(const bdaddr_t *ba, char *str)
{
	return sprintf(str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
		ba->b[5], ba->b[4], ba->b[3], ba->b[2], ba->b[1], ba->b[0]);
}

static int bt_str2ba(const char *str, bdaddr_t *ba)
{
	int i;

	for (i = 5; i >= 0; i--, str += 3)
		ba->b[i] = strtol(str, NULL, 16);

	return 0;
}

static gboolean modem_address_cmp(gpointer key, gpointer value, gpointer user_data)
{
	const struct bt_peer *peer = user_data;
	struct ofono_modem *modem = value;
	struct hfp *hfp = ofono_modem_get_data(modem);

	return (g_strcmp0(hfp->device_address, peer->dst) == 0 &&
			g_strcmp0(hfp->adapter_address, peer->src) == 0);
}

static void sco_watch_destroy(gpointer user_data)
{
	struct hfp *hfp = user_data;

	hfp->sco_watch = 0;
	if (hfp->scoio) {
		g_io_channel_unref(hfp->scoio);
		hfp->scoio = NULL;
	}
}

static gboolean sco_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)

{
	struct hfp *hfp = user_data;
	struct media_transport *transport;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	DBG("%s connected to %s", hfp->adapter_address, hfp->device_address);

	transport = media_transport_by_codec(hfp->transports,
						hfp->current_codec);
	if (transport == NULL) {
		ofono_error("No transport for codec %d", hfp->current_codec);
		return FALSE;
	}

	media_transport_set_channel(transport, io);

	return FALSE;
}

static GIOChannel *sco_connect(bdaddr_t *src, bdaddr_t *dst, int *err)
{
	struct sockaddr_sco addr;
	GIOChannel *io;
	int sk, ret;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		*err = errno;
		return NULL;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bt_bacpy(&addr.sco_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		*err = errno;
		return NULL;
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bt_bacpy(&addr.sco_bdaddr, dst);

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, NULL);

	ret = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) {
		g_io_channel_unref(io);
		*err = errno;
		return NULL;
	}

	return io;
}

static void bcs_notify(GAtResult *result, gpointer user_data)
{
	struct hfp *hfp = user_data;
	struct hfp_slc_info *info = &hfp->info;
	GAtResultIter iter;
	GString *str;
	int i, value;

	g_at_result_iter_init(&iter, result);

	if (!g_at_result_iter_next(&iter, "+BCS:"))
		return;

	if (!g_at_result_iter_next_number(&iter, &value))
		return;

	/* If some codec matches, we confirm it */
	for (i = 0; i < info->codecs_len; i++) {
		if (info->codecs[i] == value) {
			char buf[32];

			hfp->current_codec = value;
			DBG("Negotiated HFP codec: %d", value);

			snprintf(buf, sizeof(buf), "AT+BCS=%d", value);
			g_at_chat_send(info->chat, buf, NULL, NULL,
							NULL, NULL);
			return;
		}
	}

	/* If none matches, we send our supported codecs again */
	str = g_string_new("AT+BAC=");

	for (i = 0; i < info->codecs_len; i++) {
		g_string_append_printf(str, "%d", info->codecs[i]);
		if (i + 1 < info->codecs_len)
			str = g_string_append(str, ",");
	}

	g_at_chat_send(info->chat, str->str, NULL, NULL, NULL, NULL);
	g_string_free(str, TRUE);
}

static void bcc_cb(gboolean ok, GAtResult *result, gpointer user_data)
{
	struct media_transport *transport = user_data;

	if (ok)
		return;

	media_transport_set_channel(transport, NULL);
}

static void hfp16_initiate_sco(struct media_transport *transport,
							gpointer user_data)
{
	struct hfp *hfp = user_data;
	struct hfp_slc_info *info = &hfp->info;

	DBG("HFP16 connecting SCO ...");
	g_at_chat_send(info->chat, "AT+BCC", NULL, bcc_cb, transport, NULL);
}

static void hfp15_initiate_sco(struct media_transport *transport,
							gpointer user_data)
{
	struct hfp *hfp = user_data;
	GIOCondition cond;
	bdaddr_t src, dst;
	int err = 0;

	DBG("HFP15 connecting SCO: %s > %s", hfp->adapter_address,
						hfp->device_address);

	bt_str2ba(hfp->adapter_address, &src);
	bt_str2ba(hfp->device_address, &dst);

	hfp->scoio = sco_connect(&src, &dst, &err);
	if (hfp->scoio == NULL) {
		ofono_error("SCO connect: %s(%d)", strerror(err), err);
		return;
	}

	cond = G_IO_OUT | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	hfp->sco_watch = g_io_add_watch_full(hfp->scoio, G_PRIORITY_DEFAULT,
						cond, sco_connect_cb, hfp,
						sco_watch_destroy);
}

static void transport_registered_cb(DBusPendingCall *call, gpointer user_data)
{
	struct hfp *hfp = user_data;
	DBusMessage *reply;
	struct DBusError derr;
	dbus_bool_t ret;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	ret = dbus_set_error_from_message(&derr, reply);

	dbus_message_unref(reply);

	if (ret == FALSE)
		return;

	ofono_error("%s: %s", derr.name, derr.message);
	dbus_error_free(&derr);

	if (hfp->slcio) {
		g_io_channel_unref(hfp->slcio);
		hfp->slcio = NULL;
	}
}

static void transport_register(gpointer data, gpointer user_data)
{
	struct media_endpoint *endpoint = data;
	struct media_transport *transport;
	struct hfp *hfp = user_data;
	struct hfp_slc_info *info = &hfp->info;
	media_hf_initiate_sco cb;

	if (info->ag_features & HFP_AG_FEATURE_CODEC_NEGOTIATION &&
                       info->hf_features & HFP_HF_FEATURE_CODEC_NEGOTIATION)
		cb = hfp16_initiate_sco;
	else
		cb = hfp15_initiate_sco;

	transport = media_transport_new(hfp->device_path, endpoint, cb, hfp);
	if (media_transport_register(transport, transport_registered_cb,
								hfp) < 0) {
		media_transport_unref(transport);
		return;
	}

	hfp->transports = g_slist_append(hfp->transports, transport);
}

static void transport_unregister(gpointer data, gpointer user_data)
{
	struct media_transport *transport = data;

	media_transport_unregister(transport);
}

static void slc_established(gpointer userdata)
{
	struct ofono_modem *modem = userdata;
	struct hfp *hfp = ofono_modem_get_data(modem);
	struct hfp_slc_info *info = &hfp->info;
	DBusMessage *msg;

	g_at_chat_register(info->chat, "+BCS:", bcs_notify, FALSE, hfp, NULL);

	ofono_modem_set_powered(modem, TRUE);

	msg = dbus_message_new_method_return(hfp->msg);
	g_dbus_send_message(ofono_dbus_get_connection(), msg);
	dbus_message_unref(hfp->msg);
	hfp->msg = NULL;

	ofono_info("Service level connection established");

	g_slist_foreach(hfp->endpoints, transport_register, hfp);
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

	g_slist_foreach(hfp->transports, transport_unregister, hfp);
	g_slist_free_full(hfp->transports, (GDestroyNotify) media_transport_unref);
	hfp->transports = NULL;

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

static struct ofono_modem *modem_register(const char *device,
						const char *alias)
{
	struct ofono_modem *modem;
	struct hfp *hfp;
	char *path;

	modem = g_hash_table_lookup(modem_hash, device);
	if (modem != NULL)
		return modem;

	path = g_strconcat("hfp", device, NULL);

	modem = ofono_modem_create(path, "hfp");

	g_free(path);

	if (modem == NULL)
		return NULL;

	ofono_modem_set_name(modem, alias);
	ofono_modem_register(modem);

	hfp = g_new0(struct hfp, 1);

	ofono_modem_set_data(modem, hfp);

	hfp->device_path = g_strdup(device);

	g_hash_table_insert(modem_hash, g_strdup(device), modem);

	return modem;
}

static int modem_enable(struct ofono_modem *modem, int fd,
				uint8_t *codecs, int len,
				guint version)
{
	struct hfp *hfp;
	int err = 0;

	hfp = ofono_modem_get_data(modem);

	hfp_slc_info_init(&hfp->info, version, codecs, len);

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

static void parse_uuids(DBusMessageIter *array, gpointer user_data)
{
	GSList **uuids = user_data;
	DBusMessageIter value;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &value);

	while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
		const char *uuid;

		dbus_message_iter_get_basic(&value, &uuid);

		*uuids = g_slist_prepend(*uuids, g_strdup(uuid));

		dbus_message_iter_next(&value);
	}
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

static void connect_cb(gboolean success, gpointer user_data)
{
	struct ofono_modem *modem = user_data;

	if (success)
		return;

	ofono_modem_set_powered(modem, FALSE);
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
	struct hfp *hfp;

	DBG("%p", modem);

	if (ofono_modem_get_powered(modem))
		return 0;

	hfp = ofono_modem_get_data(modem);

	bluetooth_connect_profile(ofono_dbus_get_connection(),
					hfp->device_path, HFP_AG_UUID,
					connect_cb, modem);

	return -EINPROGRESS;
}

static int hfp_disable(struct ofono_modem *modem)
{
	struct hfp *hfp;

	DBG("%p", modem);

	if (ofono_modem_get_powered(modem) == FALSE)
		return 0;

	hfp = ofono_modem_get_data(modem);

	bluetooth_disconnect_profile(ofono_dbus_get_connection(),
					hfp->device_path, HFP_AG_UUID,
					NULL, NULL);

	return -EINPROGRESS;
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
	struct ofono_modem *modem;
	DBusMessageIter iter;
	GDBusProxy *proxy;
	struct sockaddr_rc saddr;
	socklen_t optlen;
	DBusMessageIter entry;
	const char *device, *alias;
	GSList *endpoints = NULL;
	guint16 version = HFP_VERSION_1_6, features = 0;
	char device_address[18], adapter_address[18];
	guint8 *codecs;
	int len, fd, err;

	DBG("Profile handler NewConnection");

	if (dbus_message_iter_init(msg, &entry) == FALSE)
		goto error;

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_OBJECT_PATH)
		goto error;

	dbus_message_iter_get_basic(&entry, &device);

	proxy = g_hash_table_lookup(devices_proxies, device);
	if (proxy == NULL)
		goto error;

	if (g_dbus_proxy_get_property(proxy, "Alias", &iter) == FALSE)
		alias = "unknown";
	else
		dbus_message_iter_get_basic(&iter, &alias);

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

	DBG("%s alias: %s version: 0x%04x feature: 0x%04x",
					device, alias, version, features);

	if (endpoints == NULL) {
		ofono_error("Media Endpoint missing");
		goto error;
	}

	memset(&saddr, 0, sizeof(saddr));
	optlen = sizeof(saddr);
	if (getsockname(fd, (struct sockaddr *) &saddr, &optlen) < 0) {
		err = errno;
		ofono_error("RFCOMM getsockname(): %s (%d)", strerror(err), err);
		goto error;
	}

	bt_ba2str(&saddr.rc_bdaddr, adapter_address);

	memset(&saddr, 0, sizeof(saddr));
	optlen = sizeof(saddr);
	if (getpeername(fd, (struct sockaddr *) &saddr, &optlen) < 0) {
		err = errno;
		ofono_error("RFCOMM getpeername(): %s (%d)", strerror(err), err);
		goto error;
	}

	bt_ba2str(&saddr.rc_bdaddr, device_address);

	modem = modem_register(device, alias);
	if (modem == NULL)
		goto error;

	hfp = ofono_modem_get_data(modem);

	hfp_reset(hfp, endpoints, msg, adapter_address, device_address);

	codecs = media_endpoints_to_codecs(endpoints, &len);

	err = modem_enable(modem, fd, codecs, len, version);

	g_free(codecs);

	if (err < 0 && err != -EINPROGRESS) {
		hfp_free(hfp);
		goto error;
	}

	return NULL;

error:
	close(fd);
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

static void reply_pending(gpointer key, gpointer value, gpointer user_data)
{
	const char *owner, *sender = user_data;
	struct ofono_modem *modem = value;
	struct hfp *hfp = ofono_modem_get_data(modem);
	DBusMessage *reply;

	if (hfp->msg == NULL)
		return;

	owner = dbus_message_get_sender(hfp->msg);
	if (g_str_equal(owner, sender) == FALSE)
		return;

	if (hfp->slcio) {
		g_io_channel_unref(hfp->slcio);
		hfp->slcio = NULL;
	}

	reply = g_dbus_create_error(hfp->msg,
				BLUEZ_ERROR_INTERFACE ".Canceled",
				"Operation canceled");
	g_dbus_send_message(ofono_dbus_get_connection(), reply);

	dbus_message_unref(hfp->msg);
	hfp->msg = NULL;
}

static DBusMessage *profile_cancel(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	char *sender = (char *) dbus_message_get_sender(msg);

	DBG("Profile handler Cancel");

	g_hash_table_foreach(modem_hash, reply_pending, sender);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *profile_disconnection(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem;
	struct hfp *hfp;
	const char *device = NULL;
	DBusMessageIter entry;

	DBG("Profile handler RequestDisconnection");

	if (dbus_message_iter_init(msg, &entry) == FALSE)
		goto error;

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_OBJECT_PATH)
		goto error;

	dbus_message_iter_get_basic(&entry, &device);

	modem = g_hash_table_lookup(modem_hash, device);
	if (modem == NULL)
		goto error;

	hfp = ofono_modem_get_data(modem);
	if (hfp->slcio) {
		g_io_channel_shutdown(hfp->slcio, FALSE, NULL);
		g_io_channel_unref(hfp->slcio);
		hfp->slcio = NULL;
	}

	return dbus_message_new_method_return(msg);

error:
	return g_dbus_create_error(msg,
			BLUEZ_ERROR_INTERFACE ".Rejected",
			"Invalid arguments in method call");
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

static uint8_t codec2mode(uint8_t codec)
{
	switch (codec) {
	case HFP_CODEC_CVSD:
		return SCO_MODE_CVSD;
	default:
		return SCO_MODE_TRANSPARENT;
	}
}

static gboolean sco_set_codec(int sk, uint8_t codec)
{
	struct sco_options options;
	int err;

	memset(&options, 0, sizeof(options));

	options.mode = codec2mode(codec);

	if (setsockopt(sk, SOL_SCO, SCO_OPTIONS, &options, sizeof(options)) < 0) {
		err = errno;
		ofono_error("Can't set SCO options: %s (%d)",
							strerror(err), err);
		return FALSE;
	}

	return TRUE;
}

static gboolean sco_accept(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct sockaddr_sco saddr;
	struct ofono_modem *modem;
	struct media_transport *transport;
	struct hfp *hfp;
	socklen_t optlen;
	GIOChannel *nio;
	struct bt_peer peer;
	int sk, nsk, err;

	DBG("");

	if (cond & G_IO_NVAL)
		return FALSE;

	sk = g_io_channel_unix_get_fd(io);

	memset(&saddr, 0, sizeof(saddr));
	optlen = sizeof(saddr);

	nsk = accept(sk, (struct sockaddr *) &saddr, &optlen);
	if (nsk < 0)
		return TRUE;

	bt_ba2str(&saddr.sco_bdaddr, peer.dst);

	memset(&saddr, 0, sizeof(saddr));
	optlen = sizeof(saddr);
	if (getsockname(nsk, (struct sockaddr *) &saddr, &optlen) < 0) {
		err = errno;
		ofono_error("SCO getsockname(): %s (%d)", strerror(err), err);
		return TRUE;
	}

	bt_ba2str(&saddr.sco_bdaddr, peer.src);
	modem = g_hash_table_find(modem_hash, modem_address_cmp, &peer);
	if (modem == NULL) {
		ofono_error("Rejecting SCO: SLC connection missing!");
		close(nsk);
		return TRUE;
	}

	hfp = ofono_modem_get_data(modem);

	if (sco_set_codec(nsk, hfp->current_codec) == FALSE) {
		ofono_error("Can't set codec SCO option");

		/* Fallback to the default codec */
		hfp->current_codec = HFP_CODEC_CVSD;
	}

	DBG("SCO: %s < %s (incoming)", peer.src, peer.dst);

	nio = g_io_channel_unix_new(nsk);

	g_io_channel_set_close_on_unref(nio, TRUE);
	g_io_channel_set_flags(nio, G_IO_FLAG_NONBLOCK, NULL);

	transport = media_transport_by_codec(hfp->transports,
						hfp->current_codec);
	if (transport == NULL) {
		ofono_error("No transport for codec %d", hfp->current_codec);
		return TRUE;
	}

	media_transport_set_channel(transport, nio);

	g_io_channel_unref(nio);

	return TRUE;
}

static GIOChannel *sco_listen(int *err)
{
	struct sockaddr_sco addr;
	GIOChannel *io;
	int sk, defer_setup = 1;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		*err = -errno;
		return NULL;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bt_bacpy(&addr.sco_bdaddr, BDADDR_ANY);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		*err = -errno;
		return NULL;
	}

	if (setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP,
				&defer_setup, sizeof(defer_setup)) < 0) {
		ofono_warn("Can't enable deferred setup: %s (%d)",
						strerror(errno), errno);
		*err = -errno;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, NULL);

	if (listen(sk, 5) < 0) {
		g_io_channel_unref(io);
		*err = -errno;
		return NULL;
	}

	return io;
}

static int sco_init(void)
{
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	int err = 0;

	sco_io = sco_listen(&err);
	if (sco_io == NULL)
		return err;

	sco_watch = g_io_add_watch(sco_io, cond, sco_accept, NULL);

	return 0;
}

static void connect_handler(DBusConnection *conn, void *user_data)
{
	uint16_t features = HF_SDP_FEATURE_3WAY |
				HF_SDP_FEATURE_CLIP |
				HF_SDP_FEATURE_WBS |
				HF_SDP_FEATURE_VOICE_RECOGNITION |
				HF_SDP_FEATURE_REMOTE_VOLUME_CONTROL;

	DBG("Registering External Profile handler ...");

	if (!g_dbus_register_interface(conn, HFP_EXT_PROFILE_PATH,
					BLUEZ_PROFILE_INTERFACE,
					profile_methods, NULL,
					NULL, NULL, NULL)) {
		ofono_error("Register Profile interface failed: %s",
						HFP_EXT_PROFILE_PATH);
	}

	bluetooth_register_profile(conn, HFP_HS_UUID, HFP_VERSION_1_6,
				features, "hfp_hf", HFP_EXT_PROFILE_PATH);
}

static void disconnect_handler(DBusConnection *conn, void *user_data)
{

	DBG("Unregistering External Profile handler ...");

	g_dbus_unregister_interface(conn, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface, *path, *alias;
	DBusMessageIter iter;
	GSList *l, *uuids = NULL;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	if (g_str_equal(BLUEZ_DEVICE_INTERFACE, interface) == FALSE)
		return;

	g_hash_table_insert(devices_proxies, g_strdup(path),
						g_dbus_proxy_ref(proxy));
	DBG("Device proxy: %s(%p)", path, proxy);

	if (g_dbus_proxy_get_property(proxy, "UUIDs", &iter) == FALSE)
		return;

	parse_uuids(&iter, &uuids);

	for (l = uuids; l; l = l->next) {
		const char *uuid = l->data;

		if (g_str_equal(uuid, HFP_AG_UUID) == TRUE)
			break;
	}

	g_slist_free_full(uuids, g_free);

	if (l == NULL)
		return;

	if (g_dbus_proxy_get_property(proxy, "Alias", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &alias);

	modem_register(path, alias);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface, *path;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	if (g_str_equal(BLUEZ_DEVICE_INTERFACE, interface)) {
		g_hash_table_remove(devices_proxies, path);
		DBG("Device proxy: %s(%p)", path, proxy);
	}
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface, *path, *alias;
	struct ofono_modem *modem;
	DBusMessageIter alias_iter;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	DBG("path: %s interface: %s", path, interface);

	if (g_str_equal(BLUEZ_DEVICE_INTERFACE, interface) == FALSE)
		return;

	if (g_dbus_proxy_get_property(proxy, "Alias", &alias_iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&alias_iter, &alias);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;

	ofono_modem_set_name(modem, alias);
}

static int hfp_init(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();
	int err;

	if (DBUS_TYPE_UNIX_FD < 0)
		return -EBADF;

	err = sco_init();
	if (err < 0) {
		ofono_error("SCO: %s(%d)", strerror(-err), -err);
		return err;
	}

	/* Registers External Profile handler */
	if (!g_dbus_register_interface(conn, HFP_EXT_PROFILE_PATH,
					BLUEZ_PROFILE_INTERFACE,
					profile_methods, NULL,
					NULL, NULL, NULL)) {
		ofono_error("Register Profile interface failed: %s",
						HFP_EXT_PROFILE_PATH);
		return -EIO;
	}

	bluez = g_dbus_client_new(conn, BLUEZ_SERVICE, BLUEZ_MANAGER_PATH);
	g_dbus_client_set_connect_watch(bluez, connect_handler, NULL);
	g_dbus_client_set_disconnect_watch(bluez, disconnect_handler, NULL);
	g_dbus_client_set_proxy_handlers(bluez, proxy_added, proxy_removed,
						property_changed, NULL);

	err = ofono_modem_driver_register(&hfp_driver);
	if (err < 0)
		return err;

	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
								modem_data_free);

	devices_proxies = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, (GDestroyNotify) g_dbus_proxy_unref);

	return 0;
}

static void hfp_exit(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();

	g_dbus_unregister_interface(conn, HFP_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);

	ofono_modem_driver_unregister(&hfp_driver);

	g_dbus_client_unref(bluez);

	g_hash_table_destroy(modem_hash);
	g_hash_table_destroy(devices_proxies);

	if (sco_watch)
		g_source_remove(sco_watch);

	if (sco_io)
		g_io_channel_unref(sco_io);

}

OFONO_PLUGIN_DEFINE(hfp_bluez5, "External Hands-Free Profile Plugin", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT, hfp_init, hfp_exit)

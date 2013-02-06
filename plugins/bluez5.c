/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>

#include <glib.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/dbus.h>
#include <ofono/plugin.h>
#include <ofono/log.h>

#include <gdbus/gdbus.h>
#include "bluez5.h"

#define MEDIA_ENDPOINT_INTERFACE	"org.bluez.MediaEndpoint1"
#define MEDIA_TRANSPORT_INTERFACE	"org.bluez.MediaTransport1"

enum transport_state {
	STATE_IDLE,
	STATE_PENDING,
	STATE_ACTIVE
};

struct bt_endpoint {
	gint ref;
	char *owner;
	char *path;
	uint8_t codec;
	unsigned char *capa;	/* Capabilities */
	int capa_size;		/* Capabilities size */
	char *uuid;
};

struct bt_transport {
	gint ref;
	char *path;
	char *device_path;
	guint watch;
	GIOChannel *io;
	enum transport_state state;
	struct bt_endpoint *endpoint;
	bt_initiate_audio init_audio;
	DBusMessage *pending;
	gpointer user_data;
};

static guint sco_watch;
static GSList *sco_cbs;

struct bt_endpoint *bt_endpoint_ref(struct bt_endpoint *endpoint)
{
	if (endpoint == NULL)
		return NULL;

	g_atomic_int_inc(&endpoint->ref);

	return endpoint;
}

void bt_endpoint_unref(struct bt_endpoint *endpoint)
{
	if (g_atomic_int_dec_and_test(&endpoint->ref) == FALSE)
		return;

	g_free(endpoint->owner);
	g_free(endpoint->path);
	g_free(endpoint->uuid);

	if (endpoint->capa)
		g_free(endpoint->capa);

	g_free(endpoint);
}

static struct bt_endpoint *endpoint_new(const char *owner, const char *path,
								uint8_t codec)
{
	struct bt_endpoint *endpoint;

	endpoint = g_new0(struct bt_endpoint, 1);
	endpoint->owner = g_strdup(owner);
	endpoint->path = g_strdup(path);
	endpoint->codec = codec;
	endpoint->uuid = g_strdup(HFP_HS_UUID);

	return bt_endpoint_ref(endpoint);
}

static void parse_uint16(DBusMessageIter *iter, gpointer user_data)
{
	uint16_t *value = user_data;

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

static void parse_endpoints(DBusMessageIter *array, gpointer user_data)
{
	GSList **endpoints = user_data;
	struct bt_endpoint *endpoint;
	const char *path, *owner;
	guint8 codec;
	DBusMessageIter dict, variant, entry;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		path = NULL;
		codec = 0x00;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return;

		dbus_message_iter_get_basic(&entry, &owner);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return;

		dbus_message_iter_recurse(&entry, &variant);

		ofono_dbus_iter_parse_properties(&variant,
				"Path", parse_string, &path,
				"Codec", parse_byte, &codec,
				NULL);

		dbus_message_iter_next(&dict);

		endpoint = endpoint_new(owner, path, codec);
		*endpoints = g_slist_append(*endpoints, endpoint);

		DBG("Media Endpoint %s %s codec: 0x%02X", owner, path, codec);
	}
}

int bt_parse_fd_properties(DBusMessageIter *iter, uint16_t *version,
				uint16_t *features, GSList **endpoints)
{
	uint16_t ver = 0, feat = 0;

	if (endpoints)
		ofono_dbus_iter_parse_properties(iter,
				"Version", parse_uint16, &ver,
				"Features", parse_uint16, &feat,
				"MediaEndpoints", parse_endpoints, endpoints,
				NULL);
	else
		ofono_dbus_iter_parse_properties(iter,
				"Version", parse_uint16, &ver,
				"Features", parse_uint16, &feat,
				NULL);

	if (version)
		*version = ver;

	if (features)
		*features = feat;

	return 0;
}

void bt_bacpy(bdaddr_t *dst, const bdaddr_t *src)
{
	memcpy(dst, src, sizeof(bdaddr_t));
}

int bt_ba2str(const bdaddr_t *ba, char *str)
{
	return sprintf(str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
		ba->b[5], ba->b[4], ba->b[3], ba->b[2], ba->b[1], ba->b[0]);
}

int bt_bacmp(const bdaddr_t *ba1, const bdaddr_t *ba2)
{
	return memcmp(ba1, ba2, sizeof(bdaddr_t));
}

static gboolean sco_accept(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct sockaddr_sco saddr;
	socklen_t alen;
	int sk, nsk;
	GSList *l;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	sk = g_io_channel_unix_get_fd(io);

	memset(&saddr, 0, sizeof(saddr));
	alen = sizeof(saddr);

	nsk = accept(sk, (struct sockaddr *) &saddr, &alen);
	if (nsk < 0)
		return TRUE;

	for (l = sco_cbs; l; l = l->next) {
		bt_sco_accept_cb cb = l->data;

		if (cb(nsk, &saddr))
			return TRUE;
	}

	ofono_warn("No SCO callback for incoming connection");
	close(nsk);

	return TRUE;
}

static int sco_init(void)
{
	GIOChannel *sco_io;
	struct sockaddr_sco saddr;
	int sk, defer_setup = 1;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | O_NONBLOCK | SOCK_CLOEXEC,
								BTPROTO_SCO);
	if (sk < 0)
		return -errno;

	/* Bind to local address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sco_family = AF_BLUETOOTH;
	bt_bacpy(&saddr.sco_bdaddr, BDADDR_ANY);

	if (bind(sk, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		close(sk);
		return -errno;
	}

	if (setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP,
				&defer_setup, sizeof(defer_setup)) < 0)
		ofono_warn("Can't enable deferred setup: %s (%d)",
						strerror(errno), errno);

	if (listen(sk, 5) < 0) {
		close(sk);
		return -errno;
	}

	sco_io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(sco_io, TRUE);

	sco_watch = g_io_add_watch(sco_io,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				sco_accept, NULL);

	g_io_channel_unref(sco_io);

	return 0;
}

int bt_register_sco_server(bt_sco_accept_cb cb)
{
	int err;

	if (!cb) {
		ofono_error("SCO: invalid callback");
		return -1;
	}

	if (!sco_cbs) {
		err = sco_init();
		if (err < 0) {
			ofono_error("SCO: %s(%d)", strerror(-err), -err);
			return err;
		}
	}

	sco_cbs = g_slist_append(sco_cbs, cb);

	return 0;
}

void bt_unregister_sco_server(bt_sco_accept_cb cb)
{
	if (!cb) {
		ofono_error("SCO: invalid callback");
		return;
	}

	sco_cbs = g_slist_remove(sco_cbs, cb);
	if (sco_cbs)
		return;

	g_source_remove(sco_watch);
}

struct bt_transport *bt_transport_ref(struct bt_transport *transport)
{
	if (transport == NULL)
		return NULL;

	g_atomic_int_inc(&transport->ref);

	return transport;
}

guint8 *bt_endpoints_to_codecs(GSList *endpoints, int *len)
{
	GSList *l;
	guint8 *codecs;
	int i;

	if (endpoints == NULL || len == NULL)
		return NULL;

	*len = g_slist_length(endpoints);

	codecs = g_malloc0(*len * sizeof(guint8));

	for (i = 0, l = endpoints; l; l = l->next, i++) {
		struct bt_endpoint *endpoint = l->data;

		codecs[i] = endpoint->codec;
	}

	return codecs;
}

void bt_transport_unref(struct bt_transport *transport)
{
	if (g_atomic_int_dec_and_test(&transport->ref) == FALSE)
		return;

	g_free(transport->device_path);
	g_free(transport->path);

	if (transport->endpoint)
		bt_endpoint_unref(transport->endpoint);

	if (transport->watch)
		g_source_remove(transport->watch);

	if (transport->io)
		g_io_channel_unref(transport->io);

	if (transport->pending)
		dbus_message_unref(transport->pending);

	g_free(transport);
}

void bt_transport_mic_volume_changed(void *userdata)
{
	struct bt_transport *transport = userdata;

	g_dbus_emit_property_changed(ofono_dbus_get_connection(),
				transport->path, MEDIA_TRANSPORT_INTERFACE,
				"MicrophoneGain");
}

void bt_transport_speaker_volume_changed(void *userdata)
{
	struct bt_transport *transport = userdata;

	g_dbus_emit_property_changed(ofono_dbus_get_connection(),
				transport->path, MEDIA_TRANSPORT_INTERFACE,
				"SpeakerGain");
}

struct bt_transport *bt_transport_new(const char *device,
						struct bt_endpoint *endpoint,
						bt_initiate_audio init_audio,
						gpointer user_data)
{
	struct bt_transport *transport;
	static int id = 0;

	transport = g_new0(struct bt_transport, 1);
	transport->path = g_strdup_printf("/transport%d%s/fd", id++, device);
	transport->device_path = g_strdup(device);
	transport->endpoint = bt_endpoint_ref(endpoint);
	transport->state = STATE_IDLE;
	transport->init_audio = init_audio;
	transport->user_data = user_data;

	return bt_transport_ref(transport);
}

struct bt_transport *bt_transport_by_codec(GSList *transports,
							guint8 codec)
{
	GSList *l;

	for (l = transports; l; l = l->next) {
		struct bt_transport *transport = l->data;

		if (transport->endpoint->codec == codec)
			return transport;
	}

	return NULL;
}

static const char *state2str(enum transport_state state)
{
	switch(state) {
	case STATE_IDLE:
		return "idle";
	case STATE_PENDING:
		return "pending";
	case STATE_ACTIVE:
		return "active";
	}

	return "idle";
}

static void transport_set_state(struct bt_transport *transport,
						enum transport_state state)
{
	transport->state = state;
	g_dbus_emit_property_changed(ofono_dbus_get_connection(),
				transport->path, MEDIA_TRANSPORT_INTERFACE,
				"State");
}

static void transport_append_properties(DBusMessageIter *iter,
					struct bt_transport *transport)
{
	DBusMessageIter dict;
	struct bt_endpoint *endpoint = transport->endpoint;
	const char *str;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	ofono_dbus_dict_append(&dict, "Device", DBUS_TYPE_OBJECT_PATH,
						&transport->device_path);

	ofono_dbus_dict_append(&dict, "Codec", DBUS_TYPE_BYTE,
						&endpoint->codec);

	str = state2str(transport->state);
	ofono_dbus_dict_append(&dict, "State", DBUS_TYPE_STRING, &str);

	ofono_dbus_dict_append(&dict, "UUID", DBUS_TYPE_STRING,
							&endpoint->uuid);

	if (endpoint->capa && endpoint->capa_size)
		ofono_dbus_dict_append_array(&dict, "Configuration",
					DBUS_TYPE_BYTE, &endpoint->capa,
					endpoint->capa_size);

	dbus_message_iter_close_container(iter, &dict);
}

static DBusMessage *acquire_message(DBusMessage *msg, GIOChannel *io)
{
	guint16 imtu, omtu;
	int fd;

	fd = g_io_channel_unix_get_fd(io);
	imtu = 48;
	omtu = 48;

	return g_dbus_create_reply(msg, DBUS_TYPE_UNIX_FD, &fd,
					DBUS_TYPE_UINT16, &imtu,
					DBUS_TYPE_UINT16, &omtu,
					DBUS_TYPE_INVALID);
}

static DBusMessage *acquire(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct bt_transport *transport = user_data;
	struct bt_endpoint *endpoint = transport->endpoint;
	const char *sender;

	sender = dbus_message_get_sender(msg);

	DBG("sender %s owner %s", sender, endpoint->owner);

	if (!g_str_equal(sender, endpoint->owner) ||
			transport->state == STATE_ACTIVE || transport->pending)
		return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
						".NotAuthorized",
						"Operation not authorized");

	if (transport->state == STATE_PENDING) {
		transport_set_state(transport, STATE_ACTIVE);
		return acquire_message(msg, transport->io);
	}

	if (transport->init_audio == NULL)
		return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
					".NotAvailable",
					"Operation currently not available");

	transport->pending = dbus_message_ref(msg);
	transport->init_audio(transport, transport->user_data);

	return NULL;
}

static DBusMessage *try_acquire(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct bt_transport *transport = user_data;
	struct bt_endpoint *endpoint = transport->endpoint;
	const char *sender;

	sender = dbus_message_get_sender(msg);

	DBG("sender %s owner %s", sender, endpoint->owner);

	if (!g_str_equal(sender, endpoint->owner) ||
					transport->state == STATE_ACTIVE)
		return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
						".NotAuthorized",
						"Operation not authorized");

	if (transport->state == STATE_PENDING) {
		transport_set_state(transport, STATE_ACTIVE);
		return acquire_message(msg, transport->io);
	}

	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
						".NotAvailable",
						"Transport not ready");
}

static DBusMessage *release(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct bt_transport *transport = user_data;
	struct bt_endpoint *endpoint = transport->endpoint;
	const char *sender;

	sender = dbus_message_get_sender(msg);

	DBG("sender %s owner %s", sender, endpoint->owner);

	if (!g_str_equal(sender, endpoint->owner))
		return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
						".NotAuthorized",
						"Operation not authorized");

	if (transport->state != STATE_ACTIVE)
		goto done;

	transport_set_state(transport, STATE_IDLE);
	if (transport->io) {
		g_io_channel_unref(transport->io);
		g_io_channel_shutdown(transport->io, FALSE, NULL);
		transport->io = NULL;
	}

done:
	return dbus_message_new_method_return(msg);
}

static gboolean transport_property_get_device(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct bt_transport *transport = data;

	dbus_message_iter_append_basic(iter,
			DBUS_TYPE_OBJECT_PATH, &transport->device_path);

	return TRUE;
}

static gboolean transport_property_get_uuid(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct bt_transport *transport = data;
	struct bt_endpoint *endpoint = transport->endpoint;

	dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &endpoint->uuid);

	return TRUE;
}

static gboolean transport_property_get_codec(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct bt_transport *transport = data;
	struct bt_endpoint *endpoint = transport->endpoint;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &endpoint->codec);

	return TRUE;
}

static gboolean transport_property_get_config(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct bt_transport *transport = data;
	struct bt_endpoint *endpoint = transport->endpoint;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	if (endpoint->capa && endpoint->capa_size)
		dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
					&endpoint->capa, endpoint->capa_size);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean transport_property_get_state(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct bt_transport *transport = data;
	const char *state = state2str(transport->state);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &state);

	return TRUE;
}

static gboolean transport_property_get_mic_gain(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
//	struct bt_transport *transport = data;
	const uint8_t volume = 0;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &volume);

	return TRUE;
}

static void transport_property_set_mic_gain(const GDBusPropertyTable *prop,
			DBusMessageIter *value, GDBusPendingPropertySet id,
			void *data)

{
//	struct bt_transport *transport = data;
	unsigned char volume;
//	const char *sender;

/*	sender = g_dbus_pending_property_get_sender(id);

	if (g_strcmp0(sender, transport->endpoint->owner) != 0) {
		g_dbus_pending_property_error(id,
				BLUEZ_ERROR_INTERFACE ".NotAuthorized",
				"Operation not authorized");
		return;
	}
*/
	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_BYTE) {
		g_dbus_pending_property_error(id,
				BLUEZ_ERROR_INTERFACE ".InvalidArguments",
				"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(value, &volume);

	if (volume > 15) {
		g_dbus_pending_property_error(id,
				BLUEZ_ERROR_INTERFACE ".InvalidArguments",
				"Invalid arguments in method call");
		return;
	}

//	hfp_cv_set_mic_volume(transport->cv, volume);

	g_dbus_pending_property_success(id);
}

static gboolean transport_property_get_speaker_gain(
					const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
//	struct bt_transport *transport = data;
	const uint8_t volume = 0;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &volume);

	return TRUE;
}

static void transport_property_set_speaker_gain(const GDBusPropertyTable *prop,
			DBusMessageIter *value, GDBusPendingPropertySet id,
			void *data)
{
//	struct bt_transport *transport = data;
	unsigned char volume;
//	const char *sender;

/*	sender = g_dbus_pending_property_get_sender(id);

	if (g_strcmp0(sender, transport->endpoint->owner) != 0) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".NotAuthorized",
					"Operation not authorized");
		return;
	}
*/
	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_BYTE) {
		g_dbus_pending_property_error(id,
				BLUEZ_ERROR_INTERFACE ".InvalidArguments",
				"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(value, &volume);

	if (volume > 15) {
		g_dbus_pending_property_error(id,
				BLUEZ_ERROR_INTERFACE ".InvalidArguments",
				"Invalid arguments in method call");
		return;
	}

//	hfp_cv_set_speaker_volume(transport->cv, volume);

	g_dbus_pending_property_success(id);
}

static const GDBusMethodTable transport_methods[] = {
	{ GDBUS_ASYNC_METHOD("Acquire",
			NULL, GDBUS_ARGS({ "fd", "h" }, { "mtu_r", "q" },
							{ "mtu_w", "q" } ),
			acquire) },
	{ GDBUS_ASYNC_METHOD("TryAcquire",
			NULL, GDBUS_ARGS({ "fd", "h" }, { "mtu_r", "q" },
							{ "mtu_w", "q" } ),
			try_acquire) },
	{ GDBUS_METHOD("Release", NULL, NULL, release) },
	{ },
};

static const GDBusPropertyTable transport_properties[] = {
	{ "Device", "o", transport_property_get_device },
	{ "UUID", "s", transport_property_get_uuid },
	{ "Codec", "y", transport_property_get_codec },
	{ "Configuration", "ay", transport_property_get_config },
	{ "State", "s", transport_property_get_state },
	{ "MicrophoneGain", "y", transport_property_get_mic_gain,
				transport_property_set_mic_gain },
	{ "SpeakerGain", "y", transport_property_get_speaker_gain,
				transport_property_set_speaker_gain },
	{ }
};

int bt_transport_register(struct bt_transport *transport,
					DBusPendingCallNotifyFunction cb,
					gpointer user_data)
{
	struct bt_endpoint *endpoint = transport->endpoint;
	DBusMessage *msg;
	DBusMessageIter iter;
	DBusPendingCall *c;
	DBusConnection *conn = ofono_dbus_get_connection();

	if (g_dbus_register_interface(conn, transport->path,
				MEDIA_TRANSPORT_INTERFACE, transport_methods,
				NULL, transport_properties,
				transport, NULL) == FALSE) {
		ofono_error("Could not register transport %s", transport->path);
		return -EIO;
	}

	msg = dbus_message_new_method_call(endpoint->owner, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SetConfiguration");
	if (msg == NULL) {
		ofono_error("Couldn't allocate D-Bus message");
		g_dbus_unregister_interface(conn, transport->path,
						MEDIA_TRANSPORT_INTERFACE);
		return -ENOMEM;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&transport->path);

	transport_append_properties(&iter, transport);

	if (!dbus_connection_send_with_reply(conn, msg, &c, -1)) {
		ofono_error("Sending SetConfiguration failed");
		g_dbus_unregister_interface(conn, transport->path,
						MEDIA_TRANSPORT_INTERFACE);
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_pending_call_set_notify(c, cb, user_data, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);

	return 0;
}

void bt_transport_unregister(struct bt_transport *transport)
{
	struct bt_endpoint *endpoint = transport->endpoint;
	DBusConnection *conn = ofono_dbus_get_connection();
	DBusMessage *msg;
	DBusMessageIter iter;

	msg = dbus_message_new_method_call(endpoint->owner, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"ClearConfiguration");
	if (msg == NULL) {
		ofono_error("Couldn't allocate D-Bus message");
		return;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&transport->path);

	g_dbus_send_message(conn, msg);

	g_dbus_unregister_interface(conn, transport->path,
					MEDIA_TRANSPORT_INTERFACE);
}

static gboolean channel_watch(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct bt_transport *transport = user_data;

	DBG("");

	transport_set_state(transport, STATE_IDLE);
	transport->watch = 0;
	g_io_channel_unref(transport->io);
	transport->io = NULL;

	return FALSE;
}

gboolean bt_transport_set_channel(struct bt_transport *transport,
								GIOChannel *io)
{
	DBusMessage *reply;

	if (transport == NULL)
		return FALSE;

	if (io) {
		GIOCondition cond = G_IO_HUP | G_IO_ERR;

		transport->watch = g_io_add_watch(io, cond, channel_watch,
								transport);
		transport->io = g_io_channel_ref(io);
		g_io_channel_set_close_on_unref(transport->io, TRUE);
	}

	/* Acquire NOT pending */
	if (transport->pending == NULL) {
		transport_set_state(transport, STATE_PENDING);
		return TRUE;
	}

	if (io) {
		transport_set_state(transport, STATE_ACTIVE);
		reply = acquire_message(transport->pending, transport->io);
	} else
		reply = g_dbus_create_error(transport->pending,
						BLUEZ_ERROR_INTERFACE
						".Failed",
						"Connection failed");

	dbus_message_unref(transport->pending);
	transport->pending = NULL;

	g_dbus_send_message(ofono_dbus_get_connection(), reply);

	return TRUE;
}

static void profile_register_cb(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("RegisterProfile() replied an error: %s, %s",
						derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	DBG("");

done:
	dbus_message_unref(reply);
}

static void unregister_profile_cb(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("UnregisterProfile() replied an error: %s, %s",
						derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	DBG("");

done:
	dbus_message_unref(reply);
}

int bluetooth_register_profile(DBusConnection *conn, const char *uuid,
					uint16_t version, uint16_t features,
					const char *name, const char *object)
{
	DBusMessageIter iter, dict;
	DBusPendingCall *c;
	DBusMessage *msg;

	DBG("Bluetooth: Registering %s (%s) profile", uuid, name);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, "/org/bluez",
			BLUEZ_PROFILE_MGMT_INTERFACE, "RegisterProfile");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &uuid);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
	ofono_dbus_dict_append(&dict, "Name", DBUS_TYPE_STRING, &name);

	if (version)
		ofono_dbus_dict_append(&dict, "Version",
					DBUS_TYPE_UINT16, &version);

	if (features)
		ofono_dbus_dict_append(&dict, "Features",
					DBUS_TYPE_UINT16, &features);

	dbus_message_iter_close_container(&iter, &dict);

	if (!dbus_connection_send_with_reply(conn, msg, &c, -1)) {
		ofono_error("Sending RegisterProfile failed");
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_pending_call_set_notify(c, profile_register_cb, NULL, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);

	return 0;
}

void bluetooth_unregister_profile(DBusConnection *conn, const char *object)
{
	DBusMessageIter iter;
	DBusPendingCall *c;
	DBusMessage *msg;

	DBG("Bluetooth: Unregistering profile %s", object);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, "/org/bluez",
			BLUEZ_PROFILE_MGMT_INTERFACE, "UnregisterProfile");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object);

	if (!dbus_connection_send_with_reply(conn, msg, &c, -1)) {
		ofono_error("Sending UnregisterProfile failed");
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(c, unregister_profile_cb, NULL, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);
}

OFONO_PLUGIN_DEFINE(bluez5, "BlueZ 5 Utils Plugin", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT, NULL, NULL)

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
#include <glib.h>
#include <gdbus.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/log.h>
#include <ofono/dbus.h>

#include "bluez5.h"
#include "media.h"

#define MEDIA_ENDPOINT_INTERFACE	"org.bluez.MediaEndpoint1"
#define MEDIA_TRANSPORT_INTERFACE	"org.bluez.MediaTransport1"
#define ERROR_INTERFACE			"org.bluez.Error"

enum transport_state {
	STATE_IDLE,
	STATE_PENDING,
	STATE_ACTIVE
};

struct media_endpoint {
	gint ref;
	char *owner;
	char *path;
	guint8 codec;
	char *uuid;
	GArray *capabilities;
};

struct media_transport {
	gint ref;
	char *path;
	char *device_path;
	guint watch;
	GIOChannel *io;
	enum transport_state state;
	struct media_endpoint *endpoint;
	media_hf_initiate_sco init_sco;
	DBusMessage *pending;
	gpointer user_data;
};

struct media_endpoint *media_endpoint_ref(struct media_endpoint *endpoint)
{
	if (endpoint == NULL)
		return NULL;

	g_atomic_int_inc(&endpoint->ref);

	return endpoint;
}

void media_endpoint_unref(struct media_endpoint *endpoint)
{
	if (g_atomic_int_dec_and_test(&endpoint->ref) == FALSE)
		return;

	g_free(endpoint->owner);
	g_free(endpoint->path);
	g_free(endpoint->uuid);
	if (endpoint->capabilities)
		g_array_unref(endpoint->capabilities);
	g_free(endpoint);
}

struct media_endpoint *media_endpoint_new(const char *owner,
					const char *path,
					guint8 codec,
					GArray *capabilities)
{
	struct media_endpoint *endpoint;

	endpoint = g_new0(struct media_endpoint, 1);
	endpoint->owner = g_strdup(owner);
	endpoint->path = g_strdup(path);
	endpoint->codec = codec;
	endpoint->uuid = g_strdup(HFP_HS_UUID);

	if (capabilities)
		endpoint->capabilities = g_array_ref(capabilities);

	return media_endpoint_ref(endpoint);
}

struct media_transport *media_transport_ref(struct media_transport *transport)
{
	if (transport == NULL)
		return NULL;

	g_atomic_int_inc(&transport->ref);

	return transport;
}

void media_transport_unref(struct media_transport *transport)
{
	if (g_atomic_int_dec_and_test(&transport->ref) == FALSE)
		return;

	g_free(transport->device_path);
	g_free(transport->path);

	if (transport->endpoint)
		media_endpoint_unref(transport->endpoint);

	if (transport->watch)
		g_source_remove(transport->watch);

	if (transport->io)
		g_io_channel_unref(transport->io);

	if (transport->pending)
		dbus_message_unref(transport->pending);

	g_free(transport);
}

struct media_transport *media_transport_new(const char *device,
						struct media_endpoint *endpoint,
						media_hf_initiate_sco init_sco,
						gpointer user_data)
{
	struct media_transport *transport;
	static int id = 0;

	transport = g_new0(struct media_transport, 1);
	transport->path = g_strdup_printf("/transport%d%s/fd", id++, device);
	transport->device_path = g_strdup(device);
	transport->endpoint = media_endpoint_ref(endpoint);
	transport->state = STATE_IDLE;
	transport->init_sco = init_sco;
	transport->user_data = user_data;

	return media_transport_ref(transport);
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

static void transport_set_state(struct media_transport *transport,
						enum transport_state state)
{
	transport->state = state;
	g_dbus_emit_property_changed(ofono_dbus_get_connection(),
				transport->path, MEDIA_TRANSPORT_INTERFACE,
				"State");
}

static void transport_append_properties(DBusMessageIter *iter,
					struct media_transport *transport)
{
	DBusMessageIter dict;
	struct media_endpoint *endpoint = transport->endpoint;
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

	if (endpoint->capabilities)
		ofono_dbus_dict_append_array(&dict, "Configuration",
				DBUS_TYPE_BYTE, &endpoint->capabilities->data,
				endpoint->capabilities->len);

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
	struct media_transport *transport = user_data;
	struct media_endpoint *endpoint = transport->endpoint;
	const char *sender;

	sender = dbus_message_get_sender(msg);

	if (!g_str_equal(sender, endpoint->owner))
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotAuthorized",
						"Operation not authorized");

	if (transport->state == STATE_ACTIVE)
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".InProgress",
					"Operation already in progress");

	if (transport->state == STATE_PENDING) {
		transport_set_state(transport, STATE_ACTIVE);
		return acquire_message(msg, transport->io);
	}

	if (transport->init_sco == NULL)
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".NotAvailable",
					"Operation currently not available");

	transport->pending = dbus_message_ref(msg);
	transport->init_sco(transport, transport->user_data);

	return NULL;
}

static DBusMessage *try_acquire(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct media_transport *transport = user_data;
	struct media_endpoint *endpoint = transport->endpoint;

	const char *sender;

	sender = dbus_message_get_sender(msg);

	DBG("sender %s owner %s", sender, endpoint->owner);

	if (!g_str_equal(sender, endpoint->owner))
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotAuthorized",
						"Operation not authorized");

	if (transport->state == STATE_ACTIVE)
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".InProgress",
					"Operation already in progress");

	if (transport->state == STATE_PENDING) {
		transport_set_state(transport, STATE_ACTIVE);
		return acquire_message(msg, transport->io);
	}

	return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotAvailable",
						"Transport not ready");
}

static DBusMessage *release(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct media_transport *transport = user_data;

	DBG("");

	transport_set_state(transport, STATE_IDLE);

	return g_dbus_create_error(msg, ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static gboolean transport_property_get_device(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;

	dbus_message_iter_append_basic(iter,
			DBUS_TYPE_OBJECT_PATH, &transport->device_path);

	return TRUE;
}

static gboolean transport_property_get_uuid(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct media_endpoint *endpoint = transport->endpoint;

	dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &endpoint->uuid);

	return TRUE;
}

static gboolean transport_property_get_codec(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct media_endpoint *endpoint = transport->endpoint;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &endpoint->codec);

	return TRUE;
}

static gboolean transport_property_get_config(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	struct media_endpoint *endpoint = transport->endpoint;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	if (endpoint->capabilities)
		dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&endpoint->capabilities->data,
						endpoint->capabilities->len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean transport_property_get_state(const GDBusPropertyTable *prop,
					DBusMessageIter *iter, void *data)
{
	struct media_transport *transport = data;
	const char *state = state2str(transport->state);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &state);

	return TRUE;
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
	{ }
};

int media_transport_register(struct media_transport *transport,
					DBusPendingCallNotifyFunction cb,
					gpointer user_data)
{
	struct media_endpoint *endpoint = transport->endpoint;
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

void media_transport_unregister(struct media_transport *transport)
{
	struct media_endpoint *endpoint = transport->endpoint;
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
	struct media_transport *transport = user_data;

	DBG("");

	transport_set_state(transport, STATE_IDLE);

	transport->watch = 0;
	g_io_channel_unref(transport->io);
	transport->io = NULL;

	return FALSE;
}

gboolean media_transport_set_channel(struct media_transport *transport,
								GIOChannel *io)
{
	GIOCondition cond = G_IO_HUP | G_IO_ERR;

	if (transport == NULL)
		return FALSE;

	transport->watch = g_io_add_watch(io, cond, channel_watch, transport);
	transport->io = g_io_channel_ref(io);
	g_io_channel_set_close_on_unref(transport->io, TRUE);

	return TRUE;
}

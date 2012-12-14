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
	char *owner;
	char *path;
	guint8 codec;
	char *uuid;
	GArray *capabilities;
};

struct media_transport {
	char *path;
	char *device_path;
	guint watch;
	GIOChannel *io;
	enum transport_state state;
	struct media_endpoint *endpoint;
};

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

	return endpoint;
}

void media_endpoint_free(gpointer data)
{
	struct media_endpoint *endpoint = data;

	g_free(endpoint->owner);
	g_free(endpoint->path);
	g_free(endpoint->uuid);
	g_array_unref(endpoint->capabilities);
	g_free(endpoint);
}

struct media_transport *media_transport_new(int id, const char *device,
						struct media_endpoint *endpoint)
{
	struct media_transport *transport;

	transport = g_new0(struct media_transport, 1);
	transport->path = g_strdup_printf("%s/%d", device, id);
	transport->device_path = g_strdup(device);
	/* Missing refcounting */
	transport->endpoint = endpoint;
	transport->state = STATE_IDLE;

	return transport;
}

void media_transport_free(struct media_transport *transport)
{
	g_free(transport->device_path);
	g_free(transport->path);

	if (transport->watch)
		g_source_remove(transport->watch);

	if (transport->io)
		g_io_channel_unref(transport->io);

	g_free(transport);
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

static DBusMessage *acquire(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	DBG("");

	return g_dbus_create_error(msg, ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static DBusMessage *try_acquire(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct media_transport *transport = user_data;

	DBG("");

	transport->state = STATE_ACTIVE;

	return g_dbus_create_error(msg, ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static DBusMessage *release(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct media_transport *transport = user_data;

	DBG("");

	transport->state = STATE_IDLE;

	return g_dbus_create_error(msg, ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
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
				NULL, NULL, transport, NULL) == FALSE) {
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
	/* ClearConfiguration */
}

static gboolean channel_watch(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct media_transport *transport = user_data;

	DBG("");

	transport->state = STATE_IDLE;
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

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

#include "media.h"

#define MEDIA_ENDPOINT_INTERFACE	"org.bluez.MediaEndpoint1"
#define MEDIA_TRANSPORT_INTERFACE	"org.bluez.MediaTransport1"

struct media_endpoint {
	char *owner;
	char *path;
	guint8 codec;
	GArray *capabilities;
};

struct media_transport {
	char *path;
	char *device_path;
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
	if (capabilities)
		endpoint->capabilities = g_array_ref(capabilities);

	return endpoint;
}

void media_endpoint_free(gpointer data)
{
	struct media_endpoint *endpoint = data;

	g_free(endpoint->owner);
	g_free(endpoint->path);
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

	return transport;
}

void media_transport_free(struct media_transport *transport)
{
	g_free(transport->device_path);
	g_free(transport->path);
	g_free(transport);
}

static void transport_append_properties(DBusMessageIter *iter,
					struct media_transport *transport)
{
	DBusMessageIter dict;
	struct media_endpoint *endpoint = transport->endpoint;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	ofono_dbus_dict_append(&dict, "Device", DBUS_TYPE_OBJECT_PATH,
						&transport->device_path);

	ofono_dbus_dict_append(&dict, "Codec", DBUS_TYPE_BYTE,
						&endpoint->codec);

	if (endpoint->capabilities)
		ofono_dbus_dict_append_array(&dict, "Configuration",
				DBUS_TYPE_BYTE, &endpoint->capabilities->data,
				endpoint->capabilities->len);

	dbus_message_iter_close_container(iter, &dict);
}

int media_transport_register(struct media_transport *transport,
					DBusPendingCallNotifyFunction cb,
					gpointer user_data)
{
	struct media_endpoint *endpoint = transport->endpoint;
	DBusMessage *msg;
	DBusMessageIter iter;
	DBusPendingCall *c;

	/* Register transport object */

	msg = dbus_message_new_method_call(endpoint->owner, endpoint->path,
						MEDIA_ENDPOINT_INTERFACE,
						"SetConfiguration");
	if (msg == NULL) {
		ofono_error("Couldn't allocate D-Bus message");
		return -ENOMEM;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&transport->path);

	transport_append_properties(&iter, transport);

	if (!dbus_connection_send_with_reply(ofono_dbus_get_connection(),
								msg, &c, -1)) {
		ofono_error("Sending SetConfiguration failed");
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

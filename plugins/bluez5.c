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

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/dbus.h>
#include <ofono/plugin.h>
#include <ofono/log.h>

#include <gdbus/gdbus.h>
#include "bluez5.h"

#define BLUEZ_PROFILE_MGMT_INTERFACE   BLUEZ_SERVICE ".ProfileManager1"

typedef void (*PropertyHandler)(DBusMessageIter *iter, gpointer user_data);

struct property_handler {
	const char *property;
	PropertyHandler callback;
	gpointer user_data;
};

static gint property_handler_compare(gconstpointer a, gconstpointer b)
{
	const struct property_handler *handler = a;
	const char *property = b;

	return g_strcmp0(handler->property, property);
}

void bluetooth_iter_parse_properties(DBusMessageIter *array,
						const char *property, ...)
{
	va_list args;
	GSList *prop_handlers = NULL;
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		goto done;

	va_start(args, property);

	while (property != NULL) {
		struct property_handler *handler =
					g_new0(struct property_handler, 1);

		handler->property = property;
		handler->callback = va_arg(args, PropertyHandler);
		handler->user_data = va_arg(args, gpointer);

		property = va_arg(args, const char *);

		prop_handlers = g_slist_prepend(prop_handlers, handler);
	}

	va_end(args);

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;
		GSList *l;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto done;

		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto done;

		dbus_message_iter_recurse(&entry, &value);

		l = g_slist_find_custom(prop_handlers, key,
					property_handler_compare);

		if (l) {
			struct property_handler *handler = l->data;

			handler->callback(&value, handler->user_data);
		}

		dbus_message_iter_next(&dict);
	}

done:
	g_slist_foreach(prop_handlers, (GFunc) g_free, NULL);
	g_slist_free(prop_handlers);
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
		ofono_error("Sending RegisterProfile failed");
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(c, unregister_profile_cb, NULL, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);
}

OFONO_PLUGIN_DEFINE(bluez5, "BlueZ 5 Utils Plugin", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT, NULL, NULL)
